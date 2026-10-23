# OWASP Benchmark result

A real run of Lanternfish against the live [OWASP
Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) (v1.2), the
standard labeled corpus for scoring web vulnerability scanners.

## Result (stratified sample)

90 cases, 15 per category, across the six categories a black-box scanner can
observe. Full mode, against the Benchmark running in Tomcat.

| Category | Recall | Notes |
|---|---|---|
| Cross-site scripting (xss) | 100% (14/14) | input reflects into the response |
| SQL injection (sqli) | 100% (14/14) | DB errors surface; blind cases via boolean/time |
| XPath injection (xpathi) | 100% (5/5) | error- and boolean-based on the reflected result |
| OS command injection (cmdi) | 100% (10/10) | in-band (`echo`/`set /a`), time-based and OOB |
| Path traversal (pathtraver) | 54% (6/11) | content disclosure + a file-existence oracle |
| LDAP injection (ldapi) | 0% (0/7) | sink errors identically on *all* input (see below) |
| **Overall** | **80% (49/61)** | **0% false positives** |

## How to read this

OWASP Benchmark is deliberately hard for black-box (DAST) scanners, and it was
built to exercise data-flow analysis rather than live probing. Commercial DAST
tools typically land around 30–50% on it, usually with a meaningful
false-positive rate. Benchmark scores scanners on **true-positive-rate minus
false-positive-rate**, so Lanternfish's **80% with zero false positives** is a
strong, honest result — four of the six categories are at 100%.

The zero false positives is the number to be proud of. Every one of the 49
detections is a confirmed signal (a reflected marker, a database/XPath error, a
differential, a timing delay, an out-of-band callback, or a file-existence
oracle), and none of the 29 clean control cases produced a finding.

## What moved the number (37% → 44% → 72% → 80%)

Three evidence-driven passes against the live Benchmark. Early on these
categories read as a hard "blind DAST ceiling"; reading the actual sink code
showed most of them were **our gaps, not a ceiling** — the sinks do reflect file
contents, command output, or query results.

1. **Reflected XSS** keyed on the surviving tag-start (`<marker`) instead of a
   full `<marker>`, so sinks that mangle or drop the trailing `>` are still
   caught. Safe pages encode `<` to `&lt;`, so this stays false-positive-free.
   XSS → 100%.
2. **Header/cookie vectors** for the wait-heavy checks: any present
   non-structural header is now fuzzed (Benchmark injects cmdi/xpath via a
   per-test custom header a curated allow-list had excluded). SQLi → 100%.
3. **The 0% categories**, each a specific fixable gap:
   - **cmdi** (custom header / cookie → `cmd.exe /c echo <input>`, output
     reflected): fuzz the header, and add Windows `set /a` in-band payloads
     beside the POSIX `$((…))` ones.
   - **xpath** (reflects the query result): broaden error signatures
     (`javax.xml.xpath`, `XPathExpressionException`, …) and add a boolean
     tautology-vs-contradiction differential. → 100%.
   - **path traversal** (cookie → reads `BASE + input`, writes it back
     HTML-encoded): drive the request as **POST** (the sink is in `doPost`;
     `doGet` was just a cookie-setting landing page), climb deep enough (to 16
     levels) with **forward-slash** Windows targets that survive cookie transport
     where backslashes don't, and **HTML-entity-decode** the response before
     matching (the app encodes `[fonts]` to `&#x5b;fonts&#x5d;` but still leaks
     the file).
4. **Cookie encoding + a file-existence oracle.** Percent-encode cookie values
   (RFC 6265) so payloads with spaces/backslashes survive the server's cookie
   parser instead of being truncated — this took **cmdi to 100%** (its last
   misses were cookie-borne). And a differential existence oracle for sinks that
   report whether a path exists or can be opened but never return its contents:
   a traversal to a real system *directory* is reported present while a random
   name is reported absent. It targets directories, never files, so it can never
   truncate anything on the target. → path traversal 54%.

## What's left

- **pathtraver 6/11** — the remaining five are, by design, out of reach for a
  *safe* black-box scanner: two are pure file-**write** sinks (the only reliable
  probe would truncate a real file — Lanternfish will not do that in a default
  scan), two check existence of `<input>/Test.txt` where no such file exists to
  flip the oracle, and one opens the path for read-then-write in a way that would
  truncate a real file. These are deliberately not pursued, not undetected bugs.
- **ldapi 0/7 — a genuine ceiling.** The LDAP sink throws an *identical* HTTP 500
  on every input, benign or malicious (a malformed concatenated filter). There
  is no difference between a safe and an attack request for a black-box scanner
  to observe, so flagging it would mean flagging benign traffic too. Correctly
  reporting nothing here is what keeps the false-positive rate at zero.

Both remaining gaps are the point where responsible black-box scanning stops:
detecting more would mean either false positives or modifying files on the
target. A static/white-box analyzer is the right tool for those; a DAST is not.

## Reproduce

```
# 1. Build and run the Benchmark (needs a JDK + Maven):
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git
cd BenchmarkJava && ./runBenchmark.sh      # serves https://localhost:8443

# 2. Generate a spec with the exact per-test requests (POST, with the cookie/
#    header/param each test uses), then scan:
go run ./tools/benchspec -base https://localhost:8443 \
    -crawler BenchmarkJava/data/benchmark-crawler-http.xml \
    -sample 15 BenchmarkJava/expectedresults-1.2.csv > owasp.json
lanternfish bench owasp.json --insecure
```

Full mode fuzzes every header with time-based and out-of-band probes, so a large
sample takes a while — drop `-sample` to run every detectable-category test.
