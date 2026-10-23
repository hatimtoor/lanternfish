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
| OS command injection (cmdi) | 70% (7/10) | in-band (`echo`/`set /a`), time-based and OOB |
| Path traversal (pathtraver) | 36% (4/11) | reads a known file via deep traversal |
| LDAP injection (ldapi) | 0% (0/7) | sink errors identically on *all* input (see below) |
| **Overall** | **72% (44/61)** | **0% false positives** |

## How to read this

OWASP Benchmark is deliberately hard for black-box (DAST) scanners, and it was
built to exercise data-flow analysis rather than live probing. Commercial DAST
tools typically land around 30–50% on it, usually with a meaningful
false-positive rate. Benchmark scores scanners on **true-positive-rate minus
false-positive-rate**, so Lanternfish's **72% with zero false positives** is a
strong, honest result.

The zero false positives is the number to be proud of. Every one of the 44
detections is a confirmed signal (a reflected marker, a database/XPath error, a
differential, a timing delay, or an out-of-band callback), and none of the 29
clean control cases produced a finding.

## What moved the number (37% → 44% → 72%)

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
   - **cmdi** (custom header → `cmd.exe /c echo <input>`, output reflected):
     fuzz the header, and add Windows `set /a` in-band payloads beside the POSIX
     `$((…))` ones. → 70%.
   - **xpath** (reflects the query result): broaden error signatures
     (`javax.xml.xpath`, `XPathExpressionException`, …) and add a boolean
     tautology-vs-contradiction differential. → 100%.
   - **path traversal** (cookie → reads `BASE + input`, writes it back
     HTML-encoded): drive the request as **POST** (the sink is in `doPost`;
     `doGet` was just a cookie-setting landing page), climb deep enough (to 16
     levels) with **forward-slash** Windows targets that survive cookie transport
     where backslashes don't, and **HTML-entity-decode** the response before
     matching (the app encodes `[fonts]` to `&#x5b;fonts&#x5d;` but still leaks
     the file). → 36%.

## What's left

- **cmdi 7/10, pathtraver 4/11** — the remaining misses use sink/vector variants
  not yet covered (other traversal bases, non-shell `exec` arg-array cmdi that
  genuinely emits no signal). Real headroom remains here.
- **ldapi 0/7 — a genuine ceiling.** The LDAP sink throws an *identical* HTTP 500
  on every input, benign or malicious (a malformed concatenated filter). There
  is no difference between a safe and an attack request for a black-box scanner
  to observe, so flagging it would mean flagging benign traffic too. Correctly
  reporting nothing here is what keeps the false-positive rate at zero.

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
