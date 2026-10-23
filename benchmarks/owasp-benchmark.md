# OWASP Benchmark result

A real run of Lanternfish against the live [OWASP
Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) (v1.2), the
standard labeled corpus for scoring web vulnerability scanners.

## Result (stratified sample)

90 cases, 15 per category, across the six categories a black-box scanner can
observe. Full mode, against the Benchmark running in Tomcat.

| Category | Recall | Notes |
|---|---|---|
| Cross-site scripting (xss) | ~85% | input reflects into the response |
| SQL injection (sqli) | ~78% | database errors surface |
| XPath injection (xpathi) | low | Benchmark returns no error/signal (blind) |
| LDAP injection (ldapi) | low | blind |
| OS command injection (cmdi) | low | blind, and often via a header vector |
| Path traversal (pathtraver) | low | the file read is swallowed (blind) |
| **Overall** | **~37%** | **0% false positives** |

## How to read this

OWASP Benchmark is deliberately hard for black-box (DAST) scanners. It was
built to exercise data-flow analysis: many test cases are **blind** — the
injected value reaches a sink but the HTTP response reveals nothing, so no
proxy-based scanner can see it without an out-of-band signal. Commercial DAST
tools typically land around 30–50% on Benchmark, usually with a meaningful
false-positive rate.

Lanternfish's **0% false positives** is the number to be proud of here:
Benchmark scores scanners on true-positive-rate minus false-positive-rate, so a
clean 37% with no false alarms is a solidly positive score, competitive with
established tools. Where it reflects or errors (XSS, SQLi) it scores well; the
blind categories are the known DAST ceiling and the place to improve next
(out-of-band detection for blind command/SQL injection, and extending
time-based checks to the header and cookie vectors Benchmark uses).

## Reproduce

```
# 1. Build and run the Benchmark (needs a JDK + Maven):
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git
cd BenchmarkJava && ./runBenchmark.sh      # serves https://localhost:8443

# 2. Generate a spec with the exact per-test requests, then scan:
go run ./tools/benchspec -base https://localhost:8443 \
    -crawler BenchmarkJava/data/benchmark-crawler-http.xml \
    -sample 15 BenchmarkJava/expectedresults-1.2.csv > owasp.json
lanternfish bench owasp.json --insecure
```

Drop `-sample` to run the full ~1,570 detectable-category tests (slow).
