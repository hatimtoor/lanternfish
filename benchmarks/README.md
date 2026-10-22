# Benchmarks

Measuring accuracy is how Lanternfish improves over time — the open equivalent
of the feedback a commercial scanner gets from thousands of users. A benchmark
is a labeled target: endpoints whose vulnerabilities (or lack of them) are
known, so we can score **detection** (did it find what's there?) and **false
positives** (did it cry wolf where nothing's wrong?).

## Run the built-in benchmark

No external setup — it uses the bundled, loopback-only practice target:

```
lanternfish-testbed &                    # start the deliberately vulnerable app on :9000
lanternfish bench benchmarks/testbed.json
```

You'll get a per-case result and a summary:

```
Detection: 16/16 expected findings (100% recall)
False positives: 0 across 1 clean case(s)
```

Add `--json` for machine-readable output (useful in CI), or `--fast` to skip the
wait-heavy blind/time-based checks (faster, but it will miss `blind-ssrf`).

## Spec format

A spec is JSON: a `base` URL and a list of `cases`. Each case names a `path` and
either the check ids it should produce (`expect`, matched by prefix so `sqli`
covers `sqli-error`, `sqli-mysql`, …) or `clean: true` (no high/critical finding
should fire — this is how false positives are measured).

```json
{
  "name": "My target",
  "base": "http://127.0.0.1:8080",
  "cases": [
    {"path": "/item?id=1", "expect": ["sqli"]},
    {"path": "/about",     "clean": true}
  ]
}
```

## Pointing it at external corpora

The same harness scores any target you can label. Only run these against
instances you control.

### OWASP Benchmark (has an answer key → auto-generate the spec)

The OWASP Benchmark ships `expectedresults-*.csv` labeling every test as a real
vulnerability or not. Convert it straight into a spec:

```
go run ./tools/benchspec -base http://localhost:8443 expectedresults-1.2.csv > benchmarks/owasp-benchmark.json
lanternfish bench benchmarks/owasp-benchmark.json
```

The converter maps the categories a black-box scanner can observe
(path traversal, SQLi, XSS, command/LDAP/XPath injection, cookie flags) and
skips the source-level ones (crypto, hashing, weak randomness, trust boundary)
that no proxy-based scanner can see.

> Caveat: many Benchmark endpoints only trigger with specific parameters or a
> POST body, which a single GET per path will not exercise, so a raw run
> under-reports. Treat the generated spec as a labeling starting point; for full
> coverage, drive the endpoints with the right requests (e.g. via crawling).

### WAVSEP, Juice Shop, WebGoat, DVWA, bWAPP, VAmPI

These have no single machine-readable answer key, so write the spec by hand:
run the app, note which endpoints are vulnerable (and which are safe), and list
them as `expect` / `clean` cases in a `*.json` spec. Commit it here and track
the score as the checks improve. A pull request that moves the numbers should
say so.

## Keeping signatures fresh (separate from benchmarking)

The secret and vulnerable-library databases are refreshed from gitleaks and
retire.js by `scripts/update-signatures.sh` (see `../CONTRIBUTING.md`). That is
a different pipeline from the benchmark; both feed accuracy.

**On nuclei:** nuclei's templates are a different execution model (per-template
YAML with its own request/matcher language), not a signature list, so they are
not synced here. Running them would mean building a nuclei-template interpreter
— a separate, larger project rather than a database refresh.
