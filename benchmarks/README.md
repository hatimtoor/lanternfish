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

The same harness scores any target you can label. These free, deliberately
vulnerable projects are the standard ones (run each on your own machine, then
write a spec for it):

- **WAVSEP** — the Web Application Vulnerability Scanner Evaluation Project,
  built specifically to score scanners with true/false-positive cases.
- **OWASP Benchmark** — a large labeled Java app with a known answer key.
- **OWASP Juice Shop**, **WebGoat**, **DVWA**, **bWAPP** — broad, well-known
  vulnerable apps. **VAmPI** is a good labeled API target.

Only run these against instances you control. Write a `*.json` spec mapping
their vulnerable and safe endpoints, commit it here, and track the score as the
checks improve. A pull request that moves the numbers should say so.
