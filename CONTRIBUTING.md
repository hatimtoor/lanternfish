# Contributing to Lanternfish

Lanternfish gets better the same way the commercial tools did: real people run
it, tell us what it got wrong, and we tune it. You do not need to be an expert
to help — a clear bug report or a single false positive makes the tool better
for everyone, permanently.

## The most valuable thing you can do: report accuracy

Lanternfish's long-term quality is mostly about two numbers — how much it finds
(coverage) and how often it cries wolf (false positives). Both improve from
real reports:

- **False positive?** It reported something that is not real → open a
  [False positive](../../issues/new?template=false_positive.yml) issue.
- **Missed something?** A real bug it did not find → open a
  [Missed finding](../../issues/new?template=missed_finding.yml) issue.

Please redact anything sensitive (real hosts, tokens, personal data) first. A
minimal request/response that still reproduces is perfect. Every confirmed
report becomes a regression test in `internal/scan`, so once fixed it cannot
come back.

## Measuring accuracy yourself

The `benchmarks/` directory has a scoring harness. Run it against the bundled,
legal practice targets:

```
lanternfish-testbed &             # start the practice target (loopback only)
lanternfish bench benchmarks/testbed.json
```

It prints detection (recall) and false-positive numbers per class. See
`benchmarks/README.md` for pointing it at external corpora like WAVSEP, the
OWASP Benchmark, or OWASP Juice Shop. If a change moves the numbers, say so in
your pull request.

## Keeping signatures fresh

The vulnerable-library signatures are refreshed from the public retire.js
database:

```
scripts/update-signatures.sh      # regenerates internal/scan/checks/data/, then builds + tests
```

Review the diff and commit it. The generated entries supplement the curated set
in `internal/scan/checks/vuln_libs.go`.

## Adding a check, a lab, or a lesson

- **A scan check** lives in `internal/scan/checks/` and implements
  `PassiveCheck`, `ActiveCheck`, or `RequestCheck`, then is registered in
  `registry.go`. Add a detection test and, ideally, a no-false-positive test.
- **A knowledge-base lesson** (what/why/confirm/fix + a free link) goes in
  `internal/kb/kb_entries.go`, keyed by the check id. Every check should have one.
- **A practice challenge** goes in `internal/labs/`, with a brief, a hint
  ladder, and a flag revealed only on solve. Keep it loopback-only.

Use only publicly documented techniques and public data sources. Do not copy
code from any commercial product — Lanternfish is a clean-room project.

## Development

```
go build ./...          # build everything
go test ./...           # run the full suite (the scan package is slow)
go vet ./...
gofmt -w .              # format before committing
```

CI runs build, vet, and tests on every push and pull request. Please keep the
suite green and add tests for new behavior. Small, focused pull requests are
easiest to review.

## Code of conduct, in one line

Be kind, assume good faith, and remember a lot of people here are learning. This
project exists so that money is not what stops someone from becoming a security
analyst — keep that spirit.
