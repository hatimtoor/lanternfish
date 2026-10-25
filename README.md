<img src="assets/icon.svg" alt="Lanternfish" width="72" align="left" />

# Lanternfish

A free web security toolkit that brings hidden flaws to light — and teaches you as it goes.

<br clear="left"/>

A CLI-first web application security testing engine: an intercepting HTTP/HTTPS
proxy, a request replayer, and an active + passive vulnerability scanner. Lanternfish
runs headless with JSON output, so it fits scripts and CI as easily as a
terminal.

## Why Lanternfish exists

Learning web security often means paying for a commercial tool like Burp Suite
Professional. For a lot of people — students, self-taught beginners, folks in
places where that price is out of reach — the cost is the wall that stops them
before they start. Lanternfish exists to remove that wall: it's free and
open-source, it covers the everyday web-testing workflow, and it teaches as you
use it. Every finding comes with an explanation, and a built-in practice range
(`lanternfish lab`) gives you somewhere legal to learn. If you couldn't afford
the paid tools, this is for you.

Lanternfish is an independent, clean-room project. It implements publicly documented
security-testing techniques (OWASP Testing Guide, CWE) and contains no code
from any other product. It is not affiliated with or derived from Burp Suite or
PortSwigger.

## Authorized use only

Lanternfish is a security testing tool. Use it only against systems you own or have
explicit, written permission to test. Scanning, proxying, or attacking systems
without authorization is illegal in most jurisdictions and can cause real harm.
You are responsible for how you use it. The authors provide Lanternfish for lawful,
authorized security work — defending your own applications, authorized
penetration testing, bug-bounty programs that permit it, and learning on
deliberately vulnerable targets such as the bundled `lanternfish-testbed`. If you do
not have permission to test a target, do not point Lanternfish at it.

New to this? Start with [docs/getting-started.md](docs/getting-started.md): it
takes you from install to your first finding using the built-in, legal practice
range (`lanternfish lab`) and the narrated workflow (`lanternfish guide`). Running `lanternfish`
with no arguments prints the same orientation.

## Install

Pick whichever fits your platform — no Go toolchain needed.

**Linux / macOS (one line):**

```
curl -fsSL https://raw.githubusercontent.com/hatimtoor/lanternfish/main/install.sh | sh
```

It downloads the right binary for your OS and architecture, verifies its
checksum, and installs it.

**Windows (Scoop):**

```
scoop install https://raw.githubusercontent.com/hatimtoor/lanternfish/main/packaging/scoop/lanternfish.json
```

**macOS / Linux (Homebrew):**

```
brew install --formula https://raw.githubusercontent.com/hatimtoor/lanternfish/main/packaging/homebrew/lanternfish.rb
```

**Direct download:** grab a prebuilt binary from the
[Releases](https://github.com/hatimtoor/lanternfish/releases) page (Windows,
Linux, macOS; amd64 and arm64), make it executable, and run it. To build your
own set, run `scripts/build-release.sh` into `./dist`.

## Verifying your download

A security tool should be one you can trust before you run it. Every release
binary is:

- **Checksummed** — compare it against the published `SHA256SUMS.txt`
  (`sha256sum -c SHA256SUMS.txt`).
- **Attested** — GitHub's CI attaches signed build provenance. Verify that this
  exact binary was built by this repo's workflow from this source:

  ```
  gh attestation verify <file> --repo hatimtoor/lanternfish
  ```

  This is a free, tamper-evident alternative to code signing: it proves where
  the binary came from without a paid certificate.
- **Reproducible** — builds use `-trimpath` and are CGO-free, so you can rebuild
  from a tag and get the same bytes.

Honest note: the binaries are **not** code-signed with a paid Authenticode or
Apple certificate, so Windows SmartScreen or macOS Gatekeeper may warn on first
run. That is expected for an unsigned open-source binary. If you would rather
not click through a warning, build from source (below) — it takes one command
and sidesteps the issue entirely. Signing with a real certificate is on the
roadmap once the project can fund one.

## Build

Requires Go 1.23+. Runs on Windows, Linux, and macOS.

```
# CLI (all commands, runs in a console) — Linux/macOS
go build -o lanternfish ./cmd/lanternfish
# Windows
go build -o lanternfish.exe ./cmd/lanternfish

# Standalone desktop app (Windows only; native WebView2 window)
go build -ldflags "-H windowsgui" -o lanternfish-gui.exe ./cmd/lanternfish-gui
```

The CLI, `serve`, `mcp`, scanner, and labs are pure Go and run on every
platform. The native desktop window is Windows-only; on Linux and macOS
`lanternfish gui` falls back to the browser UI automatically, and `lanternfish serve` is
the recommended way to use the UI there.

### Learn and practice

```
lanternfish lab                      legal, deliberately vulnerable practice range
lanternfish guide <url>              narrated step-by-step first assessment
lanternfish learn                    the OWASP-mapped learning path (and per-challenge solutions)
lanternfish explain <check>          what a finding means, how to confirm and fix it
```

`lanternfish-gui.exe` is the double-click desktop app: a single native window owned
by the process (via the cgo-free WebView2 binding), plus the proxy on :8080.
No browser, no console.

## Commands

```
lanternfish gui     [--proxy :8080]                         native desktop window (proxy + GUI)
lanternfish serve   [--proxy :8080] [--ui 127.0.0.1:8081]  proxy + web GUI in the browser
lanternfish mcp     [--proxy :8080] [--insecure]            MCP server over stdio for an LLM (+proxy)
lanternfish proxy   [--addr :8080] [--auto-audit --scope H]  intercepting proxy (optionally live auto-audit)
lanternfish scan    <url> [--json] [--fast] [--http3]        active + passive scan of a URL
lanternfish auto    <url> [--browser] [--fast] [--json]      autopilot: crawl + audit everything, one command
lanternfish crawl   <seed> [--audit] [--max N] [--json]     crawl a site; optionally audit findings
lanternfish replay  <url> [--method GET] [--data ...]       send one request, show response
lanternfish ca      [--out lanternfish-ca.pem]                    export the local CA certificate
lanternfish collaborator [--addr :80] [--control :8085]      run a hosted out-of-band collaborator server
lanternfish version
```

Lanternfish has one engine and front-ends over it. `gui` gives a human a native
desktop window; `serve` the same UI in a browser; `mcp` gives an LLM the same
operations as tools. All run the intercepting proxy and share one live session
(history, sitemap, issues, scope, intercept).

## Native desktop window (`gui`)

```
lanternfish gui --proxy :8080
```

Opens Lanternfish as a standalone desktop window owned by the process, using the
WebView2 runtime through a cgo-free binding — a real app window, not a browser.
If the native runtime is unavailable it falls back to a chromeless app window
and then the default browser. Prefer the `lanternfish-gui.exe` build for the
no-console double-click experience.

## Web GUI (`serve`)

```
lanternfish serve --proxy :8080 --ui 127.0.0.1:8081
```

Open `http://127.0.0.1:8081`. Tabs:

- **Proxy** — HTTP history; click a row for the full request/response.
- **Intercept** — toggle interception; edit, forward, or drop held requests.
- **Repeater** — craft and resend a request, view the response.
- **Target** — crawl a seed URL and browse the host/path sitemap.
- **Scanner** — run a scan on a URL and browse issues.
- **Intruder** — fuzz a request (marker + payload list). The positional engine
  (sniper/battering ram/pitchfork/cluster bomb with grep-extract) is available
  via the API and MCP.
- **Decoder** — base64/url/hex/html/ascii-hex, hashes, and smart-decode.
- **Comparer** — line/word diff of two texts.
- **Sequencer** — token randomness (Shannon entropy) estimate.
- **WebSockets** — messages observed through the proxy, both directions.
- **Match/Replace** — regex rewrite rules applied to proxied requests.
- **Extensions** — register webhooks that receive traffic and return findings.
- **Scope** — include/exclude rules, a scope tester, and session auth headers
  for authenticated scanning.

Proxy history rows can be sent to Repeater or Intruder. The Scanner tab shows
out-of-band (OAST) callbacks. The header has Save/Load for the whole session as
a JSON project file and a one-click HTML report. Additional capabilities —
login/session macros, CSRF PoC generation, per-request notes/organizer, report
export (JSON/XML/HTML/text), and recurring scan scheduling — are exposed over
the REST API and MCP.

Point your browser's proxy at `--proxy`, and trust the CA (`lanternfish ca --out
lanternfish-ca.pem`, then import it) for HTTPS.

## LLM control (`mcp`)

```
lanternfish mcp --proxy :8080
```

Speaks MCP (JSON-RPC 2.0) over stdio, so an agent can drive the same engine.
Register it with an MCP client. For Claude Code:

```
claude mcp add lanternfish -- lanternfish mcp --proxy :8080
```

Tools exposed: `scan_url`, `crawl_site`, `fuzz`, `replay_request`,
`list_history`, `get_message`, `list_issues`, `get_sitemap`,
`list_interactions`, `list_websockets`, `set_scope`, `set_auth_header`,
`list_auth_headers`, `intercept_toggle`, `intercept_list`, `intercept_forward`,
`intercept_drop`, `add_rewrite_rule`, `list_rewrite_rules`,
`remove_rewrite_rule`, `add_extension`, `list_extensions`, `remove_extension`,
`save_project`, `load_project`, `stats`.

Because the proxy and the MCP server share one session, an LLM can watch live
traffic, hold a request, edit and forward it, and scan what it finds.

### Scan

```
lanternfish scan "https://target.example/search?q=test" --json --fail-on high
```

Runs every bundled check against each insertion point, emits findings as text
or JSON, and can set a non-zero exit code when an issue meets a severity
threshold (for CI gating). `--fast` skips the wait-heavy checks (out-of-band
and time-based) for a quick pass. `--rate N` caps requests per second so you can
scan a third-party target politely, and `--oob interactsh` turns on zero-setup
out-of-band detection (see below). A live `scanning: N/M probes` line reports
progress.

Insertion points mirror Burp's taxonomy: URL query and form-body parameters,
JSON body values, cookies, selected request headers, URL path segments, XML
text and attributes, multipart fields, and parameter names.

### Autopilot

```
lanternfish auto "https://target.example/" --browser
```

One command does the whole workflow with no manual steps: scope to the host,
enable out-of-band checks, scan the seed, crawl and actively audit every
in-scope request, optionally drive a headless browser for JavaScript endpoints
and DOM-XSS, then report every issue by severity. Available from the CLI, the
REST API (`POST /api/auto`), the MCP tool `auto_scan`, and the GUI's Autopilot
tab.

With `--browser` the headless crawl follows single-page-app routes (History API
pushState, hash routes, framework `routerLink`/`data-href` attributes) and
captured fetch/XHR endpoints, so client-rendered apps get mapped too. For sites
behind a login, add `--login-url`/`--login-user`/`--login-pass` to log in
through the browser first and scan authenticated — Lanternfish auto-detects the
form fields, reuses the session cookies, and re-logs-in automatically if the
session drops mid-scan. Use `--rate N` to scan a third-party target politely.

### Live auto-audit

With a scope set, `lanternfish proxy --auto-audit --scope <host>` (or the Autopilot
tab's toggle / `set_live_audit`) actively scans each in-scope request as you
browse it through the proxy, so browsing a target drives the scanner. It
refuses to run without a scope, so it can never audit arbitrary sites.

### Out-of-band detection (blind vulnerabilities)

Blind bugs — blind SSRF, blind SQL/command injection, out-of-band XXE — give no
hint in the HTTP response. The only way to catch them is to make the target call
back to a server you control. Lanternfish gives you three ways to do that, from
easiest to most controlled:

- **Public Interactsh (zero setup, works on remote targets).** `--oob interactsh`
  (on `scan` and `auto`, or `LANTERNFISH_OAST=interactsh`) registers with a free
  public Interactsh server — the same out-of-band service the wider community
  uses — so callbacks from *someone else's* system are captured and polled over
  HTTPS, encrypted to a key only you hold. No DNS, no domain, no server to run.
  This is the path for bug-bounty and research work. (Callbacks transit the
  public server; use a private collaborator below if that matters to you.)
- **Local listener (default; for your own box).** With no flag, Lanternfish runs a
  loopback listener. Perfect when you are testing an app on your own machine
  that can reach you, and it keeps everything local.
- **Your own hosted collaborator.** Run a reachable server you fully control:

  ```
  lanternfish collaborator --addr :80 --control :8085 --domain http://oast.example.com
  # then, on the scanner side:
  #   LANTERNFISH_COLLABORATOR_URL=http://oast.example.com
  #   LANTERNFISH_COLLABORATOR_CONTROL=http://oast.example.com:8085
  #   LANTERNFISH_COLLABORATOR_SECRET=<printed secret>
  ```

### APIs and authenticated apps

Point Lanternfish at an OpenAPI 3 / Swagger 2 spec **or a Postman collection** to audit every documented
endpoint — the modern-app equivalent of crawling:

```
lanternfish openapi api.json --base https://api.example.com
```

It reads the spec, fills in sample parameters and request bodies so each
endpoint responds, and scans them all. For APIs behind a login, send an auth
header or cookie — these apply to every request:

```
lanternfish openapi api.json --base https://api.example.com \
  --auth-header "Authorization: Bearer <token>"

lanternfish auto https://app.example.com --cookie "session=<value>"
```

`auto` and `openapi` both accept `--auth-header` and `--cookie`. For full login
flows (submitting a form, extracting a token), use a login macro via the API or
MCP, which establishes the session for all later scanner traffic.

### HTTP/3

Lanternfish can test servers that speak HTTP/3 (QUIC): `lanternfish scan --http3`, `lanternfish
replay --http3`, or `LANTERNFISH_HTTP3=1` for the autopilot/serve/gui/mcp paths. The
target must support h3.

### DOM analysis

The headless DOM probe (`dom_xss` / `POST /api/dom-xss`, and autopilot's
`--browser`) instruments a broad set of sinks (innerHTML/outerHTML,
document.write, eval, Function, setTimeout/setInterval with strings,
setAttribute on URL attributes, iframe.srcdoc, jQuery.html), detects client-side
prototype pollution, and feeds the canary through postMessage as well as the
URL, so message-handler sinks are covered.

### Native extensions

Besides webhook extensions (any language, over JSON), Lanternfish has a native
in-process extension API shaped like Burp's Montoya model: an extension can
edit requests and responses in the proxy and contribute passive and active scan
checks. See `internal/ext` and the `SampleExtension` (enable with
`LANTERNFISH_EXT_DEMO=1`). It does not run Burp's Java BApp JARs.

### Proxy

```
lanternfish proxy --addr 127.0.0.1:8080
```

Point your browser or tool at the proxy. For HTTPS interception, trust the local
CA once:

```
lanternfish ca --out lanternfish-ca.pem      # then import into your OS/browser trust store
```

or fetch it through the running proxy at `http://lanternfish.ca/cert`. The CA and its
key are generated on first run and stored under your user config directory
(`<config>/lanternfish`). Observed traffic is run through passive checks live.

> On Windows, `curl` uses the schannel TLS backend, which does not trust a CA
> *file*. Import the Lanternfish CA into the Windows certificate store (or use a client
> that honors `RootCAs`) for HTTPS interception.

### Replay

```
lanternfish replay "https://target.example/login" --method POST --data "u=a&p=b"
```

## Bundled checks

Passive:
- `security-headers` — missing CSP, X-Content-Type-Options, clickjacking
  protection, HSTS; insecure cookie flags.
- `exposed-secrets` (CWE-200) — API keys, private keys, JWTs in responses.
- `verbose-error` (CWE-209) — stack traces / framework error disclosure.
- `directory-listing` (CWE-548) — auto-generated directory index pages.
- `private-ip-disclosure` (CWE-200), `mixed-content` (CWE-311),
  `password-autocomplete` (CWE-200).
- `session-token-in-url` (CWE-598), `banner-disclosure` (CWE-200),
  `cookie-samesite` (CWE-1275), `source-map-disclosure` (CWE-540),
  `sensitive-comment` (CWE-615), `pii-credit-card` (CWE-359, Luhn-checked),
  `insecure-form` (CWE-319), `vulnerable-js-library` (CWE-1104, retire.js-style).
- `insecure-deserialization` (CWE-502), `jwt-weakness` (CWE-347, alg=none),
  `email-disclosure` (CWE-200), `cacheable-sensitive` (CWE-525),
  `additional-headers` (Referrer-Policy / Permissions-Policy).

Data-driven databases add the long tail (each entry is its own check):
- **Per-DBMS / per-engine injection** (`internal/scan/checks/injectiondb.go`):
  MySQL, MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, DB2, Sybase, Access,
  Informix, Firebird, Ingres, HSQLDB, H2, plus SpEL, OGNL, Jinja2, and XML.
- **Secret detection** (`secretdb.go`): ~90 credential/token patterns
  (cloud, CI, payment, messaging, SaaS, private keys), gitleaks-style.
- **Technology fingerprints** (`fingerprintdb.go`): ~45 frameworks, servers,
  CMSes, CDNs, and WAFs.

About **205 distinct registered checks** in total, spanning the OWASP
vulnerability classes plus secret and technology detection.

Active (per insertion point — query and form-body parameters):
- `reflected-xss` (CWE-79) — marker reflected unencoded into HTML, including the
  JavaScript-string context (quote survives inside a `<script>` block).
- `sqli-error` (CWE-89) — database error provoked by a syntax-breaking value,
  compared against a baseline.
- `path-traversal` (CWE-22) — traversal sequences returning known-file content
  (raw or HTML-entity-encoded).
- `path-traversal-oracle` (CWE-22) — file-existence oracle for sinks that report
  whether a path exists/opens but never return its content (directory target, so
  it never writes to the filesystem).
- `open-redirect` (CWE-601) — attacker-controlled `Location` redirect target.
- `ssti` (CWE-1336) — template expression evaluated server-side.
- `crlf-injection` (CWE-113) — CRLF in a value injects a response header.
- `command-injection` (CWE-78) — time-based blind OS command injection.
- `command-injection-inband` (CWE-78) — shell/`cmd.exe` arithmetic evaluation.
- `command-injection-oob` (CWE-78) — out-of-band callback confirms blind OS
  command injection.
- `ssrf` (CWE-918) — in-band SSRF: cloud instance-metadata (incl. AWS IAM creds)
  or local files fetched and reflected.
- `blind-ssrf` (CWE-918) — out-of-band callback confirms server-side request
  forgery.
- `ldap-injection` (CWE-90), `xpath-injection` (CWE-643) — error-based and
  boolean/differential.
- `sqli-boolean-blind` / `sqli-time-blind` (CWE-89) — blind SQL injection.
- `sqli-oob` (CWE-89) — out-of-band blind SQLi via DNS/UNC exfiltration
  (MSSQL/Oracle/MySQL/PostgreSQL).
- `lfi` (CWE-98) — local file inclusion via php:// wrappers.
- `nosql-injection` (CWE-943) — error-based NoSQL injection.
- `stored-xss` (CWE-79) — second-order XSS: a canary submitted to a value vector
  is persisted and returned unencoded on a later page load.

The out-of-band checks (`*-oob`, `blind-ssrf`) fire payloads without waiting and
are polled once per scan, so enabling them does not slow the scan per insertion
point. Point them at a remote target with `--oob interactsh`.

Request-level (once per request):
- `cors-misconfig` (CWE-942) — reflected/wildcard origin, the `null` origin, and
  allow-list bypasses (trusted subdomain, prefix, suffix).
- `cache-poisoning` (CWE-444) — unkeyed header (X-Forwarded-Host, etc.) reflected
  into a cacheable response.
- `xxe` (CWE-611) — XML external entity injection, in-band and out-of-band.
- `host-header-injection` (CWE-644) — attacker host reflected in body/redirect.
- `dangerous-http-methods` (CWE-650) — risky methods advertised via OPTIONS.
- `graphql-introspection` (CWE-200) — schema introspection enabled; also
  `graphql-suggestions` (field "Did you mean" schema leak) and `graphql-batching`
  (array queries that bypass per-request rate limits).
- `content-discovery` (CWE-538) — exposed sensitive files (.git, .env, etc.).

Passive highlights: `security-headers`, `csp-weakness` (a present-but-permissive
Content-Security-Policy — `unsafe-inline`, wildcard script-src, missing
object-src/base-uri), `cookie-security` (missing Secure/HttpOnly, `__Host-`/
`__Secure-` prefix violations), `hsts-weak` (short max-age / missing
includeSubDomains), exposed secrets, vulnerable JS libraries, and more.

## Architecture

```
cmd/lanternfish            CLI (gui, serve, mcp, proxy, scan, crawl, replay, ca)
cmd/lanternfish-gui        standalone desktop app entrypoint (-H windowsgui)
internal/app         front-end runners (gui/serve/mcp) over a shared stack
internal/desktop     native WebView2 window + app-window/browser fallback
internal/httpmsg     request/response model
internal/ca          local CA + per-host leaf certs for TLS interception
internal/client      shared upstream sender (implements scan.Sender)
internal/scope       include/exclude target scope
internal/session     shared state: history, sitemap, issues, scope, intercept, rewrite rules, auth headers, project save/load
internal/proxy       intercepting HTTP/HTTPS proxy + WebSocket relay (uses session)
internal/replay      single-request replayer
internal/crawl       scope-aware crawler (links + forms)
internal/fuzz        Intruder: simple fuzzer + positional attack types
internal/oast        out-of-band callback listener (blind vuln detection)
internal/ext         extension webhooks (external detection logic)
internal/decoder     Decoder/encoder transforms
internal/comparer    line/word diff (Comparer)
internal/sequencer   token entropy analysis (Sequencer)
internal/macro       login/session macros
internal/csrf        CSRF proof-of-concept generator
internal/scan        engine, issue model, insertion points
internal/scan/checks bundled passive / active / request-level checks
internal/service     high-level ops (scan, crawl, fuzz, replay, project) shared by API and MCP
internal/api         REST API + embedded web GUI
internal/mcp         MCP stdio server (LLM front-end)
internal/desktop     native window launcher (WebView2 app window)
internal/report      JSON / text reporting
```

Both front-ends (`internal/api`, `internal/mcp`) call `internal/service` over a
single `internal/session.Session`, so the human GUI and an LLM see the same
live state.

New checks implement `scan.PassiveCheck` or `scan.ActiveCheck` and register in
`internal/scan/checks/registry.go`.

## Testing

```
go test ./...
```

## Legal and ethical use

Only test systems you own or are explicitly authorized to test. Unauthorized
scanning or interception of systems is illegal in most jurisdictions.

## License

MIT (intended). Add a LICENSE file before distribution.
