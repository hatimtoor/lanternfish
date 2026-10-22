# Getting started with Lanternfish

This guide takes you from nothing to your first finding, the safe and legal
way. It is written for someone new to security testing. No prior tooling
experience is assumed.

> **Authorized testing only.** Only test systems you own or have explicit,
> written permission to test. Everything in this guide uses Lanternfish's own
> practice range, which runs on your computer and is legal to attack.

## 1. Install

Lanternfish is a single program written in Go. You need Go 1.23 or newer
(https://go.dev/dl/). It runs on Windows, Linux, and macOS.

### Build it

Linux / macOS:

```
go build -o lanternfish ./cmd/lanternfish
```

Windows (PowerShell):

```
go build -o lanternfish.exe ./cmd/lanternfish
```

That produces one self-contained binary. There is nothing else to install.

The optional native desktop window is Windows-only:

```
go build -ldflags "-H windowsgui" -o lanternfish-gui.exe ./cmd/lanternfish-gui
```

On Linux and macOS you use the browser UI instead (see step 4). `lanternfish gui`
there automatically falls back to opening the UI in your browser.

## 2. Start the practice range

Lanternfish ships with a built-in set of deliberately vulnerable challenges. Run:

```
lanternfish lab
```

Open the address it prints (default http://127.0.0.1:9000/) in your browser.
You will see challenges for cross-site scripting, SQL injection, access
control, path traversal, command injection, and SSRF. Each has a brief, hints,
and a flag that appears only when you solve it. This range is safe and legal:
it only listens on your own machine and refuses to run anywhere public.

## 3. Your first guided assessment

In another terminal, point Lanternfish's guided mode at a lab challenge:

```
lanternfish guide http://127.0.0.1:9000/lab/xss?name=world
```

It walks the five steps every analyst follows — scope, map, test, review,
report — explaining each one, running the scan for you, showing the most
important finding with a lesson on why it matters and how to confirm it, and
writing an HTML report. Read it top to bottom. That loop is the whole job in
miniature.

## 4. Explore with the full UI

```
lanternfish serve
```

Open the address it prints. The Autopilot tab is the fastest way in: paste a
URL, click Run, and it crawls and tests the whole target. Every finding has a
"Learn about this" expander. Other tabs give you a proxy, repeater, intruder,
decoder, and more — the standard toolkit.

To intercept HTTPS traffic from your browser, set your browser's proxy to the
address `serve` printed for the proxy, then trust the local CA once:

```
lanternfish ca --out lanternfish-ca.pem      # import this file into your OS/browser trust store
```

## 5. Learn every finding

Any time you see a finding, get the full lesson:

```
lanternfish explain reflected-xss
lanternfish explain --list            # every topic with a lesson
```

Each lesson covers what the bug is, why it matters, how to confirm it by hand,
how to exploit it safely in a lab, how to fix it, and free resources to go
deeper (the PortSwigger Web Security Academy and OWASP are both free and
excellent).

## 6. The learning loop

Repeat this until it is second nature:

1. Pick a challenge in `lanternfish lab`.
2. Read the brief. Try to solve it by hand first.
3. Stuck? Reveal a hint, or run `lanternfish guide` against it to see the approach.
4. Run `lanternfish explain <topic>` and read the linked free lesson.
5. Move to the next challenge.

When you can solve every lab challenge by hand and explain each bug in your own
words, you have the core skills of a junior web security analyst — built with a
free tool, on your own machine.

## Common commands

```
lanternfish lab                         start the legal practice range
lanternfish guide <url>                 narrated, step-by-step assessment
lanternfish auto <url>                  autopilot: crawl + test everything at once
lanternfish scan <url>                  scan a single URL
lanternfish serve                       full web UI + proxy
lanternfish explain <check>             learn about a finding
lanternfish mcp                         drive Lanternfish from an AI assistant (MCP)
```

Add `--help` to any command for its options.
