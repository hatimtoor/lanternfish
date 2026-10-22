# Security policy

Lanternfish is a security tool, so a vulnerability in Lanternfish itself (for
example, something that could harm a user running it) matters more than usual.

## Reporting a vulnerability in Lanternfish

Please report it privately rather than opening a public issue, so it can be
fixed before it is widely known. Use GitHub's private vulnerability reporting:

- Go to the repository's **Security** tab → **Report a vulnerability**.

Include what the issue is, how to reproduce it, and the impact. We will
acknowledge the report, work on a fix, and credit you if you would like.

## Scope

In scope: defects in Lanternfish's own code — the proxy, parsers, TLS/CA
handling, the local API and MCP server, the collaborator, and the CLI.

Out of scope: the deliberately vulnerable code in `internal/labs` and
`cmd/lanternfish-testbed`. Those are intentional teaching targets and only bind
to loopback by design.

## Using Lanternfish responsibly

Lanternfish is for authorized testing only. Use it against systems you own or
have explicit, written permission to test. The project cannot help with, and
does not condone, unauthorized access.
