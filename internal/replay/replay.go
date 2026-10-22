// Package replay sends a single request and returns the response, the
// equivalent of a manual "repeater". It is a thin layer over the shared client
// that also renders a human-readable exchange.
package replay

import (
	"context"
	"fmt"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// Once sends the request a single time.
func Once(ctx context.Context, s scan.Sender, r *httpmsg.Request) (*httpmsg.Response, error) {
	return s.Send(ctx, r)
}

// Render formats a request/response exchange for terminal display.
func Render(req *httpmsg.Request, resp *httpmsg.Response) string {
	var b strings.Builder
	b.WriteString("> ")
	b.WriteString(strings.ReplaceAll(strings.TrimRight(req.DumpRequestLine(), "\n"), "\n", "\n> "))
	b.WriteString("\n\n")
	if resp != nil {
		fmt.Fprintf(&b, "< %s %s (%d bytes, %s)\n", resp.Proto, resp.Status, len(resp.Body), resp.Elapsed.Round(1e6))
		for k, vals := range resp.Header {
			for _, v := range vals {
				fmt.Fprintf(&b, "< %s: %s\n", k, v)
			}
		}
		b.WriteString("\n")
		body := resp.BodyString()
		if len(body) > 2000 {
			body = body[:2000] + "\n... [truncated]"
		}
		b.WriteString(body)
		b.WriteString("\n")
	}
	return b.String()
}
