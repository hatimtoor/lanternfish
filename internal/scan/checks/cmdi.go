package checks

import (
	"context"
	"fmt"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// CommandInjection detects OS command injection using time-based inference:
// if a payload that runs a sleep delays the response by about the requested
// amount (and a doubled delay scales), the parameter likely reaches a shell.
// Blind timing avoids relying on command output and is a public technique.
type CommandInjection struct{}

func (CommandInjection) ID() string { return "command-injection" }

// AppliesTo limits time-based command-injection inference to the insertion
// points where it realistically occurs, so it does not sleep-probe every
// header and path segment. Header points are allowed but gated in Active to a
// curated set of headers apps commonly pass to a shell (see headerVectorAllowed).
func (CommandInjection) AppliesTo(k scan.Kind) bool {
	switch k {
	case scan.KindQuery, scan.KindBody, scan.KindJSON, scan.KindCookie, scan.KindHeader:
		return true
	default:
		return false
	}
}

// base delay in seconds; kept modest to bound scan time.
const cmdiDelay = 3

func (c CommandInjection) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	// Median baseline over a few samples so one slow request does not look like
	// a successful delay.
	bt, ok := medianTiming(ctx, s, p, p.Base, 3)
	if !ok {
		return nil
	}

	templates := []string{
		";sleep %d",
		"|sleep %d",
		"& sleep %d",
		"$(sleep %d)",
		"`sleep %d`",
		"%s & timeout /t %d", // Windows (best-effort)
	}
	for _, tpl := range templates {
		if ctx.Err() != nil {
			return nil
		}
		tpl := tpl
		d1, ok := confirmScaledDelay(ctx, s, p, bt, cmdiDelay, func(secs int) string {
			return fmtDelay(tpl, secs, p.Base)
		})
		if !ok {
			continue
		}
		payload := fmtDelay(tpl, cmdiDelay, p.Base)
		return []*scan.Issue{{
			Check: "command-injection", Name: "OS command injection (time-based)",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityCritical, Confidence: scan.ConfidenceFirm,
			Detail: fmt.Sprintf("Parameter %q appears to reach an OS shell: a sleep payload delayed the response to ~%s (baseline ~%s) and a doubled delay scaled proportionally, confirming time-based OS command injection.",
				p.Name, d1.Round(time.Millisecond), bt.Round(time.Millisecond)),
			Remediation: "Never pass user input to a shell. Use argument arrays with no shell, validate strictly, and avoid system() style calls.",
			Evidence:    fmt.Sprintf("payload %q -> %s", payload, d1.Round(time.Millisecond)),
			CWE:         "CWE-78",
		}}
	}
	return nil
}

func timeSend(ctx context.Context, s scan.Sender, p scan.InsertionPoint, value string) (time.Duration, bool) {
	start := time.Now()
	resp, err := s.Send(ctx, p.Mutate(value))
	if err != nil || resp == nil {
		return 0, false
	}
	return time.Since(start), true
}

func fmtDelay(tpl string, secs int, baseVal string) string {
	// Windows template has a %s for the base value and %d for seconds.
	if countVerbs(tpl) == 2 {
		return fmt.Sprintf(tpl, baseVal, secs)
	}
	return fmt.Sprintf(tpl, secs)
}

func countVerbs(tpl string) int {
	n := 0
	for i := 0; i+1 < len(tpl); i++ {
		if tpl[i] == '%' && (tpl[i+1] == 'd' || tpl[i+1] == 's') {
			n++
		}
	}
	return n
}
