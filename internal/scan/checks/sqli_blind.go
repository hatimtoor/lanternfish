package checks

import (
	"context"
	"fmt"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// BooleanBlindSQLi detects boolean-based blind SQL injection by comparing the
// responses to a condition that is always true versus always false: if the
// true response matches the baseline and the false response differs, the
// parameter likely controls a SQL boolean. Public technique.
type BooleanBlindSQLi struct{}

func (BooleanBlindSQLi) ID() string { return "sqli-boolean-blind" }

func (BooleanBlindSQLi) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	// Require a stable baseline first: a page whose length varies on its own
	// produces a true/false difference by chance, so inferring injection from a
	// difference would be a false positive. Bail when it is not stable.
	b, ok := stableBaseline(ctx, s, p)
	if !ok || !b.stable {
		return nil
	}
	baseLen := b.length
	baseStatus := b.status

	// Pairs of (true, false) conditions across quoting styles.
	pairs := []struct{ t, f string }{
		{p.Base + "' AND '1'='1", p.Base + "' AND '1'='2"},
		{p.Base + "\" AND \"1\"=\"1", p.Base + "\" AND \"1\"=\"2"},
		{p.Base + " AND 1=1", p.Base + " AND 1=2"},
		{p.Base + "') AND ('1'='1", p.Base + "') AND ('1'='2"},
	}
	for _, pr := range pairs {
		if ctx.Err() != nil {
			return nil
		}
		tr, err := s.Send(ctx, p.Mutate(pr.t))
		if err != nil || tr == nil {
			continue
		}
		fr, err := s.Send(ctx, p.Mutate(pr.f))
		if err != nil || fr == nil {
			continue
		}
		// True must look like the baseline; false must differ clearly from both
		// the baseline and the true response.
		if similarLen(len(tr.Body), baseLen) && tr.StatusCode == baseStatus &&
			!similarLen(len(fr.Body), baseLen) && !similarLen(len(fr.Body), len(tr.Body)) {
			return []*scan.Issue{{
				Check: "sqli-boolean-blind", Name: "SQL injection (boolean-based blind)",
				URL: base.AbsoluteURL().String(), Param: p.Name,
				Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
				Detail:      "Parameter " + p.Name + " changed the response only for a false SQL condition (AND 1=2) while a true condition (AND 1=1) matched the baseline, indicating boolean-based blind SQL injection.",
				Remediation: "Use parameterized queries / prepared statements.",
				Evidence:    "true-condition length ≈ baseline; false-condition length differs",
				CWE:         "CWE-89",
			}}
		}
	}
	return nil
}

// similarLen reports whether two body lengths are within 5% (or 32 bytes).
func similarLen(a, b int) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	if d <= 32 {
		return true
	}
	larger := a
	if b > a {
		larger = b
	}
	return larger > 0 && d*100/larger <= 5
}

// TimeBlindSQLi detects time-based blind SQL injection via a database sleep.
type TimeBlindSQLi struct{}

func (TimeBlindSQLi) ID() string { return "sqli-time-blind" }

// AppliesTo limits time-based inference (which costs real wall-clock per probe)
// to the insertion points where SQL injection realistically occurs, so it does
// not sleep-probe every header and path segment.
func (TimeBlindSQLi) AppliesTo(k scan.Kind) bool {
	switch k {
	case scan.KindQuery, scan.KindBody, scan.KindJSON, scan.KindCookie, scan.KindHeader:
		return true
	default:
		return false
	}
}

const sqliDelay = 3

func (TimeBlindSQLi) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	// Median baseline over a few samples so jitter does not look like a delay.
	bt, ok := medianTiming(ctx, s, p, p.Base, 3)
	if !ok {
		return nil
	}
	payloads := []string{
		p.Base + "' AND SLEEP(%d)-- -",
		p.Base + "' AND SLEEP(%d) AND '1'='1",
		p.Base + " AND SLEEP(%d)",
		p.Base + "'; WAITFOR DELAY '0:0:%d'-- -",
		p.Base + "' || pg_sleep(%d)-- -",
	}
	for _, tpl := range payloads {
		if ctx.Err() != nil {
			return nil
		}
		tpl := tpl
		d1, ok := confirmScaledDelay(ctx, s, p, bt, sqliDelay, func(secs int) string {
			return sprintfDelay(tpl, secs)
		})
		if !ok {
			continue
		}
		return []*scan.Issue{{
			Check: "sqli-time-blind", Name: "SQL injection (time-based blind)",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail:      "Parameter " + p.Name + " delayed the response in proportion to a SQL sleep payload (and a doubled delay scaled), indicating time-based blind SQL injection.",
			Remediation: "Use parameterized queries / prepared statements.",
			Evidence:    "baseline " + bt.Round(time.Millisecond).String() + ", delayed " + d1.Round(time.Millisecond).String(),
			CWE:         "CWE-89",
		}}
	}
	return nil
}

func sprintfDelay(tpl string, secs int) string {
	// tpl has a single %d for the delay.
	return fmt.Sprintf(tpl, secs)
}
