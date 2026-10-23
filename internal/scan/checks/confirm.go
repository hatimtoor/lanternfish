package checks

import (
	"context"
	"sort"
	"strings"
	"time"

	"lanternfish/internal/scan"
)

// reflectionCtx classifies where a reflected marker landed in a response, so a
// check can calibrate confidence (an HTML-text reflection is readily
// exploitable; one confined to an HTML comment usually is not).
type reflectionCtx struct {
	found     bool
	inComment bool // the only occurrence(s) sit inside <!-- ... -->
}

// classifyReflection locates needle in body and reports whether every
// occurrence is inside an HTML comment.
func classifyReflection(body, needle string) reflectionCtx {
	var rc reflectionCtx
	from := 0
	allInComment := true
	for {
		i := strings.Index(body[from:], needle)
		if i < 0 {
			break
		}
		pos := from + i
		rc.found = true
		if !insideComment(body, pos) {
			allInComment = false
		}
		from = pos + len(needle)
	}
	if rc.found {
		rc.inComment = allInComment
	}
	return rc
}

// insideComment reports whether position pos in body falls within an HTML
// comment (the nearest "<!--" before it is not yet closed by "-->").
func insideComment(body string, pos int) bool {
	open := strings.LastIndex(body[:pos], "<!--")
	if open < 0 {
		return false
	}
	close := strings.Index(body[open:pos], "-->")
	return close < 0
}

// This file holds the shared differential-confirmation helpers that blind and
// inference checks use to keep false positives low. They mirror the discipline
// a mature scanner applies: establish a stable baseline before trusting a
// response difference, and measure timing with enough samples to beat network
// jitter. The techniques are standard and public; no third-party code is used.

// baseline captures a point's un-injected behavior.
type baseline struct {
	status int
	length int
	stable bool // two baseline fetches agreed closely
}

// stableBaseline fetches the insertion point's original value twice and reports
// whether the response is stable (similar status and length). Checks that infer
// injection from a response *difference* should bail when the baseline is not
// stable, because a naturally varying page produces difference by itself.
func stableBaseline(ctx context.Context, s scan.Sender, p scan.InsertionPoint) (baseline, bool) {
	r1, err := s.Send(ctx, p.Mutate(p.Base))
	if err != nil || r1 == nil {
		return baseline{}, false
	}
	r2, err := s.Send(ctx, p.Mutate(p.Base))
	if err != nil || r2 == nil {
		return baseline{}, false
	}
	b := baseline{status: r1.StatusCode, length: len(r1.Body)}
	b.stable = r1.StatusCode == r2.StatusCode && similarLen(len(r1.Body), len(r2.Body))
	return b, true
}

// medianTiming sends value n times (n>=1) and returns the median elapsed time.
// The median resists a single slow sample (GC pause, scheduler, a transient
// network hiccup) that would fool a one-shot timing comparison.
func medianTiming(ctx context.Context, s scan.Sender, p scan.InsertionPoint, value string, n int) (time.Duration, bool) {
	if n < 1 {
		n = 1
	}
	var samples []time.Duration
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		d, ok := timeSend(ctx, s, p, value)
		if !ok {
			continue
		}
		samples = append(samples, d)
	}
	if len(samples) == 0 {
		return 0, false
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], true
}

// confirmScaledDelay confirms a time-based vulnerability with a jitter-resistant,
// two-point method: the response must slow by at least threshold(delay) for a
// single delay, and the doubled delay must slow by at least threshold(2*delay),
// both measured against a median baseline. delayFmt formats the payload for a
// given number of seconds. It returns the observed single-delay latency.
func confirmScaledDelay(ctx context.Context, s scan.Sender, p scan.InsertionPoint,
	base time.Duration, delay int, payloadFor func(secs int) string) (time.Duration, bool) {
	// Require at least 0.8s of delay per requested second above baseline, so a
	// vulnerable sleep stands out while ordinary latency does not trip it.
	gate := func(secs int) time.Duration {
		return base + time.Duration(secs)*800*time.Millisecond
	}
	d1, ok := medianTiming(ctx, s, p, payloadFor(delay), 1)
	if !ok || d1 < gate(delay) {
		return 0, false
	}
	d2, ok := medianTiming(ctx, s, p, payloadFor(delay*2), 1)
	if !ok || d2 < gate(delay*2) {
		return 0, false
	}
	return d1, true
}

// injectableHeaders are the request headers worth probing for server-side
// injection (OS command / SQL). They are the headers real applications
// commonly read and then pass into a shell, query, or log pipeline. Probing
// every header is too slow and noisy, so the wait-heavy time-based and
// out-of-band checks restrict header-vector testing to this curated set.
var injectableHeaders = map[string]bool{
	"user-agent": true, "referer": true, "x-forwarded-for": true,
	"x-forwarded-host": true, "x-forwarded-by": true, "forwarded": true,
	"x-real-ip": true, "client-ip": true, "true-client-ip": true,
	"x-client-ip": true, "x-api-version": true, "x-request-id": true,
	"x-wap-profile": true, "from": true, "x-originating-ip": true,
}

// headerVectorAllowed reports whether a wait-heavy server-side-injection check
// should probe this insertion point. Non-header points are always allowed;
// header points only when the header is in the injectable set above.
func headerVectorAllowed(p scan.InsertionPoint) bool {
	if p.Kind != scan.KindHeader {
		return true
	}
	return injectableHeaders[strings.ToLower(p.Name)]
}

// vectorLabel describes an insertion point for a finding message.
func vectorLabel(p scan.InsertionPoint) string {
	switch p.Kind {
	case scan.KindHeader:
		return "header " + p.Name
	case scan.KindCookie:
		return "cookie " + p.Name
	default:
		return "parameter " + p.Name
	}
}
