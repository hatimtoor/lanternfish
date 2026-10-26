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
	inRCDATA  bool // the only occurrence(s) sit inside <textarea>/<title> (raw-text, not executable)
}

// classifyReflection locates needle in body and reports whether every
// occurrence is inside an HTML comment.
func classifyReflection(body, needle string) reflectionCtx {
	var rc reflectionCtx
	from := 0
	allInComment, allInRCDATA := true, true
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
		if !insideRCDATA(body, pos) {
			allInRCDATA = false
		}
		from = pos + len(needle)
	}
	if rc.found {
		rc.inComment = allInComment
		rc.inRCDATA = allInRCDATA
	}
	return rc
}

// insideRCDATA reports whether pos sits inside a <textarea> or <title> element,
// whose contents are raw text (RCDATA): a "<" there is literal, not a tag start,
// so a reflected "<marker" is not executable unless the element's own closing
// tag is also injected.
func insideRCDATA(body string, pos int) bool {
	low := strings.ToLower(body[:pos])
	for _, tag := range []string{"textarea", "title"} {
		open := strings.LastIndex(low, "<"+tag)
		if open < 0 {
			continue
		}
		if !strings.Contains(low[open:], "</"+tag) {
			return true // an unclosed RCDATA element precedes the reflection
		}
	}
	return false
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
	stable bool // the benign fetches agreed closely
	jitter int  // largest body-length variation seen across benign fetches
}

// stableBaseline samples the insertion point's original value a few times and
// reports whether the response is stable (same status, similar length) along
// with the natural length jitter. Checks that infer injection from a response
// *difference* bail when the baseline is unstable, and demand a change larger
// than the jitter, so a naturally varying page does not produce false findings.
func stableBaseline(ctx context.Context, s scan.Sender, p scan.InsertionPoint) (baseline, bool) {
	var lens, statuses []int
	for i := 0; i < 3; i++ {
		r, err := s.Send(ctx, p.Mutate(p.Base))
		if err != nil || r == nil {
			if i == 0 {
				return baseline{}, false
			}
			break
		}
		lens = append(lens, len(r.Body))
		statuses = append(statuses, r.StatusCode)
	}
	if len(lens) == 0 {
		return baseline{}, false
	}
	b := baseline{status: statuses[0], length: lens[0], stable: true}
	for i := 0; i < len(lens); i++ {
		if statuses[i] != statuses[0] {
			b.stable = false
		}
		for j := i + 1; j < len(lens); j++ {
			d := lens[i] - lens[j]
			if d < 0 {
				d = -d
			}
			if d > b.jitter {
				b.jitter = d
			}
			if !similarLen(lens[i], lens[j]) {
				b.stable = false
			}
		}
	}
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
