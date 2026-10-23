package checks

import (
	"context"
	"regexp"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// PathTraversalOracle detects path traversal at sinks that do not return file
// contents but do reveal, in the response, whether the supplied path exists or
// could be opened (e.g. "... file already exists" vs "... doesn't exist yet",
// or "Now ready to write to file: ..."). It is a differential existence oracle:
// a path pointing at a real system *directory* is reported as present while an
// otherwise-identical path with a random name is reported as absent, which
// proves the application resolves attacker-controlled paths against the real
// filesystem.
//
// Targets are directories, never files: a directory cannot be opened for
// writing, so this never truncates or modifies anything on the target even if
// the sink opens the path for output. The random control name confirms the
// oracle tracks the filesystem (no false positive on a constant message).
type PathTraversalOracle struct{}

func (PathTraversalOracle) ID() string { return "path-traversal-oracle" }

var (
	existsSig   = regexp.MustCompile(`(?i)already exists|ready to write to file|file exists`)
	notExistSig = regexp.MustCompile(`(?i)(does ?n[o']?t|do not|not) exist|no such file|couldn'?t open|cannot find`)
)

func (PathTraversalOracle) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	up := strings.Repeat("../", 12)
	upWin := strings.Repeat("..\\", 12)
	absent := randMarker("lfabs")

	// Each pair shares a style; only the final path component differs (a real
	// system directory vs a random, absent one).
	pairs := []struct{ present, missing, what string }{
		{`C:\Windows`, `C:\` + absent, "absolute Windows path"},
		{"/etc", "/" + absent, "absolute Unix path"},
		{up + "Windows", up + absent, "relative traversal (forward slash)"},
		{up + "etc", up + absent, "relative traversal (forward slash)"},
		{upWin + "Windows", upWin + absent, "relative traversal (backslash)"},
	}

	for _, pr := range pairs {
		if ctx.Err() != nil {
			return nil
		}
		rp, err := s.Send(ctx, p.Mutate(pr.present))
		if err != nil || rp == nil {
			continue
		}
		present := rp.BodyString()
		// Only spend the second request when the first looks like a hit.
		if !existsSig.MatchString(present) {
			continue
		}
		rm, err := s.Send(ctx, p.Mutate(pr.missing))
		if err != nil || rm == nil {
			continue
		}
		missing := rm.BodyString()
		// Confirm the oracle flipped: the real directory is reported present and
		// the random one is not. This rules out a constant "exists" message.
		if !existsSig.MatchString(missing) && notExistSig.MatchString(missing) {
			return []*scan.Issue{{
				Check: "path-traversal-oracle", Name: "Path traversal (file-existence oracle)",
				URL: base.AbsoluteURL().String(), Param: p.Name,
				Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
				Detail: "Input in " + vectorLabel(p) + " is resolved against the real filesystem: an " + pr.what +
					" pointing at a system directory was reported as existing, while the same path with a random name was reported as absent. The sink discloses whether attacker-chosen paths exist (and may read or write them), confirming path traversal.",
				Remediation: "Resolve and canonicalize paths, reject traversal sequences, and confine file access to an allow-listed base directory.",
				Evidence:    "present: " + firstLine(existsSig.FindString(present)) + " | absent: " + firstLine(notExistSig.FindString(missing)),
				CWE:         "CWE-22",
			}}
		}
	}
	return nil
}
