package checks

import "testing"

func TestClassifyReflection(t *testing.T) {
	// Marker in plain HTML text: exploitable context, not comment-only.
	rc := classifyReflection("<div><MARK></div>", "<MARK>")
	if !rc.found || rc.inComment {
		t.Fatalf("plain text: found=%v inComment=%v", rc.found, rc.inComment)
	}

	// Marker only inside an HTML comment: comment-only.
	rc = classifyReflection("<!-- <MARK> -->", "<MARK>")
	if !rc.found || !rc.inComment {
		t.Fatalf("comment-only: found=%v inComment=%v", rc.found, rc.inComment)
	}

	// One in a comment, one in the body: not comment-only.
	rc = classifyReflection("<!-- <MARK> --><p><MARK></p>", "<MARK>")
	if !rc.found || rc.inComment {
		t.Fatalf("mixed: found=%v inComment=%v", rc.found, rc.inComment)
	}

	// Absent.
	if rc = classifyReflection("nothing here", "<MARK>"); rc.found {
		t.Fatalf("absent: found=%v", rc.found)
	}
}
