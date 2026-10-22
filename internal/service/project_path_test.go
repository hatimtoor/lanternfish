package service

import (
	"path/filepath"
	"testing"

	"lanternfish/internal/session"
)

func TestProjectPathGuard(t *testing.T) {
	s := New(session.New(), false)

	// Traversal is rejected on both save and load.
	if err := s.SaveProject("../evil.json"); err == nil {
		t.Fatal("save should reject a path containing ..")
	}
	if err := s.LoadProject("../../etc/passwd.json"); err == nil {
		t.Fatal("load should reject a path containing ..")
	}
	// A non-project extension is rejected (prevents overwriting dotfiles etc).
	if err := s.SaveProject("notes.txt"); err == nil {
		t.Fatal("save should reject a non-project extension")
	}
	// An empty path is rejected.
	if err := s.SaveProject(""); err == nil {
		t.Fatal("save should reject an empty path")
	}

	// A sensible project file round-trips.
	p := filepath.Join(t.TempDir(), "proj.json")
	if err := s.SaveProject(p); err != nil {
		t.Fatalf("save valid project: %v", err)
	}
	if err := s.LoadProject(p); err != nil {
		t.Fatalf("load valid project: %v", err)
	}
}
