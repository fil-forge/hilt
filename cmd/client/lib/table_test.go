package lib

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewTable(t *testing.T) {
	var buf bytes.Buffer
	table := NewTable(&buf)
	table.Header("ID", "Weight", "URL")
	if err := table.Append("did:key:zNode", "100", "http://piri-0:3000"); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := table.Render(); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected a header and one row, got %d lines:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "ID") || !strings.Contains(lines[0], "WEIGHT") {
		t.Fatalf("header not upper-cased and flush left: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "did:key:zNode  ") {
		t.Fatalf("row not flush left and space separated: %q", lines[1])
	}
	// Columns line up: the second column starts at the same offset in both lines.
	if strings.Index(lines[0], "WEIGHT") != strings.Index(lines[1], "100") {
		t.Fatalf("columns not aligned:\n%s", out)
	}
	for _, r := range "│─┌┐└┘├┤┬┴┼+|" {
		if strings.ContainsRune(out, r) {
			t.Fatalf("unexpected border character %q in output:\n%s", r, out)
		}
	}
}
