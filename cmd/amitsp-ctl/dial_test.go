package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/adee42/ami-tsp/internal/config"
	"github.com/adee42/ami-tsp/internal/lines"
)

func testRegistry(t *testing.T, channels ...string) *lines.Registry {
	t.Helper()
	reg, err := lines.Load(filepath.Join(t.TempDir(), "lines.json"))
	if err != nil {
		t.Fatal(err)
	}
	var found []lines.Entry
	for _, ch := range channels {
		e := lines.Entry{Line: config.Line{Channel: ch}}
		e.Line.Normalise()
		found = append(found, e)
	}
	reg.Merge(found)
	return reg
}

// TestResolveLine covers what `dial` accepts: an extension by default, or a
// line index behind a "#".
func TestResolveLine(t *testing.T) {
	reg := testRegistry(t, "PJSIP/81", "PJSIP/83", "PJSIP/84")

	for _, tc := range []struct {
		spec string
		want int
	}{
		{"81", 0},
		{"83", 1},
		{"84", 2},
		{"#0", 0},
		{"#2", 2},
		{" 83 ", 1}, // trimmed
		{"# 2", 2},  // tolerated
	} {
		got, err := resolveLine(reg, tc.spec)
		if err != nil {
			t.Errorf("resolveLine(%q) errored: %v", tc.spec, err)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveLine(%q) = %d, want %d", tc.spec, got, tc.want)
		}
	}
}

// TestResolveLineErrors: every failure must name the alternatives, because the
// whole point of this argument is not having to look them up first.
func TestResolveLineErrors(t *testing.T) {
	reg := testRegistry(t, "PJSIP/81", "PJSIP/83")

	for _, spec := range []string{"99", "#7", "#-1", "#abc", ""} {
		_, err := resolveLine(reg, spec)
		if err == nil {
			t.Errorf("resolveLine(%q) should have failed", spec)
			continue
		}
		// The numeric-syntax failures do not list lines; the lookup failures
		// must.
		if spec == "99" || spec == "#7" {
			if !strings.Contains(err.Error(), "PJSIP/81") {
				t.Errorf("resolveLine(%q) error does not list the lines: %v", spec, err)
			}
		}
	}
}

// TestResolveLineAmbiguous: two devices can share an extension, and guessing
// which one to call from would be worse than refusing.
func TestResolveLineAmbiguous(t *testing.T) {
	// Two endpoints deliberately answering the same extension. The channel
	// names differ, so the registry keeps both.
	reg := testRegistry(t)
	reg.Merge([]lines.Entry{
		{Line: config.Line{Channel: "PJSIP/81a", Extension: "81"}},
		{Line: config.Line{Channel: "PJSIP/81b", Extension: "81"}},
	})

	if _, err := resolveLine(reg, "81"); err == nil {
		t.Fatal("a shared extension should not resolve silently")
	} else if !strings.Contains(err.Error(), "#0") || !strings.Contains(err.Error(), "#1") {
		t.Errorf("ambiguity error should offer both indices: %v", err)
	}

	// The "#" form is the documented way out of the ambiguity.
	if got, err := resolveLine(reg, "#1"); err != nil || got != 1 {
		t.Errorf("resolveLine(#1) = %d, %v; want 1, nil", got, err)
	}
}
