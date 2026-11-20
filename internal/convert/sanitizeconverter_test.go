package convert

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestSanitizePairsTargetTheSanitizedForm is the regression proof for the
// third finding of PR #12.
//
// SanitizedOOXMLExtension implements D-06 -- a sanitized .docm is a .docx,
// because the sanitizer rewrites [Content_Types].xml to the macro-free type --
// and it was written, documented and unit-tested by Plan 60-03 while nothing
// in production called it. The registry got identity pairs for every format,
// so the worker named a sanitized .docm `out.docm`: a file presenting itself
// as macro-enabled with no macros inside, which Office warns on.
//
// The unit test on the helper stayed green through all of that, because it
// tested the helper rather than its use. This one tests the registry, which is
// the thing the worker and the API actually read.
func TestSanitizePairsTargetTheSanitizedForm(t *testing.T) {
	cases := []struct {
		from, want string
		why        string
	}{
		{"docm", "docx", "macro-enabled Word document loses its macro-enabled content type"},
		{"xlsm", "xlsx", "same for Excel"},
		{"pptm", "pptx", "same for PowerPoint"},
		{"docx", "docx", "already macro-free: the pair stays identity"},
		{"pdf", "pdf", "sanitize is not a conversion"},
		{"jpg", "jpg", "same"},
		{"png", "png", "same"},
	}

	for _, tc := range cases {
		if _, ok := Default.EngineForOp(OperationSanitize, tc.from, tc.want); !ok {
			t.Errorf("no registered sanitize pair %s -> %s (%s)", tc.from, tc.want, tc.why)
		}
		if tc.from != tc.want {
			// The identity pair must NOT be registered for a macro-enabled
			// format: accepting it would let a client ask for an output whose
			// extension contradicts its own content type.
			if _, ok := Default.EngineForOp(OperationSanitize, tc.from, tc.from); ok {
				t.Errorf("sanitize %s -> %s is registered, but a sanitized %s is a %s",
					tc.from, tc.from, tc.from, tc.want)
			}
		}
	}
}

// TestEverySanitizePairTargetsAKnownMIMEType closes the gap the fix above
// opened: changing a target extension is only safe if the service can describe
// the resulting object. An unknown extension yields an empty content type,
// which S3 serves as application/octet-stream and a browser offers as a
// download of unknown kind.
func TestEverySanitizePairTargetsAKnownMIMEType(t *testing.T) {
	for _, p := range (SanitizeConverter{}).Pairs() {
		if MIMEType(p.To) == "" {
			t.Errorf("sanitize target %q has no MIME type; the stored object would carry none", p.To)
		}
	}
}

// TestSanitizeConverterRejectsOptions pins the refusal rather than the
// comment. Sanitize has no options: every knob would be a way to ask for less
// removal, and an operation whose contract is "the enumerated classes are
// gone" cannot have a switch that makes that untrue.
func TestSanitizeConverterRejectsOptions(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.png")
	if err := os.WriteFile(in, []byte{0x89, 'P', 'N', 'G'}, 0o600); err != nil {
		t.Fatal(err)
	}
	err := (SanitizeConverter{}).Convert(context.Background(), in, filepath.Join(dir, "out.png"),
		map[string]any{"keep_metadata": true})
	if err == nil {
		t.Fatal("Convert accepted options; a sanitize option is a way to ask for less removal")
	}

	if _, err := SanitizeOptsFromMap(map[string]any{"keep_metadata": true}); err == nil {
		t.Error("SanitizeOptsFromMap accepted options -- a persisted Opts map with content is a " +
			"corrupt column value and must be terminal (D-10)")
	}
}
