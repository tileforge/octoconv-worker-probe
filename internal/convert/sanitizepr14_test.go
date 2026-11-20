package convert

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// Regression tests for the three findings of PR #14 round 1. All three are the
// same class in different clothes: a rule stated once, applied by two
// independent walkers, and each walker getting a slightly different version of
// it -- or, in the object-index case, both getting the same wrong one.

// TestObjectIndexIgnoresStreamPayloads is the serious one.
//
// The object index was a whole-file search for " obj". A stream payload is
// arbitrary bytes, so a payload containing "7 0 obj\n5" overwrote the real
// object 7's offset, and a later "/Length 7 0 R" resolved its length from
// attacker-controlled bytes. That either rejects valid output or -- if an
// in-payload "endstream" lines up with the bogus length -- protects only a
// prefix and leaves redactEngineIdentity free to rewrite the rest of a real
// stream. Which is precisely the corruption this phase exists to prevent,
// reintroduced through its own helper.
func TestObjectIndexIgnoresStreamPayloads(t *testing.T) {
	// A decoy object header inside a direct-length stream's payload, naming
	// the same object number the later indirect /Length refers to.
	decoy := []byte("filler\n7 0 obj\n5\nendobj\nmore filler\n")
	real := []byte("the real payload, longer than the decoy claims\n")

	// ORDER MATTERS AND THE FIRST VERSION OF THIS TEST HAD IT WRONG.
	//
	// The index is a map, so a later occurrence overwrites an earlier one. With
	// the real "7 0 obj" written last, the whole-file scan produced the RIGHT
	// answer anyway and both inversions passed -- a test that proved nothing,
	// found by inverting rather than by reading. The real object therefore comes
	// FIRST here and the decoy second, which is the order the finding describes:
	// "an indirect length object is FOLLOWED in the file by a stream whose
	// payload contains 7 0 obj".
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	fmt.Fprintf(&buf, "7 0 obj\n%d\nendobj\n", len(real))
	fmt.Fprintf(&buf, "1 0 obj\n<< /Length %d >>\nstream\n", len(decoy))
	buf.Write(decoy)
	buf.WriteString("endstream\nendobj\n")
	fmt.Fprintf(&buf, "2 0 obj\n<< /Length 7 0 R >>\nstream\n")
	buf.Write(real)
	buf.WriteString("endstream\nendobj\n")
	buf.WriteString("trailer\n<< /Size 8 >>\nstartxref\n0\n%%EOF\n")
	raw := buf.Bytes()

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatalf("pdfStreamRanges: %v -- the decoy object header inside a stream "+
			"payload was read as structure", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("got %d ranges, want 2", len(ranges))
	}

	// Every byte of the second stream must be protected, not just the first 5.
	tail := bytes.Index(raw, []byte("longer than the decoy claims"))
	if tail < 0 {
		t.Fatal("fixture lost its own payload")
	}
	if !inAnyRange(ranges, tail) {
		t.Errorf("the tail of the real stream at %d is outside %v -- the redaction "+
			"may rewrite it", tail, ranges)
	}

	// And the verifier's independent index must reach the same conclusion.
	if _, err := pdfNonStreamBytes(raw); err != nil {
		t.Errorf("the verifier's own object index was poisoned by the same decoy: %v", err)
	}
}

// TestEndstreamAcceptsEveryPDFWhitespaceByte pins the two walkers to one
// definition of whitespace.
//
// PDF's whitespace set (ISO 32000-1 Table 1) includes form feed and NUL. The
// sanitizer's pdfEndstreamFollows accepted them through isPDFSpace; the
// verifier's copy listed four bytes by hand and did not. So a valid
// "\f\nendstream" was accepted on one side and rejected on the other -- and a
// verifier rejection DELETES the output.
//
// Two independent walkers are supposed to disagree about verdicts. They are not
// supposed to disagree about what a space is.
func TestEndstreamAcceptsEveryPDFWhitespaceByte(t *testing.T) {
	body := []byte("payload")
	for _, ws := range []struct {
		name  string
		bytes string
	}{
		{"line feed", "\n"},
		{"carriage return + line feed", "\r\n"},
		{"space", " "},
		{"tab", "\t"},
		{"form feed", "\f\n"},
		{"nul", "\x00\n"},
	} {
		t.Run(ws.name, func(t *testing.T) {
			raw := []byte("%PDF-1.4\n1 0 obj\n<< /Length " + fmt.Sprint(len(body)) +
				" >>\nstream\n" + string(body) + ws.bytes + "endstream\nendobj\n")

			if _, err := pdfStreamRanges(raw); err != nil {
				t.Errorf("the sanitizer rejected %s before endstream: %v", ws.name, err)
			}
			if _, err := pdfNonStreamBytes(raw); err != nil {
				t.Errorf("the verifier rejected %s before endstream: %v -- and a "+
					"verifier rejection deletes the output", ws.name, err)
			}
		})
	}
}

// TestContentTypeExtensionMatchIsCaseInsensitive covers OPC's own rule.
//
// Extension matching in OPC is ASCII-case-insensitive (ECMA-376 Part 2
// §9.1.2.3), and rewriteContentTypes preserves whatever capitalization the
// input used. The first version of contentTypeDeclares searched for the
// lowercase extension only, so a package declaring `Extension="XML"` was
// rejected -- and rejection deletes the output. Too strict costs a client a
// file exactly as surely as too loose lets one through.
func TestContentTypeExtensionMatchIsCaseInsensitive(t *testing.T) {
	requireVerifierBinaries(t)

	for _, ext := range []string{"xml", "XML", "Xml"} {
		t.Run("Extension="+ext, func(t *testing.T) {
			path := buildOOXMLPackage(t, map[string][]byte{
				"[Content_Types].xml": []byte(`<?xml version="1.0"?>` +
					`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
					`<Default Extension="` + ext + `" ContentType="application/xml"/>` +
					`</Types>`),
				"word/document.xml": []byte(`<?xml version="1.0"?><document/>`),
			})
			if _, err := verifySanitized(context.Background(), engineExec{}, "docx", path); err != nil {
				t.Errorf("a package declaring its main part with Extension=%q was rejected: %v",
					ext, err)
			}
		})
	}

	// The match must still be about the right extension, or "case-insensitive"
	// has quietly become "any Default at all".
	path := buildOOXMLPackage(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/xml"/>` +
			`</Types>`),
		"word/document.xml": []byte(`<?xml version="1.0"?><document/>`),
	})
	if _, err := verifySanitized(context.Background(), engineExec{}, "docx", path); err == nil {
		t.Error("a Default for a DIFFERENT extension was accepted as declaring word/document.xml")
	}
}

// TestPR14FixesDoNotBreakTheCorpus is the cheap guard against a fix that is
// correct in isolation and wrong in place.
func TestPR14FixesDoNotBreakTheCorpus(t *testing.T) {
	requireGhostscript(t)
	requireVerifierBinaries(t)

	for _, tc := range []struct{ format, name string }{
		{"pdf", "threat_all_classes.pdf"},
		{"pdf", "endstream_in_stream.pdf"},
		{"jpg", "icc_multichunk.jpg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			if _, err := sanitizeFile(context.Background(), engineExec{}, tc.format,
				filepath.Join(sanitizeCorpusDir, tc.name), out); err != nil {
				t.Errorf("sanitizeFile: %v", err)
			}
		})
	}
}
