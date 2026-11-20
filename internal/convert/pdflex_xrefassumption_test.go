package convert

import (
	"strings"
	"testing"
)

// The tokenizer's forward-reference resolution depends on a GHOSTSCRIPT FLAG,
// and nothing held the two together until now.
//
// pdfStreamPayloads resolves "/Length 6 0 R" through the classic
// cross-reference TABLE. pdflex.go says why that is safe -- "sanitizePDF forces
// -dCompatibilityLevel=1.4, which means a classic cross-reference TABLE rather
// than a 1.5+ cross-reference stream" -- and that sentence is the whole
// argument. A PDF 1.5+ writer emits a cross-reference STREAM instead, which
// pdfXrefObjects cannot read, so every forward-referenced /Length becomes
// unresolved and the verifier fails CLOSED on files it should pass.
//
// The failure mode is therefore not a security hole; it is a valid document
// refused, which is this project's other recurring defect (63-02 removed a
// whole admission gate for it). It would arrive as "sanitize suddenly rejects
// everything" some time after an unrelated change to a flag list.
//
// Raised as a follow-up when PR #14 closed: "worth a test that renders the flag
// and the xref-reading assumption together". This is it.
func TestXrefAssumptionIsPinnedToTheGhostscriptFlag(t *testing.T) {
	args := strings.Join(pdfwriteArgs("/tmp/in.ps", "/tmp/out.pdf"), " ")

	const flag = "-dCompatibilityLevel=1.4"
	if !strings.Contains(args, flag) {
		t.Fatalf("pdfwriteArgs no longer passes %s.\n\nThat flag is not a preference: "+
			"pdfStreamPayloads resolves forward /Length references through the CLASSIC "+
			"cross-reference table, and a 1.5+ writer emits a cross-reference STREAM that "+
			"pdfXrefObjects cannot read. Every forward-referenced stream would go unresolved and "+
			"verifySanitized would fail closed on its own sanitizer's output.\n\nIf the level is "+
			"raised deliberately, pdfXrefObjects has to learn cross-reference streams FIRST.\n\n"+
			"args = %s", flag, args)
	}

	// The version in the flag and the version pdfXrefObjects can actually read
	// are the same claim in two places. Pin the number, not just the presence:
	// -dCompatibilityLevel=1.5 would keep every substring check above happy.
	for _, higher := range []string{"1.5", "1.6", "1.7", "2.0"} {
		if strings.Contains(args, "-dCompatibilityLevel="+higher) {
			t.Fatalf("pdfwriteArgs asks ghostscript for PDF %s, which may emit a cross-reference "+
				"STREAM; pdfXrefObjects reads only classic tables", higher)
		}
	}
}

// TestXrefStreamFileFailsClosedRatherThanSilently is the other half: it shows
// what the flag protects against, on a file that HAS a cross-reference stream
// instead of a table.
//
// The assertion is deliberately weak on WHICH outcome -- the point is that both
// legal outcomes are safe, and neither is "resolved a length from somewhere it
// should not have". A file whose xref is unreadable either resolves nothing
// (and fails closed) or resolves only from objects seen before the stream.
func TestXrefStreamFileFailsClosedRatherThanSilently(t *testing.T) {
	// A minimal 1.5-shaped file: the length of object 1's stream is defined by
	// object 2, which comes AFTER it, and the only cross-reference is a stream
	// (/Type /XRef), not a table.
	raw := []byte("%PDF-1.5\n" +
		"1 0 obj\n<< /Length 2 0 R >>\nstream\nabcde\nendstream\nendobj\n" +
		"2 0 obj\n5\nendobj\n" +
		"3 0 obj\n<< /Type /XRef /Size 4 /W [1 2 1] /Length 12 >>\nstream\n" +
		"\x00\x00\x00\x00\x01\x00\x09\x00\x01\x00\x30\x00\nendstream\nendobj\n" +
		"startxref\n120\n%%EOF\n")

	ranges, err := pdfStreamPayloads(raw)
	if err != nil {
		// Fail-closed: the documented behaviour for an input whose forward
		// references cannot be resolved.
		return
	}
	for i, r := range ranges {
		if r[0] < 0 || r[1] > len(raw) || r[1] < r[0] {
			t.Fatalf("range %d = [%d,%d) is outside the input", i, r[0], r[1])
		}
		if !endstreamFollowsIndependently(raw, r[1]) {
			t.Fatalf("range %d = [%d,%d) is not followed by endstream: a length was resolved from "+
				"something the file does not justify", i, r[0], r[1])
		}
	}
}
