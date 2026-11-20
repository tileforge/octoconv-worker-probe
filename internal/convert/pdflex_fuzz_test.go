package convert

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Fuzzing the PDF tokenizer, because five review rounds were a person doing by
// hand what `go test -fuzz` does mechanically.
//
// PR #14 found eighteen defects across five rounds. Ten were byte-scanning
// mistakes in the code pdflex.go replaced; four more were in the TOKENIZER
// ITSELF -- arrays, signed integers, comments between reference tokens, name
// escapes -- and every one of them arrived as a hand-built adversarial input.
// `.planning/RETROSPECTIVE.md` already names the lesson ("don't predict a
// parser, test against it"), and a sixth round of hand-built cases would be
// more predicting.
//
// WHAT IS ASSERTED, AND WHY IT IS NOT A GOLDEN OUTPUT
//
// A fuzzer cannot say what the right stream ranges are for an arbitrary byte
// string -- that is the parser's job and would just re-implement it. What it
// CAN say is that certain things must hold no matter what the input is, and
// each of these is an invariant the sanitizer's safety already rests on:
//
//	1. it terminates and does not panic, and every range lies inside the input;
//	2. ranges are ordered and do not overlap -- overlapping ranges would let
//	   pdfNonStreamBytes blank bytes twice and, worse, mean the walk read the
//	   same bytes as both payload and structure;
//	3. every returned range is followed by "endstream" after only whitespace.
//	   The scanner checks this itself; asserting it HERE, with an independent
//	   re-implementation, is the point -- a check that only ever validates
//	   itself proves nothing;
//	4. pdfNonStreamBytes returns exactly as many bytes as it was given and
//	   differs from the input only inside the returned ranges. That is the
//	   contract the verifier's whole "structure vs payload" split depends on:
//	   if it could differ outside a payload, a residue scan would be reading
//	   bytes the file does not contain;
//	5. the pass whose ranges were returned recorded no object header inside
//	   any of them -- scanPDF's own claim ("a resolved payload is jumped over
//	   whole"), and the one property that decides the residual PR #14 left
//	   open.
//
// A failure here is a REAL finding, not a fuzzer artifact: every property is
// one the calling code already assumes.

// endstreamFollowsIndependently re-implements the "only whitespace, then
// endstream" rule WITHOUT calling the scanner's own helper. Deliberately: the
// property is worth asserting only if the assertion has its own opinion.
func endstreamFollowsIndependently(b []byte, end int) bool {
	i := end
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\r', '\n', '\f', 0:
			i++
			continue
		}
		break
	}
	return bytes.HasPrefix(b[i:], []byte("endstream"))
}

var pdfLexFuzzSeeds = [][]byte{
	[]byte(""),
	[]byte("%PDF-1.4\n"),
	[]byte("%PDF-1.4\n1 0 obj\n<< /Length 5 >>\nstream\nabcde\nendstream\nendobj\n"),
	[]byte("%PDF-1.4\n1 0 obj\n<< /Length 2 0 R >>\nstream\nabcde\nendstream\nendobj\n" +
		"2 0 obj\n5\nendobj\n"),
	[]byte("%PDF-1.4\n1 0 obj\n<< /Length 5 /Foo [/Length 900] >>\nstream\nabcde\nendstream\nendobj\n"),
	[]byte("%PDF-1.4\n% 7 0 obj 5\n1 0 obj\n<< /Length 5 >>\nstream\nabcde\nendstream\nendobj\n"),
	[]byte("%PDF-1.4\n1 0 obj\n<< /Length -5 >>\nstream\nabcde\nendstream\nendobj\n"),
	[]byte("%PDF-1.4\n1 0 obj\n<< /Length 2 % c\n0 R >>\nstream\nabcde\nendstream\nendobj\n"),
	[]byte("%PDF-1.4\n1 0 obj\n<< /Le#6egth 5 >>\nstream\nabcde\nendstream\nendobj\n"),
	[]byte("%PDF-1.4\n1 0 obj\n<< /Length 5 /X ( >>\nstream\nabcde\nendstream\nendobj\n"),
	[]byte("%PDF-1.4\n1 0 obj\n<< /Length 30 >>\nstream\n2 0 obj\n<< /Length 1 >>\nx\nendstream\nendobj\n"),
}

func FuzzPDFStreamPayloads(f *testing.F) {
	for _, s := range pdfLexFuzzSeeds {
		f.Add(s)
	}
	// And the real files this repository already pins: ghostscript output and
	// the threat corpus. Synthetic seeds share their author's blind spots.
	for _, name := range []string{
		filepath.Join("testdata", "sanitize", "threat_all_classes.pdf"),
		filepath.Join("testdata", "sanitize", "endstream_in_stream.pdf"),
		filepath.Join("testdata", "ocr", "multipage_text.pdf"),
		filepath.Join("testdata", "verapdf_noncompliant.pdf"),
	} {
		if raw, err := os.ReadFile(name); err == nil {
			f.Add(raw)
		}
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		ranges, err := pdfStreamPayloads(raw)
		if err != nil {
			// Failing closed is always allowed; it is the only other legal
			// outcome. What must never happen is a panic, and reaching this
			// line means one did not.
			return
		}

		prevEnd := 0
		for i, r := range ranges {
			lo, hi := r[0], r[1]

			// (1) inside the input, and not inverted.
			if lo < 0 || hi < lo || hi > len(raw) {
				t.Fatalf("range %d = [%d,%d) is not inside [0,%d)", i, lo, hi, len(raw))
			}
			// (2) ordered and non-overlapping.
			if lo < prevEnd {
				t.Fatalf("range %d = [%d,%d) starts before the previous one ended (%d): the walk "+
					"read the same bytes as both payload and structure", i, lo, hi, prevEnd)
			}
			prevEnd = hi

			// (3) the endstream rule, checked with its own implementation.
			if !endstreamFollowsIndependently(raw, hi) {
				t.Fatalf("range %d = [%d,%d) is not followed by endstream after whitespace; the "+
					"scanner accepted a payload whose end it cannot justify", i, lo, hi)
			}
		}

		// (4) the blanking contract.
		out, err := pdfNonStreamBytes(raw)
		if err != nil {
			t.Fatalf("pdfStreamPayloads succeeded but pdfNonStreamBytes failed on the same bytes: %v", err)
		}
		if len(out) != len(raw) {
			t.Fatalf("pdfNonStreamBytes returned %d bytes for a %d-byte input", len(out), len(raw))
		}
		for i := range raw {
			if out[i] == raw[i] {
				continue
			}
			if !insideAny(ranges, i) {
				t.Fatalf("byte %d changed (%q -> %q) outside every stream range: a residue scan "+
					"would be reading bytes this file does not contain", i, raw[i], out[i])
			}
		}

		// (5) NO BYTE INSIDE A PAYLOAD WAS READ AS STRUCTURE.
		//
		// This is the property the residual from PR #14 is about, and the one
		// the four above do NOT decide: "a decoy inside a stream that itself
		// failed to resolve is reachable through the resynchronisation" was
		// stated as open when that PR closed. A decoy that succeeds looks
		// perfectly well-formed from outside -- its range is in bounds,
		// ordered, and followed by an endstream it planted -- so properties
		// 1-4 pass while the scan believes an object definition it read out of
		// a payload.
		//
		// scanPDF's own doc comment makes the claim this checks: "a resolved
		// payload is jumped over whole, so no byte inside a payload can ever
		// be read as structure". An object offset that lands inside a returned
		// range is that claim being false.
		//
		// COMPARE LIKE WITH LIKE, which the first version of this property did
		// not, and the fuzzer caught it on its own corpus within a minute. The
		// FIRST pass cannot skip a payload whose /Length is defined later, so
		// it necessarily walks into one and records whatever headers it finds;
		// pdfStreamPayloads then discards that pass entirely and returns the
		// SECOND, xref-seeded one. Measured on the input this produced
		// (testdata/fuzz/.../404c4022b4abe12f, 9 875 bytes):
		//
		//	first pass   unresolved=2  streams=1  10 objects inside the ranges
		//	second pass  unresolved=0  streams=3   0 objects inside the ranges
		//
		// That is PR #14's residual, visible: the resynchronisation really does
		// record decoy headers out of a payload. What defuses it is that the
		// retry is anchored in the cross-reference table rather than in that
		// index -- so the pass whose answer is USED records nothing inside a
		// payload. This asserts exactly that, on the pass that was used.
		scan := scanPDF(raw)
		if scan.unresolved != 0 {
			scan = scanPDFSeeded(raw, pdfXrefObjects(raw))
		}
		for num, off := range scan.objects {
			if insideAny(ranges, off) {
				t.Fatalf("object %d was recorded at offset %d, which is INSIDE a stream payload: "+
					"the walk read structure out of bytes it had already accepted as opaque, which "+
					"is how a planted /Length resolves a short range", num, off)
			}
		}
	})
}

func insideAny(ranges [][2]int, i int) bool {
	for _, r := range ranges {
		if i >= r[0] && i < r[1] {
			return true
		}
	}
	return false
}
