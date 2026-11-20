package convert

import (
	"bytes"
	"context"
	"fmt"
	"testing"
)

// Round 4 of PR #14. Four of the five are ordinary tokenizer bugs -- the price of
// having written a tokenizer -- and the fifth says the retry was still anchored
// in a guess.

// TestLengthInsideAnArrayIsNotTheStreams covers array nesting.
//
// Arrays do not change dictionary depth, so "<< /Length N /Foo [/Length 5] >>"
// had the inner name read as another key of the outer dictionary, overwriting
// the real length. If byte 5 lined up with an in-payload "endstream" the short
// range was accepted and the rest of the payload left exposed.
func TestLengthInsideAnArrayIsNotTheStreams(t *testing.T) {
	body := "0123456789012345678901234"

	for _, tc := range []struct{ name, dict string }{
		{"array after the real length", `<< /Length 25 /Foo [/Length 5] >>`},
		{"array before the real length", `<< /Foo [/Length 5] /Length 25 >>`},
		{"nested arrays", `<< /Length 25 /Foo [[/Length 5] /Length 7] >>`},
		{"array inside a sub-dictionary", `<< /Length 25 /DP << /Foo [/Length 5] >> >>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte("%PDF-1.4\n1 0 obj\n" + tc.dict + "\nstream\n" + body +
				"\nendstream\nendobj\ntrailer\n<< /Size 2 >>\nstartxref\n0\n%%EOF\n")
			ranges, err := pdfStreamRanges(raw)
			if err != nil {
				t.Fatalf("pdfStreamRanges: %v", err)
			}
			if len(ranges) != 1 || ranges[0][1]-ranges[0][0] != len(body) {
				t.Errorf("ranges = %v, want one range of %d bytes -- a /Length inside an "+
					"array was used as the stream's own", ranges, len(body))
			}
		})
	}
}

// TestSignedIntegersAreIntegers covers PDF's signed integer syntax (ISO 32000-1
// 7.3.3). "/Length +5" is valid and was rejected outright, which is a
// compatibility break the lexical walker it replaced did not have -- and a
// rejection deletes the output.
func TestSignedIntegersAreIntegers(t *testing.T) {
	body := "abcde"
	for _, decl := range []string{"5", "+5"} {
		t.Run("/Length "+decl, func(t *testing.T) {
			raw := []byte("%PDF-1.4\n1 0 obj\n<< /Length " + decl + " >>\nstream\n" + body +
				"\nendstream\nendobj\ntrailer\n<< /Size 2 >>\nstartxref\n0\n%%EOF\n")
			ranges, err := pdfStreamRanges(raw)
			if err != nil {
				t.Fatalf("pdfStreamRanges rejected a valid file: %v", err)
			}
			if len(ranges) != 1 || ranges[0][1]-ranges[0][0] != len(body) {
				t.Errorf("ranges = %v, want one range of %d bytes", ranges, len(body))
			}
		})
	}

	// A negative length is not a length. It must fail closed rather than be
	// clamped into something that looks workable.
	raw := []byte("%PDF-1.4\n1 0 obj\n<< /Length -5 >>\nstream\nabcde\nendstream\nendobj\n")
	if _, err := pdfStreamRanges(raw); err == nil {
		t.Error("a negative /Length was accepted")
	}
}

// TestCommentsBetweenReferenceTokens covers "/Length 7 % why\n0 R".
//
// The main loop treated comments as whitespace; the helper deciding whether an
// integer is an object number did not, so it read the 7 as a direct length. The
// same rule needed in two places, one of which had it -- which is the shape this
// package keeps paying for, and the reason the tokenizer now has exactly one
// trivia-skipping function.
func TestCommentsBetweenReferenceTokens(t *testing.T) {
	body := []byte("payload for the comment case\n")

	for _, tc := range []struct{ name, ref string }{
		{"comment after the object number", "2 % why\n0 R"},
		{"comment after the generation", "2 0 % why\nR"},
		{"comments in both gaps", "2 % a\n0 % b\nR"},
		{"no comments", "2 0 R"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildPDF(t,
				[]byte("<< /Length "+tc.ref+" >>\nstream\n"+string(body)+"endstream"),
				[]byte(fmt.Sprint(len(body))))
			ranges, err := pdfStreamRanges(raw)
			if err != nil {
				t.Fatalf("pdfStreamRanges rejected a valid file: %v", err)
			}
			if len(ranges) != 1 || ranges[0][1]-ranges[0][0] != len(body) {
				t.Errorf("ranges = %v, want one range of %d bytes -- the reference was read "+
					"as a direct length", ranges, len(body))
			}
		})
	}
}

// TestRetryResolvesThroughTheXrefNotThroughAGuess is round 4's fifth finding,
// and the one that is not an ordinary bug.
//
// The retry used the object index built by the forward pass. That pass
// RESYNCHRONISES at the first "endstream" it can find, so on a crafted file it
// resumes inside a payload and records whatever object headers are there, while
// an unmatched "(" hides the genuine definition further on. The retry then
// resolved the length from a decoy.
//
// The file already carries the authoritative answer -- its cross-reference table
// -- and every offset read from it is checked to actually carry that object's
// own header before it is believed.
func TestRetryResolvesThroughTheXrefNotThroughAGuess(t *testing.T) {
	// A payload with an early "endstream" (so resynchronisation lands inside
	// it), then a decoy for object 2, then an unmatched "(" to hide what
	// follows from a byte walker.
	payload := "AAAAA\nendstream\n2 0 obj\n5\nendobj\n( unmatched\nBBBBBBBBBBBBBBB\n"
	raw := buildPDF(t,
		[]byte("<< /Length 2 0 R >>\nstream\n"+payload+"endstream"),
		[]byte(fmt.Sprint(len(payload))))

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatalf("pdfStreamRanges: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("got %d ranges, want 1", len(ranges))
	}
	if got := ranges[0][1] - ranges[0][0]; got != len(payload) {
		t.Errorf("range covers %d bytes, want %d -- the length came from the decoy inside "+
			"the payload, so the tail is exposed to redactEngineIdentity", got, len(payload))
	}
	tail := bytes.Index(raw, []byte("BBBBBBBBBB"))
	if !inAnyRange(ranges, tail) {
		t.Errorf("the payload tail at %d is outside %v", tail, ranges)
	}
}

// TestXrefEntriesMustCarryTheObjectTheyName pins what makes the xref
// trustworthy: an entry pointing anywhere else is discarded, not believed.
func TestXrefEntriesMustCarryTheObjectTheyName(t *testing.T) {
	raw := buildPDF(t, []byte("<< /Type /X >>"), []byte("42"))

	objs := pdfXrefObjects(raw)
	if len(objs) != 2 {
		t.Fatalf("read %d objects from a two-object file", len(objs))
	}

	// Point object 2's entry at the middle of object 1 and it must be dropped.
	broken := bytes.Replace(raw, []byte("/Size 3"), []byte("/Size 3"), 1)
	at := bytes.Index(broken, []byte("xref\n0 3\n"))
	if at < 0 {
		t.Fatal("fixture has no xref table")
	}
	// Rewrite OBJECT 2's entry to point at offset 5, which is inside the
	// "%PDF-1.4" header. Lines are: xref / 0 3 / free entry / object 1 /
	// object 2, so the index is 4 -- the first version of this used 3 and
	// corrupted object 1 instead, which the assertion below does not look at.
	lines := bytes.SplitN(broken[at:], []byte("\n"), 6)
	lines[4] = []byte("0000000005 00000 n ")
	broken = append(append([]byte{}, broken[:at]...), bytes.Join(lines, []byte("\n"))...)

	if _, ok := pdfXrefObjects(broken)[2]; ok {
		t.Error("an xref entry pointing at bytes that are not object 2's header was believed")
	}
}

// TestContentTypeDeclarationsMustBeDirectChildrenOfTypes covers the OOXML half
// of round 4: <Types><Wrapper><Override .../></Wrapper></Types> parses cleanly
// and declares nothing, because a nested element is not a package content-type
// declaration.
func TestContentTypeDeclarationsMustBeDirectChildrenOfTypes(t *testing.T) {
	ns := `xmlns="http://schemas.openxmlformats.org/package/2006/content-types"`

	nested := []byte(`<?xml version="1.0"?><Types ` + ns + `>` +
		`<Wrapper><Override PartName="/word/document.xml" ContentType="application/xml"/></Wrapper>` +
		`</Types>`)
	if contentTypeDeclares(nested, "word/document.xml") {
		t.Error("an Override nested inside another element was read as a declaration")
	}

	foreign := []byte(`<?xml version="1.0"?><Types ` + ns + `>` +
		`<Override xmlns="urn:example:other" PartName="/word/document.xml" ContentType="application/xml"/>` +
		`</Types>`)
	if contentTypeDeclares(foreign, "word/document.xml") {
		t.Error("an Override from a foreign namespace was read as a declaration")
	}

	direct := []byte(`<?xml version="1.0"?><Types ` + ns + `>` +
		`<Override PartName="/word/document.xml" ContentType="application/xml"/>` +
		`</Types>`)
	if !contentTypeDeclares(direct, "word/document.xml") {
		t.Error("a direct child of Types in the right namespace was not recognised")
	}
}

// TestMainPartMustParseAndCarryItsRoot is the other OOXML finding: a zero-byte
// or malformed main part satisfied a filename comparison while carrying no
// document at all.
func TestMainPartMustParseAndCarryItsRoot(t *testing.T) {
	requireVerifierBinaries(t)

	ct := []byte(`<?xml version="1.0"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Override PartName="/word/document.xml" ContentType="application/xml"/>` +
		`</Types>`)

	for _, tc := range []struct {
		name string
		doc  []byte
		ok   bool
	}{
		{"zero bytes", []byte(""), false},
		{"not XML at all", []byte("this is not xml"), false},
		{"truncated XML", []byte(`<?xml version="1.0"?><w:document`), false},
		{"wrong root element", []byte(`<?xml version="1.0"?><workbook/>`), false},
		{"a document", []byte(`<?xml version="1.0"?><document/>`), true},
		{"a namespaced document", []byte(`<?xml version="1.0"?>` +
			`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>`), true},
		{"a STRICT-conformance document", []byte(`<?xml version="1.0"?>` +
			`<w:document xmlns:w="http://purl.oclc.org/ooxml/wordprocessingml/main"/>`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := buildOOXMLPackage(t, map[string][]byte{
				"[Content_Types].xml": ct,
				"word/document.xml":   tc.doc,
			})
			_, err := verifySanitized(context.Background(), engineExec{}, "docx", path)
			if tc.ok && err != nil {
				t.Errorf("a usable document was rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("a package with no usable document was verified")
			}
		})
	}
}
