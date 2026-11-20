package convert

import (
	"bytes"
	"context"
	"fmt"
	"testing"
)

// buildPDF assembles objects into a file WITH a real cross-reference table.
//
// The table is not decoration: an indirect /Length whose object is written after
// its stream is resolved through the xref, deliberately, because the alternative
// -- retrying with an index scavenged from a resynchronised walk -- reads decoys
// out of payloads. A fixture with "startxref 0" and no table is therefore not a
// smaller version of a real PDF; it is a file with no answer in it.
//
// objects[i] is the BODY of object i+1, without its "N 0 obj"/"endobj" wrapper.
func buildPDF(t *testing.T, objects ...[]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for n, body := range objects {
		offsets[n] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n", n+1)
		buf.Write(body)
		buf.WriteString("\nendobj\n")
	}
	xrefAt := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xrefAt)
	return buf.Bytes()
}

// Round 3 of PR #14 found three more defects in the byte-scanning walkers, all
// of them the same one: a token recognised by its bytes without regard to the
// lexical context it sits in. These tests are that context, one case per
// context, against the tokenizer that replaced the scanning.

// TestObjectHeadersAreNotReadOutOfComments is round 3's first finding.
//
// "% 7 0 obj 5" is a comment. The lexical index read it as a definition of
// object 7, so a stream whose real /Length was "7 0 R" resolved to 5 -- and if
// byte 5 happened to be followed by an in-payload "endstream", the short range
// was accepted and redactEngineIdentity was free to rewrite the rest.
//
// Note what makes this one worse than the in-payload decoy of round 1: a comment
// sits OUTSIDE any stream, so excluding payloads -- which is what round 1 and
// round 2 were both about -- does not touch it.
func TestObjectHeadersAreNotReadOutOfComments(t *testing.T) {
	payload := []byte("AAAAA\nendstream\nBBBBBBBBBBBBBBBBBBBB\n")

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	fmt.Fprintf(&buf, "7 0 obj\n%d\nendobj\n", len(payload))
	buf.WriteString("% 7 0 obj 5\n") // the decoy, in a comment, outside every stream
	buf.WriteString("1 0 obj\n<< /Length 7 0 R >>\nstream\n")
	buf.Write(payload)
	buf.WriteString("endstream\nendobj\n")
	buf.WriteString("trailer\n<< /Size 8 >>\nstartxref\n0\n%%EOF\n")
	raw := buf.Bytes()

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatalf("pdfStreamRanges: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("got %d ranges, want 1", len(ranges))
	}
	tail := bytes.Index(raw, []byte("BBBBBBBBBB"))
	if !inAnyRange(ranges, tail) {
		t.Errorf("the payload tail at %d is outside %v -- a commented-out object header "+
			"was read as a definition", tail, ranges)
	}
}

// TestStreamKeywordInsideACommentIsNotAStream is round 3's second finding, and
// it is a REJECTION of valid input rather than an acceptance of invalid input.
//
// "<< /Length 5 >> % stream\nstream\nabcde": the first "stream" is inside a
// comment. The backward-scanning walker skipped back over the comment, found the
// dictionary, and classified the commented word as the keyword -- then its
// length did not line up and the whole file was refused. verifySanitized gates every
// sanitize output and sanitizeFile deletes what it cannot verify, so this cost a
// client a valid file.
func TestStreamKeywordInsideACommentIsNotAStream(t *testing.T) {
	raw := []byte("%PDF-1.4\n1 0 obj\n<< /Length 5 >> % stream\nstream\nabcde\nendstream\nendobj\n" +
		"trailer\n<< /Size 2 >>\nstartxref\n0\n%%EOF\n")

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatalf("pdfStreamRanges rejected a valid file: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("got %d ranges, want 1", len(ranges))
	}
	at := bytes.Index(raw, []byte("abcde"))
	if ranges[0][0] != at || ranges[0][1] != at+5 {
		t.Errorf("range %v does not cover exactly the 5-byte payload at %d", ranges[0], at)
	}
	if _, err := pdfNonStreamBytes(raw); err != nil {
		t.Errorf("the verifier rejected the same valid file: %v", err)
	}
}

// TestDelimitersInsideStringsAreNotStructure is round 3's third finding.
//
// "<< /Note (>>) /Length 21 >>" is a valid dictionary carrying a literal string
// that happens to contain ">>". The backward walk counted that as a dictionary
// close, never found the matching "<<", and silently decided the stream was not
// structural -- leaving its payload unprotected while reporting no error at all.
// Silence is the worst of the three outcomes: nothing to see in the logs.
func TestDelimitersInsideStringsAreNotStructure(t *testing.T) {
	for _, tc := range []struct{ name, dict string }{
		{"literal string containing >>", `<< /Note (>>) /Length 21 >>`},
		{"literal string containing <<", `<< /Note (<<) /Length 21 >>`},
		{"escaped parenthesis", `<< /Note (a\) b) /Length 21 >>`},
		{"nested parentheses", `<< /Note (a (b) c) /Length 21 >>`},
		{"hex string containing >", `<< /Note <3E3E> /Length 21 >>`},
		{"string containing a percent", `<< /Note (100% sure) /Length 21 >>`},
		{"string containing the word stream", `<< /Note (stream) /Length 21 >>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "123456789012345678901" // exactly 21 bytes
			raw := []byte("%PDF-1.4\n1 0 obj\n" + tc.dict + "\nstream\n" + body +
				"\nendstream\nendobj\ntrailer\n<< /Size 2 >>\nstartxref\n0\n%%EOF\n")

			ranges, err := pdfStreamRanges(raw)
			if err != nil {
				t.Fatalf("pdfStreamRanges: %v", err)
			}
			if len(ranges) != 1 {
				t.Fatalf("got %d ranges, want 1 -- the stream was not recognised, so its "+
					"payload is unprotected and nothing said so", len(ranges))
			}
			at := bytes.Index(raw, []byte(body))
			if ranges[0][0] != at || ranges[0][1] != at+len(body) {
				t.Errorf("range %v does not cover exactly the payload at %d", ranges[0], at)
			}
		})
	}
}

// TestLengthObjectDefinedAfterItsStream covers what Ghostscript actually emits,
// which the tokenizer's first version could not read at all.
//
// gs writes "<</Length 6 0 R/Filter /FlateDecode>>" with object 6 AFTER the
// stream. A single forward pass cannot resolve that, so it must resynchronise
// past the payload -- and the first version resumed tokenizing INSIDE the binary
// payload instead, where one "(" swallowed the rest of the file as a literal
// string. The whole corpus stopped sanitizing.
func TestLengthObjectDefinedAfterItsStream(t *testing.T) {
	body := []byte("payload with a ( and a % and >> in it\n")

	raw := buildPDF(t,
		[]byte("<< /Length 2 0 R >>\nstream\n"+string(body)+"endstream"),
		[]byte(fmt.Sprint(len(body))))

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatalf("pdfStreamRanges: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("got %d ranges, want 1", len(ranges))
	}
	at := bytes.Index(raw, []byte("payload with a ("))
	if ranges[0][0] != at || ranges[0][1] != at+len(body) {
		t.Errorf("range %v does not cover exactly the payload at %d", ranges[0], at)
	}
}

// TestSanitizerAndVerifierSeeTheSameStreams is what
// TestStreamRangesAgreeWithTheVerifier became once the two stopped carrying
// their own walkers.
//
// It no longer detects a divergence between two implementations, because there
// is one. It now guards against a future change reintroducing a second: if
// either side grows its own boundary logic, this fails.
func TestSanitizerAndVerifierSeeTheSameStreams(t *testing.T) {
	requireGhostscript(t)

	raw := []byte("%PDF-1.4\n1 0 obj\n<< /Note (>>) /Length 5 >>\nstream\nabcde\nendstream\nendobj\n" +
		"trailer\n<< /Size 2 >>\nstartxref\n0\n%%EOF\n")

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatal(err)
	}
	blanked, err := pdfNonStreamBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(blanked) != len(raw) {
		t.Fatalf("blanking changed the length (%d -> %d)", len(raw), len(blanked))
	}
	for _, r := range ranges {
		for i := r[0]; i < r[1]; i++ {
			if blanked[i] != ' ' {
				t.Fatalf("byte %d is inside a stream range the redaction protects but the "+
					"verifier did not blank; the two have separate boundary logic again", i)
			}
		}
	}
	for i := range raw {
		if !inAnyRange(ranges, i) && blanked[i] != raw[i] {
			t.Fatalf("byte %d is outside every stream range but the verifier blanked it", i)
		}
	}
}

// TestUnresolvableLengthStillFailsClosed re-pins D-07 against the tokenizer. The
// resynchronisation added for Ghostscript's forward-referenced lengths is a
// guess used to keep READING; it must never become a guess used to ANSWER.
func TestUnresolvableLengthStillFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"no /Length at all", "%PDF-1.4\n1 0 obj\n<< /Type /X >>\nstream\nabc\nendstream\nendobj\n"},
		{"indirect /Length naming a missing object", "%PDF-1.4\n1 0 obj\n<< /Length 9 0 R >>\nstream\nabc\nendstream\nendobj\n"},
		{"declared length its bytes disagree with", "%PDF-1.4\n1 0 obj\n<< /Length 999 >>\nstream\nabc\nendstream\nendobj\n"},
		{"/Length is a name", "%PDF-1.4\n1 0 obj\n<< /Length /Nope >>\nstream\nabc\nendstream\nendobj\n"},
		{"/Length object is a name", "%PDF-1.4\n1 0 obj\n<< /Length 9 0 R >>\nstream\nabc\nendstream\nendobj\n9 0 obj\n/Nope\nendobj\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pdfStreamRanges([]byte(tc.raw)); err == nil {
				t.Error("the sanitizer accepted it")
			}
			if _, err := pdfNonStreamBytes([]byte(tc.raw)); err == nil {
				t.Error("the verifier accepted it")
			}
		})
	}
}

// TestContentTypesMustParseToTheEnd is round 3's fourth finding, and the only
// one not about PDF.
//
// contentTypeDeclares returned true the moment it saw a matching declaration,
// so a truncated [Content_Types].xml -- a matching Override and then no closing
// tag -- was accepted, because the decoder had not yet reached the error.
// verifyOOXML's own check looks at the first start element only, so nothing else
// caught it either, and verifySanitized reported a malformed package as verified.
func TestContentTypesMustParseToTheEnd(t *testing.T) {
	good := `<?xml version="1.0"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Override PartName="/word/document.xml" ContentType="application/xml"/>` +
		`</Types>`
	if !contentTypeDeclares([]byte(good), "word/document.xml") {
		t.Fatal("a well-formed declaration was rejected; the rest of this test proves nothing")
	}

	for _, tc := range []struct{ name, xml string }{
		{
			name: "no closing Types element",
			xml: `<?xml version="1.0"?>` +
				`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
				`<Override PartName="/word/document.xml" ContentType="application/xml"/>`,
		},
		{
			name: "truncated mid-element after the match",
			xml: `<?xml version="1.0"?>` +
				`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
				`<Override PartName="/word/document.xml" ContentType="application/xml"/>` +
				`<Override PartName="/word/sty`,
		},
		{
			name: "mismatched closing tag after the match",
			xml: `<?xml version="1.0"?>` +
				`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
				`<Override PartName="/word/document.xml" ContentType="application/xml"/>` +
				`</Wrong>`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if contentTypeDeclares([]byte(tc.xml), "word/document.xml") {
				t.Error("a malformed [Content_Types].xml was accepted as a declaration; " +
					"the package it describes cannot be opened")
			}
		})
	}
}

// TestMalformedContentTypesFailsVerification drives the same case through the
// public entry point, because every assertion above calls an unexported
// function and would keep passing if the wiring broke.
func TestMalformedContentTypesFailsVerification(t *testing.T) {
	requireVerifierBinaries(t)

	path := buildOOXMLPackage(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Override PartName="/word/document.xml" ContentType="application/xml"/>`),
		"word/document.xml": []byte(`<?xml version="1.0"?><document/>`),
	})
	if _, err := verifySanitized(context.Background(), engineExec{}, "docx", path); err == nil {
		t.Error("a package whose [Content_Types].xml does not parse to the end was verified")
	}
}
