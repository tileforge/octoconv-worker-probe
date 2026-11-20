package convert

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestStreamRangeCoversAPayloadContainingEndstream is SANI-08 for the
// redaction side.
//
// endstream_in_stream.pdf's one stream carries the literal bytes "endstream"
// in its payload. The substring scan this replaced returned [274 337] for a
// payload that runs to 400, so redactEngineIdentity's protected range stopped
// 63 bytes early and it was free to rewrite the rest of a stream in place --
// preserving every xref offset while destroying what they point at, which is
// the worst available shape of corruption because nothing structural looks
// wrong.
func TestStreamRangeCoversAPayloadContainingEndstream(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(sanitizeCorpusDir, "endstream_in_stream.pdf"))
	if err != nil {
		t.Fatal(err)
	}

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatalf("pdfStreamRanges: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("got %d stream ranges, want exactly 1", len(ranges))
	}

	// Every byte of the payload, including everything past the decoy.
	for _, probe := range []string{
		"binary-ish payload with endstream inside it",
		"and startxref",
		"%%EOF too",
	} {
		at := bytes.Index(raw, []byte(probe))
		if at < 0 {
			t.Fatalf("fixture no longer contains %q", probe)
		}
		if !inAnyRange(ranges, at) {
			t.Errorf("%q at offset %d is outside the protected range %v -- the redaction "+
				"may rewrite bytes inside a stream", probe, at, ranges[0])
		}
	}

	// And the range must END at the payload, not run on into the file. A range
	// that covered everything would pass every assertion above and switch the
	// redaction off entirely.
	realTrailer := bytes.LastIndex(raw, []byte("startxref"))
	if inAnyRange(ranges, realTrailer) {
		t.Errorf("the file's real trailer at %d is inside the stream range %v -- the "+
			"range did not end, so nothing is redacted at all", realTrailer, ranges[0])
	}
}

// TestBlankingKeepsStructureAndRemovesPayload is SANI-08 for the verifier side,
// and it is the assertion that would have caught the inversion this fixture
// exposed: before the fix the payload's own "startxref" and "%%EOF" SURVIVED
// blanking while the file's real trailer was blanked to spaces. The revision
// count then read 1 and 1 and passed -- by reading the payload as structure and
// the structure as payload, two errors whose totals agree with the right
// answer.
func TestBlankingKeepsStructureAndRemovesPayload(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(sanitizeCorpusDir, "endstream_in_stream.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	outside, err := pdfNonStreamBytes(raw)
	if err != nil {
		t.Fatalf("pdfNonStreamBytes: %v", err)
	}
	if len(outside) != len(raw) {
		t.Fatalf("blanking changed the length (%d -> %d); every reported offset now lies",
			len(raw), len(outside))
	}

	payloadAt := bytes.Index(raw, []byte("and startxref"))
	realAt := bytes.LastIndex(raw, []byte("startxref"))
	if payloadAt < 0 || realAt <= payloadAt {
		t.Fatal("fixture no longer has a payload marker followed by a real one")
	}

	if bytes.Contains(outside[payloadAt:payloadAt+30], []byte("startxref")) {
		t.Error("the payload's startxref survived blanking; it will be counted as a revision")
	}
	if !bytes.Contains(outside[realAt:realAt+9], []byte("startxref")) {
		t.Error("the file's REAL startxref was blanked; the revision count now sees " +
			"structure where there is payload and payload where there is structure")
	}

	if got := bytes.Count(outside, []byte("startxref")); got != 1 {
		t.Errorf("startxref count = %d, want 1", got)
	}
	if got := bytes.Count(outside, []byte("%%EOF")); got != 1 {
		t.Errorf("%%%%EOF count = %d, want 1", got)
	}
}

// TestStreamKeywordIsStructuralNotLexical pins the defect underneath the
// reported one: "stream" is a substring of "endstream", so a lexical search
// re-enters on the tail of the keyword it just consumed and treats whatever
// follows as a new stream. On the corpus fixture that made the file's real
// trailer look like payload.
//
// A stream keyword is only a stream keyword when it follows the ">>" that
// closes its own dictionary.
func TestStreamKeywordIsStructuralNotLexical(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(sanitizeCorpusDir, "endstream_in_stream.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	// Three lexical hits, one real stream: two are the tails of "endstream"
	// (the decoy in the payload and the real terminator).
	lexical := bytes.Count(raw, []byte("stream"))
	if lexical < 3 {
		t.Fatalf("fixture has %d lexical 'stream' hits, want at least 3", lexical)
	}
	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 1 {
		t.Errorf("%d lexical hits produced %d stream ranges, want 1", lexical, len(ranges))
	}
}

// TestStreamLengthResolvesAnIndirectReference covers the path Ghostscript does
// not exercise.
//
// MEASURED FIRST: across this project's corpus, gs emits only DIRECT /Length
// values (4 streams over two files, 4 direct, 0 indirect). An indirect length
// is nonetheless legal and another gs build may well write one, so the resolver
// exists and is tested here against a hand-built file -- "the build we happened
// to measure" is not a property to depend on.
func TestStreamLengthResolvesAnIndirectReference(t *testing.T) {
	body := []byte("payload that mentions endstream and startxref\n")
	// Built with a real cross-reference table: a forward-referenced /Length is
	// resolved through the xref, so a fixture without one has no answer in it.
	raw := buildPDF(t,
		[]byte("<< /Length 2 0 R >>\nstream\n"+string(body)+"endstream"),
		[]byte(fmt.Sprint(len(body))))

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatalf("pdfStreamRanges could not resolve an indirect /Length: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("got %d ranges, want 1", len(ranges))
	}
	// LastIndex, not Index: the payload deliberately contains "startxref" too,
	// and looking for the first one finds the decoy inside the stream -- which
	// is exactly the confusion this whole derivation exists to remove.
	at := bytes.LastIndex(raw, []byte("startxref\n"))
	if !inAnyRange(ranges, bytes.Index(raw, []byte("payload that mentions"))) {
		t.Error("the resolved range does not cover the payload")
	}
	if inAnyRange(ranges, at) {
		t.Error("the resolved range swallowed the trailer")
	}

	outside, err := pdfNonStreamBytes(raw)
	if err != nil {
		t.Fatalf("pdfNonStreamBytes could not resolve an indirect /Length: %v", err)
	}
	if got := bytes.Count(outside, []byte("startxref")); got != 1 {
		t.Errorf("the verifier's own resolver disagrees: startxref count = %d, want 1", got)
	}
}

// TestUnresolvableLengthFailsClosed is D-07 for this derivation. A silent
// fallback to the substring scan would put the defect back exactly where it
// was and hide it behind a passing test.
func TestUnresolvableLengthFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "no /Length at all",
			raw:  "%PDF-1.4\n1 0 obj\n<< /Type /X >>\nstream\nabc\nendstream\nendobj\n",
		},
		{
			name: "indirect /Length naming an object that is not in the file",
			raw:  "%PDF-1.4\n1 0 obj\n<< /Length 9 0 R >>\nstream\nabc\nendstream\nendobj\n",
		},
		{
			name: "declared length its own bytes disagree with",
			raw:  "%PDF-1.4\n1 0 obj\n<< /Length 999 >>\nstream\nabc\nendstream\nendobj\n",
		},
		{
			name: "/Length is not a number",
			raw:  "%PDF-1.4\n1 0 obj\n<< /Length /Nope >>\nstream\nabc\nendstream\nendobj\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pdfStreamRanges([]byte(tc.raw)); err == nil {
				t.Error("pdfStreamRanges accepted it; an unresolvable length must fail closed")
			}
			if _, err := pdfNonStreamBytes([]byte(tc.raw)); err == nil {
				t.Error("pdfNonStreamBytes accepted it; an unresolvable length must fail closed")
			}
		})
	}
}

// TestLengthIsMatchedAsATokenNotAPrefix pins what a real corpus file found on
// the first run of this derivation.
//
// Type1 font streams carry /Length1, /Length2 and /Length3 alongside /Length.
// A prefix match on "/Length" reads the "1" of the KEY as the value, and
// embedded_font.pdf failed with "declares /Length 1 but no endstream follows
// it". A name is a token, not a prefix -- which is the same sentence this phase
// is writing three times over in other places.
func TestLengthIsMatchedAsATokenNotAPrefix(t *testing.T) {
	body := []byte("font program bytes\n")
	raw := []byte("%PDF-1.4\n1 0 obj\n<< /Length1 1 /Length2 2 /Length " +
		fmt.Sprint(len(body)) + " >>\nstream\n" + string(body) + "endstream\nendobj\n")

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatalf("pdfStreamRanges read a /Length1 as the stream's /Length: %v", err)
	}
	if len(ranges) != 1 || ranges[0][1]-ranges[0][0] != len(body) {
		t.Errorf("ranges = %v, want one range of %d bytes", ranges, len(body))
	}
	if _, err := pdfNonStreamBytes(raw); err != nil {
		t.Errorf("the verifier read a /Length1 as the stream's /Length: %v", err)
	}
}

// TestLengthInASubDictionaryIsNotTheStreamsOwn covers the other way a nearby
// key can be mistaken for this one: /DecodeParms is a dictionary and may carry
// its own numeric entries.
func TestLengthInASubDictionaryIsNotTheStreamsOwn(t *testing.T) {
	body := []byte("0123456789")
	raw := []byte("%PDF-1.4\n1 0 obj\n<< /DecodeParms << /Length 3 >> /Length " +
		fmt.Sprint(len(body)) + " >>\nstream\n" + string(body) + "\nendstream\nendobj\n")

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatalf("pdfStreamRanges: %v", err)
	}
	if len(ranges) != 1 || ranges[0][1]-ranges[0][0] != len(body) {
		t.Errorf("ranges = %v, want one range of %d bytes -- a nested /Length was used",
			ranges, len(body))
	}
}
