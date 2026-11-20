package convert

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireGhostscript skips the calling test unless gs is on PATH, mirroring
// requireOCRPDFBinaries.
//
// A skipped test is NOT a passed test. OCTOCONV_REQUIRE_BINS=1 turns the skip
// into a failure, so the phase gate can run in a mode where a missing engine
// is a red result rather than a quiet one -- the same distinction Phase 59
// drew for its own real-binary suites.
func requireGhostscript(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("gs"); err != nil {
		if os.Getenv("OCTOCONV_REQUIRE_BINS") == "1" {
			t.Fatalf("gs not on PATH and OCTOCONV_REQUIRE_BINS=1: a skipped test is not a passed test")
		}
		t.Skipf("gs not found on PATH, skipping real-binary test")
	}
}

// requirePdfinfo is requireGhostscript's sibling for poppler's pdfinfo, which
// the probe page ceiling counts with (probebounds.go). Same convention,
// including OCTOCONV_REQUIRE_BINS=1 turning the skip into a failure.
//
// It exists because the page-ceiling tests were written without one and FAILED
// rather than skipped on a checkout without poppler -- and failed confusingly,
// since a missing binary is now classified as "engine binary is not available"
// rather than as a page-count result. Found in review (PR #15 round 7).
func requirePdfinfo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pdfinfo"); err != nil {
		if os.Getenv("OCTOCONV_REQUIRE_BINS") == "1" {
			t.Fatalf("pdfinfo not on PATH and OCTOCONV_REQUIRE_BINS=1: a skipped test is not a passed test")
		}
		t.Skipf("pdfinfo not found on PATH, skipping real-binary test")
	}
}

func requirePdftotext(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pdftotext"); err != nil {
		if os.Getenv("OCTOCONV_REQUIRE_BINS") == "1" {
			t.Fatalf("pdftotext not on PATH and OCTOCONV_REQUIRE_BINS=1")
		}
		t.Skipf("pdftotext not found on PATH, skipping real-binary test")
	}
}

const sanitizeCorpusDir = "testdata/sanitize"

// sanitizeThreatMarkers is the closed list of byte sequences that must not
// survive into a sanitized PDF.
//
// Checked against the OUTPUT BYTES rather than through a parser: SANI-04 says
// "physically absent", and a parser reads the file the way a reader does --
// by the last xref -- so it would not see a construct left behind in a
// superseded revision. The parse-based check is Plan 60-04's job; this one is
// deliberately dumber and blind in a different direction.
var sanitizeThreatMarkers = []string{
	"/OpenAction",
	"/AA",
	"/Launch",
	"/URI",
	"evil.example",
	"JavaScript",
	"EmbeddedFile",
	"Secret Internal Title",
	"jane.doe@corp.example",
	"xpacket",
}

func nonWhitespaceCount(t *testing.T, pdfPath string) int {
	t.Helper()
	out, err := exec.Command("pdftotext", pdfPath, "-").Output()
	if err != nil {
		t.Fatalf("pdftotext %s: %v", pdfPath, err)
	}
	n := 0
	for _, r := range string(out) {
		if !isSpaceRune(r) {
			n++
		}
	}
	return n
}

func isSpaceRune(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\v', '\f', 0x85, 0xA0:
		return true
	}
	return false
}

// TestSanitizePDFRemovesEveryThreatMarker is the direct SANI-01/SANI-03 proof:
// every marker the corpus fixture carries is absent from the sanitized output
// bytes, and the body text is still there.
func TestSanitizePDFRemovesEveryThreatMarker(t *testing.T) {
	requireGhostscript(t)

	in := filepath.Join(sanitizeCorpusDir, "threat_all_classes.pdf")
	raw, err := os.ReadFile(in)
	if err != nil {
		t.Fatalf("read fixture: %v -- the corpus is committed by Plan 60-01 and must exist before this suite runs", err)
	}

	// The fixture must actually carry the threats, or this test proves
	// nothing. A corpus regenerated wrong would otherwise make every
	// assertion below pass on an empty subject.
	for _, m := range []string{"/OpenAction", "JavaScript", "EmbeddedFile", "evil.example"} {
		if !bytes.Contains(raw, []byte(m)) {
			t.Fatalf("fixture does not contain %q -- regenerate with scripts/sanitize-corpus.py", m)
		}
	}

	out := filepath.Join(t.TempDir(), "clean.pdf")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := sanitizeFile(ctx, engineExec{}, "pdf", in, out)
	if err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	for _, m := range sanitizeThreatMarkers {
		if bytes.Contains(got, []byte(m)) {
			t.Errorf("marker %q survived into the sanitized output", m)
		}
	}

	if len(res.Removed) == 0 {
		t.Error("Removed is empty")
	}
	for _, c := range res.Removed {
		if !IsKnownThreatClass(c) {
			t.Errorf("Removed contains unknown class %q", c)
		}
		// Reporting an OOXML-only class as removed from a PDF would be a
		// false claim about a construct that cannot exist in the format.
		if c == ThreatVBAMacro || c == ThreatOLEObject {
			t.Errorf("Removed contains %q, which cannot occur in a PDF", c)
		}
	}
	if len(res.LostCapabilities) == 0 {
		t.Error("LostCapabilities is empty -- the PostScript round trip destroys forms and bookmarks, and D-02 requires saying so")
	}
}

// TestSanitizePDFPreservesText pins content survival against the references
// Phase 59 established INDEPENDENTLY of this phase (that corpus's own
// PROVENANCE.md), so the expectation cannot drift toward whatever today's
// code happens to produce.
func TestSanitizePDFPreservesText(t *testing.T) {
	requireGhostscript(t)
	requirePdftotext(t)

	cases := []struct {
		path string
		want int
	}{
		{filepath.Join("..", "inspect", "testdata", "pdf", "embedded_font.pdf"), 42},
		{filepath.Join("..", "inspect", "testdata", "pdf", "objstm_born_digital.pdf"), 82},
	}

	for _, tc := range cases {
		t.Run(filepath.Base(tc.path), func(t *testing.T) {
			if before := nonWhitespaceCount(t, tc.path); before != tc.want {
				t.Fatalf("fixture reference moved: got %d, want %d -- Phase 59's PROVENANCE.md is the source of this number", before, tc.want)
			}
			out := filepath.Join(t.TempDir(), "clean.pdf")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if _, err := sanitizeFile(ctx, engineExec{}, "pdf", tc.path, out); err != nil {
				t.Fatalf("sanitizeFile: %v", err)
			}
			if after := nonWhitespaceCount(t, out); after != tc.want {
				t.Errorf("text after sanitization = %d non-whitespace chars, want %d", after, tc.want)
			}
		})
	}
}

// TestSanitizePDFOutputIsASingleRevision is SC3's prior-revision clause.
//
// Absence is not the requirement; UNRECOVERABILITY is. A PDF written as an
// incremental update keeps its previous revision in the file, so every marker
// assertion above could pass while the construct sits one xref back, readable
// by anything that walks the revision chain instead of the current table.
//
// The two-step round trip gives a single revision by construction -- ps2write
// destroys PDF structure entirely, so there is nothing to append to. "By
// construction" is exactly the kind of promise Phase 59 found untrue in a
// comment, so it is measured.
//
// The multi-revision INPUT case is the one that distinguishes the two
// behaviours: on a single-revision input, rewriting and appending produce
// files that look alike.
func TestSanitizePDFOutputIsASingleRevision(t *testing.T) {
	requireGhostscript(t)

	base, err := os.ReadFile(filepath.Join(sanitizeCorpusDir, "threat_all_classes.pdf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	incremental := buildIncrementalUpdate(t, base)

	dir := t.TempDir()
	twoRev := filepath.Join(dir, "two-revisions.pdf")
	if err := os.WriteFile(twoRev, incremental, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(incremental, []byte("%%EOF")); got != 2 {
		t.Fatalf("input fixture has %d %%%%EOF markers, want 2 -- the multi-revision input is the whole point of this case", got)
	}

	for _, tc := range []struct{ name, path string }{
		{"single_revision_input", filepath.Join(sanitizeCorpusDir, "threat_all_classes.pdf")},
		{"multi_revision_input", twoRev},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "clean.pdf")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if _, err := sanitizeFile(ctx, engineExec{}, "pdf", tc.path, out); err != nil {
				t.Fatalf("sanitizeFile: %v", err)
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if n := bytes.Count(got, []byte("startxref")); n != 1 {
				t.Errorf("output has %d startxref markers, want exactly 1 (SC3: no prior revision may survive)", n)
			}
			if n := bytes.Count(got, []byte("%%EOF")); n != 1 {
				t.Errorf("output has %d %%%%EOF markers, want exactly 1 (SC3)", n)
			}
			if bytes.Contains(got, []byte(incrementalRevisionPayload)) {
				t.Error("the second revision's payload survived sanitization")
			}
		})
	}
}

// TestSinglePassPdfwriteLeavesThreatsBehind does NOT test our code. It tests
// the claim our pipeline's shape rests on.
//
// It runs the fixture through ONE pdfwrite pass -- the obvious, better-reading
// form this file's header argues against -- and requires that markers SURVIVE.
// It catches two things nothing else does:
//
//   - a future simplification to a single pass. The removal test would go red
//     too, but with a confusing message about markers; this one goes red with
//     an unambiguous one about the reason there are two passes.
//   - a change in ghostscript's own behaviour. If a future version strips
//     everything in one pass, THIS test fails alone, and the correct response
//     is to re-examine the two-step justification -- not to conclude our code
//     broke.
func TestSinglePassPdfwriteLeavesThreatsBehind(t *testing.T) {
	requireGhostscript(t)

	in := filepath.Join(sanitizeCorpusDir, "threat_all_classes.pdf")
	out := filepath.Join(t.TempDir(), "one-pass.pdf")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := runCommand(ctx, "gs",
		"-q", "-dNOPAUSE", "-dBATCH", "-dSAFER",
		"-sDEVICE=pdfwrite", "-sOutputFile="+out, in); err != nil {
		t.Fatalf("one-pass gs: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	// Measured on gs 10.07.1; see sanitizepdf.go's header table and the
	// corpus PROVENANCE.md for the full set of counts.
	survivors := []string{"JavaScript", "EmbeddedFile", "Secret Internal Title", "jane.doe@corp.example"}
	var missing []string
	for _, m := range survivors {
		if !bytes.Contains(got, []byte(m)) {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		t.Errorf("a single pdfwrite pass no longer leaves %s behind.\n"+
			"This test asserts the MEASUREMENT the two-step pipeline is justified by, not our own code. "+
			"If ghostscript's behaviour changed, re-examine sanitizepdf.go's header table and 60-RESEARCH.md R1 "+
			"before concluding anything is broken.", strings.Join(missing, ", "))
	}

	// The sharpest row of the table: a single pass MANUFACTURES an XMP packet
	// the input never had, carrying the metadata it was invoked to remove.
	if !bytes.Contains(got, []byte("xpacket")) {
		t.Error("a single pdfwrite pass no longer creates an XMP packet -- re-examine the D-09 justification for -dOmitXMP")
	}
}

// incrementalRevisionPayload is the marker carried only by the SECOND revision
// of the fixture buildIncrementalUpdate produces.
const incrementalRevisionPayload = "second revision payload"

// buildIncrementalUpdate appends a genuine, well-formed second revision to a
// PDF: a new JavaScript action object, a REPLACEMENT catalog (object 1) that
// points at it, a cross-reference section listing both, and a trailer whose
// /Prev chains back to the original xref.
//
// The validity is the point, and it was not free. A first attempt appended a
// malformed revision with a bogus `startxref 0`. The test passed -- but a
// probe showed ghostscript never read the appended revision at all: it
// repaired the file from the original xref and produced an intermediate
// byte-identical in size to the base fixture's. The case was green while
// exercising nothing, which is the failure mode this whole phase is built to
// prevent, appearing in the phase's own test.
//
// With the /Prev chain correct, a single pdfwrite pass carries this payload
// into its output -- verified directly -- so the input is now genuinely a
// two-revision document that ghostscript resolves, and "our output has one
// revision" is a statement about a file that actually had two.
func buildIncrementalUpdate(t *testing.T, base []byte) []byte {
	t.Helper()

	// The base file's own startxref offset, which revision 2's /Prev chains to.
	idx := bytes.LastIndex(base, []byte("startxref"))
	if idx < 0 {
		t.Fatalf("base fixture has no startxref")
	}
	var prev int
	tail := strings.TrimSpace(string(base[idx+len("startxref"):]))
	if _, err := fmt.Sscanf(tail, "%d", &prev); err != nil {
		t.Fatalf("parse base startxref from %q: %v", tail, err)
	}

	var body bytes.Buffer
	body.WriteByte('\n')

	off14 := len(base) + body.Len()
	fmt.Fprintf(&body, "14 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('%s')) >>\nendobj\n",
		incrementalRevisionPayload)

	off1 := len(base) + body.Len()
	body.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 14 0 R\n" +
		"   /Names << /JavaScript << /Names [(rev2) 14 0 R] >> >> >>\nendobj\n")

	xrefOff := len(base) + body.Len()
	fmt.Fprintf(&body, "xref\n1 1\n%010d 00000 n \n14 1\n%010d 00000 n \n", off1, off14)
	fmt.Fprintf(&body, "trailer\n<< /Size 15 /Root 1 0 R /Info 13 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
		prev, xrefOff)

	return append(append([]byte(nil), base...), body.Bytes()...)
}

// TestClassifyGSFailureKeepsTimeoutsTransient pins the one distinction that
// makes the malformed-input sentinel safe to act on.
//
// Every ghostscript failure except a timeout is deterministic on the input and
// must be terminal. A timeout is about load, and marking it terminal would
// fail a perfectly good document because the box was busy. The two are told
// apart here and nowhere else, so a test that builds the error by hand -- as
// the worker's classification test does -- would not notice this function
// getting it wrong.
func TestClassifyGSFailureKeepsTimeoutsTransient(t *testing.T) {
	timeout := classifyEngineFailure("pdfwrite pass", fmt.Errorf("gs killed: %w", context.DeadlineExceeded))
	if errors.Is(timeout, ErrSanitizeMalformedInput) {
		t.Error("a ghostscript TIMEOUT was classified as malformed input; the job would be " +
			"failed terminally because the machine was busy")
	}
	if !errors.Is(timeout, context.DeadlineExceeded) {
		t.Error("the deadline was lost from the error chain, so nothing downstream can see it " +
			"was a timeout")
	}

	// CANCELLATION, which the first version of this function destroyed. A job
	// cancelled by the client kills ghostscript, and the error wraps
	// context.Canceled; classifying that as malformed input made the runner's
	// isCanceled check stop recognising it, so a cancelled job was MarkFailed
	// as a bad upload. The previous inversion pass missed this because no test
	// covered it -- the same gap, one round later, in the same function.
	canceled := classifyEngineFailure("ps2write pass", fmt.Errorf("gs killed: %w", context.Canceled))
	if errors.Is(canceled, ErrSanitizeMalformedInput) {
		t.Error("a CANCELLED ghostscript run was classified as malformed input; the runner " +
			"would MarkFailed a job the client had already cancelled")
	}
	if !errors.Is(canceled, context.Canceled) {
		t.Error("the cancellation was lost from the error chain, so isCanceled cannot see it")
	}

	parse := classifyEngineFailure("ps2write pass", fmt.Errorf("gs failed: exit status 1: %s",
		"Error: /undefined in --get--"))
	if !errors.Is(parse, ErrSanitizeMalformedInput) {
		t.Errorf("a ghostscript PARSE failure was not classified as malformed input: %v -- the "+
			"worker treats it as transient, exhausts its retries without MarkFailed, and leaves "+
			"the job active", parse)
	}
	if errors.Is(parse, context.DeadlineExceeded) {
		t.Error("a parse failure carries a deadline it never had")
	}
}

// TestRedactionSkipsStreamPayloads is the regression proof for the
// twenty-first finding of PR #12.
//
// redactEngineIdentity searches the whole file for "/Producer(", "/Creator("
// and "%%Invocation:". Compressed page and image data can contain those bytes
// by chance, and the redaction is LENGTH-PRESERVING -- so rewriting them
// inside a stream keeps every xref offset valid while destroying the stream
// they point at. That is the worst available shape of corruption, because
// nothing structural looks wrong afterwards and the verifier's object walk
// does not decode every page stream.
//
// The test asserts both directions, since scoping a search and switching it
// off are indistinguishable from one side.
func TestRedactionSkipsStreamPayloads(t *testing.T) {
	requireGhostscript(t)

	out := filepath.Join(t.TempDir(), "out.pdf")
	if _, err := sanitizeFile(context.Background(), engineExec{}, "pdf",
		filepath.Join(sanitizeCorpusDir, "threat_all_classes.pdf"), out); err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	ranges, err := pdfStreamRanges(raw)
	if err != nil {
		t.Fatalf("pdfStreamRanges: %v", err)
	}
	if len(ranges) == 0 {
		t.Fatal("the sanitized fixture has no streams; this test proves nothing")
	}
	payload := []byte("/Producer(compressed-bytes-that-look-like-metadata)")
	at := ranges[0][0]
	if at+len(payload) >= ranges[0][1] {
		t.Skip("first stream is too short to splice into")
	}
	spliced := append([]byte(nil), raw...)
	copy(spliced[at:], payload)

	redacted, err := redactEngineIdentity(spliced)
	if err != nil {
		t.Fatalf("redactEngineIdentity: %v", err)
	}

	if len(redacted) != len(spliced) {
		t.Fatalf("the redaction changed the file length (%d -> %d); every xref offset after "+
			"the edit is now wrong", len(spliced), len(redacted))
	}
	if !bytes.Equal(redacted[ranges[0][0]:ranges[0][1]], spliced[ranges[0][0]:ranges[0][1]]) {
		t.Error("the redaction rewrote bytes inside a stream payload; the offsets still line up " +
			"and the stream they point at is destroyed")
	}

	// The real /Info must still be emptied, or the scoping disabled the
	// redaction rather than narrowing it.
	if bytes.Contains(redacted, []byte("Ghostscript")) {
		t.Error("the engine signature survived outside the streams -- the scoping switched the " +
			"redaction off instead of narrowing it")
	}
}

func TestReadJobFileLimitedStopsBeforeTheBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pdf")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'a'}, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readJobFileLimited(context.Background(), path, 10); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("over the ceiling: %v", err)
	}
	got, err := readJobFileLimited(context.Background(), path, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 100 {
		t.Fatalf("len %d", len(got))
	}
}
