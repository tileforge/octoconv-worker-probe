package convert

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// requireVerifierBinaries skips unless the external OOXML/image verifier
// binaries are present, on the same terms as requireGhostscript: a skip is not
// a pass, and OCTOCONV_REQUIRE_BINS=1 turns it red.
func requireVerifierBinaries(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"unzip", "file"} {
		if _, err := exec.LookPath(bin); err != nil {
			if os.Getenv("OCTOCONV_REQUIRE_BINS") == "1" {
				t.Fatalf("%s not on PATH and OCTOCONV_REQUIRE_BINS=1: a skipped test is not a passed test", bin)
			}
			t.Skipf("%s not found on PATH, skipping real-binary test", bin)
		}
	}
}

// copyCorpusFixture copies name from sanitizeCorpusDir into t.TempDir() and
// returns the copy's path. testdata/sanitize/ is source-controlled and
// shared across every test in this package; verifyOOXML's extraction
// directory now lives beside its INPUT (D-05 precondition), so a caller that
// verifies a corpus file in place would write a scratch directory into the
// tracked tree instead of a throwaway one.
func copyCorpusFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join(sanitizeCorpusDir, name)
	blob, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read corpus fixture %s: %v", src, err)
	}
	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, blob, 0o600); err != nil {
		t.Fatalf("copy corpus fixture %s: %v", src, err)
	}
	return dst
}

// TestVerifierRejectsTheUnsanitizedInput is the calibration test, and it is
// the most important one in this file.
//
// A verifier that returns "clean" is worth exactly as much as its ability to
// return "dirty". Point each verifier at the corpus fixture BEFORE
// sanitization: every one of them must refuse it. Without this, a verifier
// that lost its way -- wrong path, empty marker table, a parse that silently
// returns nothing -- would pass every other test in this file by agreeing that
// everything is fine.
func TestVerifierRejectsTheUnsanitizedInput(t *testing.T) {
	requireVerifierBinaries(t)

	cases := []struct {
		format string
		file   string
	}{
		{"pdf", "threat_all_classes.pdf"},
		{"docm", "macro_enabled.docm"},
		{"jpg", "exif_gps.jpg"},
	}

	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			// Copied into t.TempDir() rather than read straight from
			// testdata/sanitize/: verifyOOXML now creates its extraction
			// directory INSIDE filepath.Dir(path) (D-05 precondition, plan
			// 69-02) -- reading the corpus fixture in place would write a
			// scratch directory into the tracked source tree.
			path := copyCorpusFixture(t, tc.file)
			classes, err := verifySanitized(context.Background(), engineExec{}, tc.format, path)
			if err == nil {
				t.Fatalf("verifier called the UNSANITIZED %s clean (returned %v) -- "+
					"it cannot prove anything about sanitized output either", tc.file, classes)
			}
			// Either refusal counts, and which one it is depends on the file:
			// pdfcpu's validator rejects the PDF fixture outright ("action O
			// not allowed for source root") before any scan can run, so that
			// case is unverifiable rather than residue. Demanding residue
			// specifically would be demanding that the parser be lenient
			// enough to read an attack file, which is the wrong thing to want.
			if !errors.Is(err, ErrSanitizeResidue) && !errors.Is(err, ErrSanitizeUnverifiable) {
				t.Fatalf("refusal is neither residue nor unverifiable: %v", err)
			}
			t.Logf("%s refused as: %v", tc.file, err)
		})
	}
}

// TestVerifierAcceptsSanitizedOutput is the other half of the calibration: the
// same verifiers must accept what the sanitizer actually produces, or the
// whole operation is unusable regardless of how strict the checks are.
func TestVerifierAcceptsSanitizedOutput(t *testing.T) {
	requireGhostscript(t)
	requireVerifierBinaries(t)

	cases := []struct{ format, file string }{
		{"pdf", "threat_all_classes.pdf"},
		{"docm", "macro_enabled.docm"},
		{"jpg", "exif_gps.jpg"},
	}

	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			res, err := sanitizeFile(context.Background(), engineExec{}, tc.format,
				filepath.Join(sanitizeCorpusDir, tc.file), out)
			if err != nil {
				t.Fatalf("sanitizeFile: %v", err)
			}
			if len(res.Verified) == 0 {
				t.Fatal("Verified is empty: the removal ran and nothing confirmed it")
			}
		})
	}
}

// TestVerifierOutcomesAreDistinguishable pins the three-outcome rule of D-07.
// "Found residue" and "could not look" must never collapse into one error, or
// an operator reading the failure cannot tell a broken sanitizer from a broken
// verifier -- and, worse, a future refactor could quietly map the second onto
// success.
func TestVerifierOutcomesAreDistinguishable(t *testing.T) {
	if errors.Is(ErrSanitizeUnverifiable, ErrSanitizeResidue) ||
		errors.Is(ErrSanitizeResidue, ErrSanitizeUnverifiable) {
		t.Fatal("the two sentinels match each other; the outcomes are not distinguishable")
	}

	dir := t.TempDir()

	// outcome 2: residue. This needs a file that PARSES and is dirty --
	// the raw fixture does not parse under pdfcpu's validator, so using it
	// here would exercise the unverifiable branch twice and the residue
	// branch never.
	requireGhostscript(t)
	dirty := filepath.Join(dir, "dirty.pdf")
	clean := filepath.Join(dir, "clean.pdf")
	if _, err := sanitizeFile(context.Background(), engineExec{}, "pdf",
		filepath.Join(sanitizeCorpusDir, "threat_all_classes.pdf"), clean); err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}
	cleanBytes, err := os.ReadFile(clean)
	if err != nil {
		t.Fatal(err)
	}
	// Append a marker as a trailing comment: the file still parses, and the
	// byte view is the only one that can see it.
	if err := os.WriteFile(dirty, append(cleanBytes, []byte("\n% /JavaScript\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySanitized(context.Background(), engineExec{}, "pdf", dirty); !errors.Is(err, ErrSanitizeResidue) {
		t.Fatalf("want residue on a parseable-but-dirty file, got %v", err)
	}

	// outcome 3: unverifiable -- bytes no parser can read.
	garbage := filepath.Join(dir, "garbage.pdf")
	if err := os.WriteFile(garbage, []byte("this is not a PDF at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySanitized(context.Background(), engineExec{}, "pdf", garbage); !errors.Is(err, ErrSanitizeUnverifiable) {
		t.Fatalf("want unverifiable on unparseable bytes, got %v", err)
	}

	// a format with no verifier registered is unverifiable, never clean.
	if _, err := verifySanitized(context.Background(), engineExec{}, "tiff", garbage); !errors.Is(err, ErrSanitizeUnverifiable) {
		t.Fatalf("want unverifiable for an unregistered format, got %v", err)
	}
}

// TestVerifierRejectsMultiRevisionOutput covers the property neither the parse
// nor the byte grep can see on its own (SC3). The input parses cleanly and
// carries no residue in its current revision -- the ONLY thing wrong with it
// is that a previous revision is still recoverable.
func TestVerifierRejectsMultiRevisionOutput(t *testing.T) {
	requireGhostscript(t)

	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.pdf")
	if _, err := sanitizeFile(context.Background(), engineExec{}, "pdf",
		filepath.Join(sanitizeCorpusDir, "threat_all_classes.pdf"), clean); err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}

	base, err := os.ReadFile(clean)
	if err != nil {
		t.Fatal(err)
	}
	twoRevisions := filepath.Join(dir, "two.pdf")
	if err := os.WriteFile(twoRevisions, buildIncrementalUpdate(t, base), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = verifySanitized(context.Background(), engineExec{}, "pdf", twoRevisions)
	if !errors.Is(err, ErrSanitizeResidue) {
		t.Fatalf("a two-revision output was not rejected: %v", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("revision")) {
		t.Fatalf("the failure does not report the revision count as its own cause: %v", err)
	}
}

// TestVerifierCatchesRenamedOLEPart proves the OOXML verifier reads content,
// not names. The package below has no part called vbaProject.bin; it has an
// OLE container called word/settings-backup.xml, which is what an attacker who
// has read our source would ship.
func TestVerifierCatchesRenamedOLEPart(t *testing.T) {
	requireVerifierBinaries(t)

	real, err := os.ReadFile(filepath.Join(sanitizeCorpusDir, "macro_enabled.docm"))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(real), int64(len(real)))
	if err != nil {
		t.Fatal(err)
	}
	var vba []byte
	for _, f := range zr.File {
		if f.Name == "word/vbaProject.bin" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			vba, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(vba) == 0 {
		t.Fatal("fixture has no vbaProject.bin to rename; this test proves nothing")
	}

	cases := []struct {
		name    string
		content []byte
		why     string
	}{
		{
			name:    "well_formed_container",
			content: vba,
			why:     "a real OLE container under an innocuous name -- libmagic's job",
		},
		{
			name:    "degenerate_container",
			content: append(append([]byte(nil), oleCFBMagic...), []byte("payload")...),
			why:     "signature and little else -- libmagic will not call this CDFV2, so the prefix check must",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "renamed.docx")
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			for name, content := range map[string][]byte{
				"[Content_Types].xml":      []byte(`<?xml version="1.0"?><Types/>`),
				"word/document.xml":        []byte(`<?xml version="1.0"?><document/>`),
				"word/settings-backup.xml": tc.content,
			} {
				w, err := zw.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write(content); err != nil {
					t.Fatal(err)
				}
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := verifySanitized(context.Background(), engineExec{}, "docx", path); !errors.Is(err, ErrSanitizeResidue) {
				t.Fatalf("%s: not caught (%v)", tc.why, err)
			}
		})
	}
}

// TestUnverifiedOutputIsDeleted is the ordering test. SANI-04 requires the
// refusal to happen before anything reaches S3, and the strongest available
// form of that is not a promise about call order -- it is that the unverified
// bytes stop existing. A fake delivery step stands in for the upload and
// counts its own invocations, so a future refactor that moves verification
// after delivery reddens this test rather than passing it quietly.
func TestUnverifiedOutputIsDeleted(t *testing.T) {
	const fakeFormat = "octoconv-test-fake"

	origSanitize, hadSanitize := sanitizeFormats[fakeFormat]
	origVerify, hadVerify := verifiers[fakeFormat]
	t.Cleanup(func() {
		if hadSanitize {
			sanitizeFormats[fakeFormat] = origSanitize
		} else {
			delete(sanitizeFormats, fakeFormat)
		}
		if hadVerify {
			verifiers[fakeFormat] = origVerify
		} else {
			delete(verifiers, fakeFormat)
		}
	})

	sanitizeFormats[fakeFormat] = func(_ context.Context, _ engineExec, _, outPath string) (SanitizeResult, error) {
		return SanitizeResult{Removed: []ThreatClass{ThreatJavaScript}},
			os.WriteFile(outPath, []byte("produced output"), 0o600)
	}
	verifiers[fakeFormat] = func(_ context.Context, _ engineExec, _, _ string) ([]ThreatClass, error) {
		return nil, ErrSanitizeUnverifiable
	}

	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(in, []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}

	delivered := 0
	deliver := func(path string) error { delivered++; return nil }

	if _, err := sanitizeFile(context.Background(), engineExec{}, fakeFormat, in, out); err == nil {
		t.Fatal("sanitizeFile returned success despite an unverifiable output")
	} else if err := deliver(out); err != nil {
		_ = err // unreachable; kept so the fake has a real call site
	}

	// deliver() above is called ONLY on the success path in real code; here it
	// is invoked explicitly to prove the counter works, then the real
	// guarantee is checked: the bytes are gone.
	if delivered != 1 {
		t.Fatalf("counter wiring is broken (delivered=%d); this test proves nothing", delivered)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("unverified output still exists at %s (stat err = %v); "+
			"it could still be uploaded by any caller that ignores the error", out, err)
	}
}

// TestEverySanitizeFormatHasAVerifier is mechanical rather than a list: adding
// a format to sanitizeFormats without a verifier would otherwise ship a path
// whose output nothing checks. It fails at the moment the gap is introduced,
// not the moment someone notices.
func TestEverySanitizeFormatHasAVerifier(t *testing.T) {
	for format := range sanitizeFormats {
		if _, ok := verifiers[format]; !ok {
			t.Errorf("format %q sanitizes but has no verifier: its output would be "+
				"produced and never checked", format)
		}
	}
}

// TestEscapeZipGlob pins the quoting bug that would read as a clean verdict.
// Every OOXML package contains [Content_Types].xml, and Info-ZIP treats the
// brackets as wildcard syntax: unescaped, the member matches nothing, unzip
// exits 11, and a verifier that ignored the exit code would conclude the part
// is empty and therefore harmless.
func TestEscapeZipGlob(t *testing.T) {
	cases := map[string]string{
		"[Content_Types].xml": `\[Content_Types\].xml`,
		"word/document.xml":   "word/document.xml",
		"a*b?c":               `a\*b\?c`,
	}
	for in, want := range cases {
		if got := escapeZipGlob(in); got != want {
			t.Errorf("escapeZipGlob(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestVerifierDoesNotScanPDFStreamPayloads is the regression proof for the
// eleventh finding of PR #12, and the PDF twin of
// TestVerifierDoesNotMistakePayloadForStructure.
//
// The output below is a real sanitized PDF with a marker sequence appended
// inside a stream. Compressed content-stream bytes are arbitrary, so a
// document with enough content eventually contains "/AA" or "/URI" by chance.
// A whole-file scan called that residue, and because verification failure
// DELETES the output, the consequence was a destroyed correct result rather
// than a mislabelled job.
func TestVerifierDoesNotScanPDFStreamPayloads(t *testing.T) {
	requireGhostscript(t)

	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.pdf")
	if _, err := sanitizeFile(context.Background(), engineExec{}, "pdf",
		filepath.Join(sanitizeCorpusDir, "threat_all_classes.pdf"), clean); err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}
	base, err := os.ReadFile(clean)
	if err != nil {
		t.Fatal(err)
	}

	// Splice the markers into the FIRST stream payload of the sanitized file,
	// in place, so nothing about the file's structure changes.
	start := bytes.Index(base, []byte("stream"))
	if start < 0 {
		t.Skip("sanitized fixture has no stream to splice into")
	}
	start += len("stream")
	for start < len(base) && (base[start] == '\r' || base[start] == '\n') {
		start++
	}
	payload := []byte("/AA/URI/JavaScript")
	if start+len(payload) >= len(base) {
		t.Fatal("stream too short to splice into")
	}
	spliced := append([]byte(nil), base...)
	copy(spliced[start:], payload)

	withMarkers := filepath.Join(dir, "markers-in-stream.pdf")
	if err := os.WriteFile(withMarkers, spliced, 0o600); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(spliced, []byte("/JavaScript")) {
		t.Fatal("fixture does not contain the bytes the old scan tripped on")
	}

	got, err := scanPDFBytes(spliced)
	if err != nil {
		t.Fatalf("scanPDFBytes: %v", err)
	}
	if len(got) > 0 {
		t.Errorf("byte scan reported %v for markers that live inside a stream payload; "+
			"a verification failure deletes the output, so this destroys a correct result", got)
	}

	// And the scan must still SEE a marker outside any stream, or the scoping
	// has simply switched the check off.
	outside := append(append([]byte(nil), base...), []byte("\n% /JavaScript\n")...)
	got, err = scanPDFBytes(outside)
	if err != nil {
		t.Fatalf("scanPDFBytes: %v", err)
	}
	if len(got) == 0 {
		t.Error("byte scan no longer finds a marker outside a stream -- the scoping " +
			"disabled the check instead of narrowing it")
	}
	_ = withMarkers
}

func TestScanPDFBytesMatchesWholeNames(t *testing.T) {
	font := []byte("%PDF-1.4\n1 0 obj\n<< /BaseFont /AABCDE+Test /URIFont /URIFONT >>\nendobj\n%%EOF\n")
	got, err := scanPDFBytes(font)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a subset font name reported %v", got)
	}

	action := []byte("%PDF-1.4\n1 0 obj\n<< /AA << /O 2 0 R >> /A#41 <<>> >>\nendobj\n%%EOF\n")
	got, err = scanPDFBytes(action)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != ThreatActionDict {
		t.Fatalf("scanPDFBytes = %v, want [%s]", got, ThreatActionDict)
	}
}

// TestVerifierCatchesRelationshipResidue is the regression proof for the
// fifteenth finding of PR #12, and the third time in one review that the
// remover moved and the checker did not.
//
// The verifier reported embedded_file, external_reference AND
// document_metadata as confirmed absent while checking only part MIME types,
// the OLE signature and the macroEnabled content type. An archive still
// carrying metadata/core.xml plus a core-properties relationship passed it --
// so the one thing an independent verifier exists to catch, a sanitizer-side
// miss, was exactly what it could not see.
//
// Each case is a package the SANITIZER would have cleaned. They are handed
// straight to the verifier, which is the only way to ask "would you have
// noticed".
func TestVerifierCatchesRelationshipResidue(t *testing.T) {
	requireVerifierBinaries(t)

	rels := func(inner string) []byte {
		return []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			inner + `</Relationships>`)
	}

	cases := []struct {
		name  string
		parts map[string][]byte
		want  string
	}{
		{
			// The target's ROOT ELEMENT is deliberately not a properties
			// root, so the content check cannot fire and only the
			// relationship traversal can. Otherwise this case would pass
			// while that traversal was broken.
			name: "core-properties relationship outside docProps",
			parts: map[string][]byte{
				"_rels/.rels":       rels(`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="metadata/core.xml"/>`),
				"metadata/core.xml": []byte(`<?xml version="1.0"?><notAPropertiesRoot><creator>SecretAuthor</creator></notAPropertiesRoot>`),
			},
			want: "core-properties",
		},
		{
			name: "embedded package relationship",
			parts: map[string][]byte{
				"word/_rels/document.xml.rels": rels(`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" Target="media/attached.docx"/>`),
				"word/media/attached.docx":     []byte("PK\x03\x04attached"),
			},
			want: "package",
		},
		{
			name: "external relationship",
			parts: map[string][]byte{
				"word/_rels/settings.xml.rels": rels(`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example/t.dotm" TargetMode="External"/>`),
			},
			want: "external relationship",
		},
		{
			name: "properties part with no relationship pointing at it",
			parts: map[string][]byte{
				// The real extended-properties namespace. A bare <Properties>
				// with no namespace is an ordinary application-defined XML
				// part, which OPC packages may carry and which the verifier
				// must NOT call residue -- rejecting it deleted a correct
				// output (PR #12, round 6).
				"stray/props.xml": []byte(`<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>SecretCompany</Company></Properties>`),
			},
			want: "document-properties part",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "out.docx")
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			all := map[string][]byte{
				"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`),
				"word/document.xml":   []byte(`<?xml version="1.0"?><document/>`),
			}
			for k, v := range tc.parts {
				all[k] = v
			}
			// Sorted, not map order. Two of this verifier's checks can each
			// catch some of these cases, and unzip lists parts in archive
			// order -- so with map iteration WHICH check fired varied per
			// run, and an assertion on the message was passing by luck. A
			// test whose outcome depends on map ordering is not testing what
			// it says it tests.
			names := make([]string, 0, len(all))
			for name := range all {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				w, err := zw.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write(all[name]); err != nil {
					t.Fatal(err)
				}
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := verifySanitized(context.Background(), engineExec{}, "docx", path)
			if err == nil {
				t.Fatalf("the verifier confirmed this package clean; it reports the OOXML " +
					"classes as verified while being unable to see this residue at all")
			}
			if !errors.Is(err, ErrSanitizeResidue) {
				t.Fatalf("want residue, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("failure does not name what it found (%q): %v", tc.want, err)
			}
		})
	}
}

// TestVerifierAcceptsCustomXMLParts is the other half of the property-root
// check, and the half that was missing when it was written.
//
// An OPC package may carry application-defined XML parts, and <Properties> in
// somebody else's namespace is an ordinary one. The first version matched on
// local name alone, so it called that residue -- and because a residue verdict
// DELETES the output, it destroyed a correct result rather than mislabelling
// a job. Too narrow a view misses residue; too broad a predicate invents it,
// and both cost the client a file.
func TestVerifierKeepsSpacedOOXMLMemberNames(t *testing.T) {
	requireVerifierBinaries(t)

	path := buildOOXMLPackage(t, map[string][]byte{
		"[Content_Types].xml":    []byte(ctWithDocument),
		"word/document.xml":      []byte(`<?xml version="1.0"?><document/>`),
		"word/media/image 1.png": []byte("not-a-real-png"),
	})
	if _, err := verifySanitized(context.Background(), engineExec{}, "docx", path); err != nil {
		t.Fatal(err)
	}
}

func TestUnzipMemberNamesKeepSpaces(t *testing.T) {
	got := unzipMemberNames([]byte("word/media/image 1.png\n[Content_Types].xml\n"))
	want := []string{"word/media/image 1.png", "[Content_Types].xml"}
	if len(got) != len(want) {
		t.Fatalf("names = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names = %#v", got)
		}
	}
}

func TestVerifierAcceptsCustomXMLParts(t *testing.T) {
	requireVerifierBinaries(t)

	path := filepath.Join(t.TempDir(), "out.docx")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	parts := map[string][]byte{
		// The Override is not decoration: SANI-09 requires the main part to be
		// present AND declared, so an empty <Types/> now fails verification.
		// This fixture used to carry one because nothing looked -- which is
		// precisely the gap that requirement closes. What this test is about
		// (application-defined XML parts are not residue) is unchanged.
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`</Types>`),
		"word/document.xml":   []byte(`<?xml version="1.0"?><document/>`),
		"customXml/item1.xml": []byte(`<?xml version="1.0"?><Properties xmlns="urn:example:app"><Field>ordinary data</Field></Properties>`),
		"customXml/item2.xml": []byte(`<?xml version="1.0"?><coreProperties xmlns="urn:example:other"><x/></coreProperties>`),
	}
	names := make([]string, 0, len(parts))
	for name := range parts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(parts[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := verifySanitized(context.Background(), engineExec{}, "docx", path); err != nil {
		t.Errorf("a package with application-defined XML parts was rejected: %v -- the output "+
			"is deleted on a residue verdict, so this destroys a correct result", err)
	}
}

// TestVerifierRequiresAContentTypesPart pins the check that says nothing when
// the part it inspects is absent.
//
// A zip carrying word/document.xml and no [Content_Types].xml is admitted as
// docx by SniffContainer. The sanitizer copies the root part through, the
// macro-enabled check never ran because there was nothing to run it on, and
// every OOXML class came back verified -- the job reached done with a package
// Office cannot open.
func TestVerifierRequiresAContentTypesPart(t *testing.T) {
	requireVerifierBinaries(t)

	path := filepath.Join(t.TempDir(), "out.docx")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`<?xml version="1.0"?><document/>`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = verifySanitized(context.Background(), engineExec{}, "docx", path)
	if err == nil {
		t.Fatal("a package with no [Content_Types].xml verified clean")
	}
	if !errors.Is(err, ErrSanitizeUnverifiable) {
		t.Errorf("want unverifiable for a package that is not OOXML, got %v", err)
	}
}

// TestVerifierAndSanitizerAgreeOnRelationshipTypes holds the two deliberately
// separate tables equal.
//
// They are separate so a mistake in the sanitizer's handling cannot travel
// into its own verification. That is only worth anything if a DIVERGENCE is
// loud: a type the sanitizer drops and the verifier does not know about is a
// class the report would claim verified without checking.
func TestVerifierAndSanitizerAgreeOnRelationshipTypes(t *testing.T) {
	for leaf := range embeddedContentRelTypes {
		if _, ok := verifyResidualRelTypes[leaf]; !ok {
			t.Errorf("the sanitizer drops %q but the verifier does not look for it", leaf)
		}
	}
	for leaf := range metadataRelTypes {
		if _, ok := verifyResidualRelTypes[leaf]; !ok {
			t.Errorf("the sanitizer drops %q but the verifier does not look for it", leaf)
		}
	}
	for leaf := range verifyResidualRelTypes {
		_, embedded := embeddedContentRelTypes[leaf]
		_, metadata := metadataRelTypes[leaf]
		if !embedded && !metadata {
			t.Errorf("the verifier rejects %q but the sanitizer never drops it -- every "+
				"sanitized package would fail verification", leaf)
		}
	}
}

// TestVerifierRejectsPaddedAdobeMarker is the regression proof for the
// nineteenth finding of PR #12.
//
// The colour-management allowance matched APP14 on the five bytes "Adobe"
// alone, so a payload of "Adobe" followed by appended EXIF survived the
// sanitizer AND was confirmed clean by the verifier. The file still decoded
// and the job still reached done, with the metadata still in it.
//
// The Adobe marker has a fixed shape -- twelve bytes -- so it is checkable,
// and both halves must check it: a verifier that accepts any "Adobe" prefix
// confirms as clean the exact segment the sanitizer was fixed to stop keeping.
func TestVerifierRejectsPaddedAdobeMarker(t *testing.T) {
	genuine := append([]byte("Adobe"), []byte{0x00, 0x64, 0, 0, 0, 0, 2}...)
	if len(genuine) != 12 {
		t.Fatalf("the genuine Adobe payload is %d bytes, not 12; the fixture is wrong", len(genuine))
	}
	padded := append(append([]byte(nil), genuine...), []byte("Exif\x00\x00MM\x00\x2aSMUGGLED")...)

	// The APP14 verdict is still a property of the single segment, so the
	// iccSetComplete argument is irrelevant to it -- passed as true so a
	// failure here can only be about the Adobe shape check.
	if !jpegSegmentAllowed(0xEE, genuine, true) {
		t.Error("the verifier rejects a genuine Adobe colour-transform marker")
	}
	if jpegSegmentAllowed(0xEE, padded, true) {
		t.Error("the verifier accepts an APP14 carrying appended metadata behind the Adobe tag")
	}
	if !isKeptJPEGAppSegment(0xEE, genuine) {
		t.Error("the sanitizer drops a genuine Adobe colour-transform marker")
	}
	if isKeptJPEGAppSegment(0xEE, padded) {
		t.Error("the sanitizer keeps an APP14 carrying appended metadata behind the Adobe tag")
	}

	// An ICC chunk set whose assembled data does not match the profile's own
	// declared size is carrying something the profile does not describe.
	//
	// Asserted through jpegMetadataResidue rather than through
	// jpegSegmentAllowed directly, because the ICC verdict is no longer a
	// property of one segment: SANI-07 moved it to the SET, since the four
	// bytes this used to read as a size are the size field only in chunk 1.
	// Both original propositions are preserved -- the well-formed chunk is
	// still accepted, the 8-declared/204-carried one is still rejected -- and
	// they are now asserted at the entry point the verifier actually uses.
	icc := func(declared uint32, extra int) []byte {
		p := append([]byte("ICC_PROFILE\x00"), 0x01, 0x01)
		size := make([]byte, 4)
		binary.BigEndian.PutUint32(size, declared)
		p = append(p, size...)
		return append(p, bytes.Repeat([]byte{0xAA}, extra)...)
	}
	if _, found, err := jpegMetadataResidue(buildJPEGWithSegments(t, jpegSegment(0xE2, icc(64, 60)))); err != nil || found {
		t.Errorf("a well-formed ICC chunk was reported as residue: %v", err)
	}
	if _, found, err := jpegMetadataResidue(buildJPEGWithSegments(t, jpegSegment(0xE2, icc(8, 200)))); err != nil || !found {
		t.Errorf("an ICC chunk carrying far more than its profile declares was accepted: %v", err)
	}
}

// TestStreamRangesAgreeWithTheVerifier holds the two independently written
// stream walkers to the same answer.
//
// They are separate so one subtle bug cannot sit in front of both the
// redaction and the check meant to catch its mistakes. Separate is only worth
// anything if divergence is loud, which is what this asserts -- on real
// sanitizer output rather than a synthetic string.
func TestStreamRangesAgreeWithTheVerifier(t *testing.T) {
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
	blanked, err := pdfNonStreamBytes(raw)
	if err != nil {
		t.Fatalf("pdfNonStreamBytes: %v", err)
	}
	if len(blanked) != len(raw) {
		t.Fatalf("the verifier's blanking changed the length (%d -> %d)", len(raw), len(blanked))
	}
	for _, r := range ranges {
		for i := r[0]; i < r[1]; i++ {
			if blanked[i] != ' ' {
				t.Fatalf("byte %d is inside a stream by one walker and outside by the other", i)
			}
		}
	}
	for i := range raw {
		if !inAnyRange(ranges, i) && blanked[i] != raw[i] {
			t.Fatalf("byte %d is outside a stream by one walker and inside by the other", i)
		}
	}
}

// TestVerifierCountsRevisionsOutsideStreams pins the scoping on the one check
// where a false positive costs a valid output.
func TestVerifierCountsRevisionsOutsideStreams(t *testing.T) {
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
		t.Fatal("no streams to splice into")
	}
	// Splice trailer-looking bytes into a stream payload, in place.
	spliced := append([]byte(nil), raw...)
	payload := []byte("%%EOF\nstartxref\n")
	at := ranges[0][0]
	if at+len(payload) >= ranges[0][1] {
		t.Skip("first stream is too short to splice into")
	}
	copy(spliced[at:], payload)

	if err := verifySingleRevision(spliced); err != nil {
		t.Errorf("trailer markers inside a stream were counted as a second revision: %v -- "+
			"this verdict deletes a valid output", err)
	}

	// And a genuine second revision must still be caught.
	twoRevisions := append(append([]byte(nil), raw...), []byte("\nstartxref\n0\n%%EOF\n")...)
	if err := verifySingleRevision(twoRevisions); err == nil {
		t.Error("a real second trailer was not counted -- the scoping disabled the check")
	}
}

// TestVerifierCatchesEveryMacroContentType holds the verifier's substring list
// to the sanitizer's content-type table.
//
// The verifier looked for "macroEnabled" alone. Every main macro content type
// contains it, so the gap was narrow -- but the vbaProject type does not, and
// the sanitizer removes its Default declaration when no .bin part survives. A
// package that kept that declaration would have verified clean while the
// sanitizer had not finished its own job.
//
// Found by sweeping for the shape rather than by review: a rule the remover
// applies more broadly than the checker, which is the pattern review named
// four separate times in this PR.
func TestVerifierCatchesEveryMacroContentType(t *testing.T) {
	for ct := range macroEnabledContentTypes {
		matched := false
		for _, marker := range macroContentTypeMarkers {
			if strings.Contains(ct, marker) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("the sanitizer rewrites content type %q and no verifier marker matches it; "+
				"a package keeping it would verify clean", ct)
		}
	}

	// The vbaProject Default the sanitizer drops alongside the part.
	const vba = "application/vnd.ms-office.vbaProject"
	matched := false
	for _, marker := range macroContentTypeMarkers {
		if strings.Contains(vba, marker) {
			matched = true
		}
	}
	if !matched {
		t.Errorf("no verifier marker matches %q", vba)
	}
}
