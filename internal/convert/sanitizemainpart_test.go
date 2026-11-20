package convert

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// buildOOXMLPackage writes a deterministic zip from the given parts.
func buildOOXMLPackage(t *testing.T, parts map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(parts))
	for n := range parts {
		names = append(names, n)
	}
	// Sorted, because a map's iteration order decides WHICH check fires first
	// when several would -- and a test whose verdict varies per run is not a
	// verdict. This package has already paid for that once.
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(parts[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pkg.docx")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const ctWithDocument = `<?xml version="1.0"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`</Types>`

// TestSanitizedPackageWithoutItsDocumentIsRejected is SANI-09.
//
// relationshipDrivenDrops resolves a relationship's Target and drops that part.
// A .rels whose Target is the package's OWN main part therefore produces an
// output that unzips, carries a well-formed [Content_Types].xml, and contains no
// document at all.
//
// Observed on ooxml_rel_targets_main.docx before this fix: sanitizeFile
// SUCCEEDED, reported five removed classes, and delivered that package. The
// verifier counted [Content_Types].xml and never asked whether anything else
// survived -- so the one thing a client would notice immediately was the one
// thing nothing checked.
func TestSanitizedPackageWithoutItsDocumentIsRejected(t *testing.T) {
	requireVerifierBinaries(t)

	src := filepath.Join(sanitizeCorpusDir, "ooxml_rel_targets_main.docx")
	out := filepath.Join(t.TempDir(), "out.docx")

	_, err := sanitizeFile(context.Background(), engineExec{}, "docx", src, out)
	if err == nil {
		t.Fatal("sanitizeFile delivered a package whose main part it had just dropped")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("word/document.xml")) {
		t.Errorf("the failure does not name the missing part: %v", err)
	}

	// D-07: an output that could not be verified is deleted, not delivered.
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("the unverifiable output is still on disk")
	}
}

// TestVerifierRequiresTheMainPartAndItsDeclaration pins both halves separately,
// because a fix that only checked presence would pass a package whose main part
// is there and undeclared -- which Office will not open either.
func TestVerifierRequiresTheMainPartAndItsDeclaration(t *testing.T) {
	requireVerifierBinaries(t)

	cases := []struct {
		name  string
		parts map[string][]byte
		want  string
	}{
		{
			name: "main part missing entirely",
			parts: map[string][]byte{
				"[Content_Types].xml": []byte(ctWithDocument),
				"word/styles.xml":     []byte(`<?xml version="1.0"?><styles/>`),
			},
			want: "has no word/document.xml",
		},
		{
			name: "main part present but not declared",
			parts: map[string][]byte{
				"[Content_Types].xml": []byte(`<?xml version="1.0"?>` +
					`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
					`<Override PartName="/word/styles.xml" ContentType="application/xml"/>` +
					`</Types>`),
				"word/document.xml": []byte(`<?xml version="1.0"?><document/>`),
			},
			want: "does not declare a content type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := buildOOXMLPackage(t, tc.parts)
			_, err := verifySanitized(context.Background(), engineExec{}, "docx", path)
			if err == nil {
				t.Fatal("the verifier accepted it")
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tc.want)) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}

	// And the honest-input case, so the requirement cannot be satisfied by
	// rejecting everything.
	ok := buildOOXMLPackage(t, map[string][]byte{
		"[Content_Types].xml": []byte(ctWithDocument),
		"word/document.xml":   []byte(`<?xml version="1.0"?><document/>`),
	})
	if _, err := verifySanitized(context.Background(), engineExec{}, "docx", ok); err != nil {
		t.Errorf("a package that has its document and declares it was rejected: %v", err)
	}
}

// TestVerifierAcceptsADefaultExtensionDeclaration covers the other legal way to
// declare a part's content type (ECMA-376 Part 2 §10.1.2). Real packages use an
// Override for the main part because its content type is format-specific, but a
// Default is not wrong and refusing it would fail a valid package -- too broad
// a rejection costs a client a file just as surely as too narrow a check.
func TestVerifierAcceptsADefaultExtensionDeclaration(t *testing.T) {
	requireVerifierBinaries(t)

	path := buildOOXMLPackage(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`</Types>`),
		"word/document.xml": []byte(`<?xml version="1.0"?><document/>`),
	})
	if _, err := verifySanitized(context.Background(), engineExec{}, "docx", path); err != nil {
		t.Errorf("a Default-declared main part was rejected: %v", err)
	}
}

// TestMainPartIsRequiredForEveryOOXMLFormatTheSanitizerServes is the
// completeness half. A map with one entry filled in would satisfy every test
// above while leaving xlsx and pptx unchecked -- and an unchecked format is one
// where this whole requirement silently does not apply.
func TestMainPartIsRequiredForEveryOOXMLFormatTheSanitizerServes(t *testing.T) {
	for _, f := range []string{"docm", "docx", "xlsm", "xlsx", "pptm", "pptx", "dotm", "potm", "ppsm"} {
		if _, ok := verifiers[f]; !ok {
			t.Fatalf("%s has no verifier registered; this list has drifted from the one in init()", f)
		}
		if ooxmlMainPart(f) == "" {
			t.Errorf("%s is verified by verifyOOXML but declares no main part, so for that "+
				"format the verifier cannot tell an empty package from a sanitized one", f)
		}
	}
	if ooxmlMainPart("pdf") != "" {
		t.Error("a non-OOXML format has a main part; the map has grown past its own subject")
	}
}
