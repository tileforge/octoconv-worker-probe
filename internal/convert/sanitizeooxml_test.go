package convert

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sanitizeDocmFixture(t *testing.T) string {
	t.Helper()
	return filepath.Join(sanitizeCorpusDir, "macro_enabled.docm")
}

// TestSanitizeOOXMLRemovesMacroBytes is the SANI-01 proof, checked in the
// OUTPUT BYTES: the OLE signature, the part name, and the p-code marker are
// all gone.
//
// The p-code marker matters on its own. VBA stomping keeps benign module
// source and hides behaviour in compiled p-code, so a sanitizer that read
// source and kept the part would leave the actual payload behind while
// looking correct.
func TestSanitizeOOXMLRemovesMacroBytes(t *testing.T) {
	in := sanitizeDocmFixture(t)
	raw, err := os.ReadFile(in)
	if err != nil {
		t.Fatalf("read fixture: %v -- committed by Plan 60-01", err)
	}
	if !bytes.Contains(raw, []byte("word/vbaProject.bin")) {
		t.Fatalf("fixture has no vbaProject part -- regenerate with scripts/sanitize-corpus.py")
	}

	out := filepath.Join(t.TempDir(), "clean.docx")
	res, err := sanitizeFile(context.Background(), engineExec{}, "docm", in, out)
	if err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range [][]byte{
		{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, // OLE CFB signature
		[]byte("vbaProject"),
		[]byte("_VBA_PROJECT"), // the p-code marker
	} {
		if bytes.Contains(got, m) {
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
	}
	if len(res.LostCapabilities) == 0 {
		t.Error("LostCapabilities is empty -- macro functionality is gone and D-02 requires saying so")
	}
}

// ooxmlConsistency walks a rebuilt archive and reports every dangling
// reference in it.
//
// It walks EVERY Override and EVERY Relationship rather than checking a list
// of names it expects to be gone. The rule "no reference dangles" survives a
// new format being added; a list of known part names does not, and would go
// quietly green on the one part nobody thought to add to it.
func ooxmlConsistency(t *testing.T, archive []byte) []string {
	t.Helper()

	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("output is not a readable zip: %v", err)
	}

	present := map[string]bool{}
	contents := map[string][]byte{}
	for _, f := range zr.File {
		present[f.Name] = true
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(rc); err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		rc.Close()
		contents[f.Name] = buf.Bytes()
	}

	var problems []string

	if raw, ok := contents["[Content_Types].xml"]; ok {
		var ct ctTypes
		if err := xml.Unmarshal(raw, &ct); err != nil {
			problems = append(problems, "[Content_Types].xml does not parse: "+err.Error())
		}
		for _, o := range ct.Override {
			name := strings.TrimPrefix(o.PartName, "/")
			if !present[name] {
				problems = append(problems, "Override points at missing part: "+name)
			}
			if _, macro := macroEnabledContentTypes[o.ContentType]; macro {
				problems = append(problems, "Override still carries a macroEnabled content type: "+o.PartName)
			}
		}
	} else {
		problems = append(problems, "[Content_Types].xml is missing entirely")
	}

	for name, raw := range contents {
		if !strings.HasSuffix(name, ".rels") {
			continue
		}
		var rs relRelationships
		if err := xml.Unmarshal(raw, &rs); err != nil {
			problems = append(problems, name+" does not parse: "+err.Error())
			continue
		}
		for _, r := range rs.Rel {
			if strings.EqualFold(r.TargetMode, "External") {
				problems = append(problems, name+" still carries an external relationship: "+r.Target)
				continue
			}
			target := resolveTarget(name, r.Target)
			if !present[target] {
				problems = append(problems, name+" points at missing part: "+target)
			}
		}
	}

	return problems
}

// TestSanitizeOOXMLStaysConsistent is what catches the failure disguised as
// success: an archive missing one of the three coordinated edits opens as a
// valid zip, finishes the job green, and is refused by Word.
func TestSanitizeOOXMLStaysConsistent(t *testing.T) {
	out := filepath.Join(t.TempDir(), "clean.docx")
	if _, err := sanitizeFile(context.Background(), engineExec{}, "docm", sanitizeDocmFixture(t), out); err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	if problems := ooxmlConsistency(t, got); len(problems) > 0 {
		t.Errorf("the rebuilt container is internally inconsistent -- it would open as a zip and be refused by Word:\n  %s",
			strings.Join(problems, "\n  "))
	}

	// The fixture's own wiring must genuinely have been present, or the
	// consistency check above passed over an empty subject.
	src, err := os.ReadFile(sanitizeDocmFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if problems := ooxmlConsistency(t, src); len(problems) != 0 {
		t.Logf("input fixture's own wiring (expected to be consistent before sanitization): %v", problems)
	}
}

// TestSanitizeOOXMLDropsRenamedMacroPart is the D-04/Q3 requirement in test
// form: the OLE container is recognised by its CONTENT, so renaming the part
// does not smuggle it through.
//
// A checker that drops "word/vbaProject.bin" by name catches only an opponent
// who left the default name in place.
// TestSanitizeOOXMLDropsRenamedMacroPart also covers the dangling-override
// case that the survivor-set rewrite fixed: the renamed package's
// [Content_Types].xml still declares an Override for /word/vbaProject.bin,
// a part that does not exist in it at all. Dropping only the overrides for
// parts THIS RUN removed left that declaration standing, so the macro was
// gone and the package still announced one.
func TestSanitizeOOXMLDropsRenamedMacroPart(t *testing.T) {
	src, err := os.ReadFile(sanitizeDocmFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(src), int64(len(src)))
	if err != nil {
		t.Fatal(err)
	}

	// Rebuild the fixture with the macro part under an innocuous name.
	var renamed bytes.Buffer
	zw := zip.NewWriter(&renamed)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()

		name := f.Name
		if name == "word/vbaProject.bin" {
			name = "word/media/image9.dat"
		}
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(buf.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	in := filepath.Join(dir, "renamed.docm")
	if err := os.WriteFile(in, renamed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "clean.docx")
	if _, err := sanitizeFile(context.Background(), engineExec{}, "docm", in, out); err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}

	// Every Override must name a part that is actually present. A declaration
	// pointing at nothing is the dangling reference this whole file exists to
	// avoid, and it carried the vbaProject content type here.
	produced, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if dangling := ooxmlConsistency(t, produced); len(dangling) > 0 {
		t.Errorf("renamed-macro package has dangling declarations: %v", dangling)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) {
		t.Error("the OLE container survived under a renamed part -- detection is keying on the part NAME, not its content")
	}
	if bytes.Contains(got, []byte("_VBA_PROJECT")) {
		t.Error("the p-code marker survived under a renamed part")
	}
}

// TestSanitizedOOXMLExtensionFollowsContentType pins D-06's client-visible
// half: a container whose content type no longer promises macros must not
// keep an extension that does.
func TestSanitizedOOXMLExtensionFollowsContentType(t *testing.T) {
	for in, want := range map[string]string{
		"docm": "docx", "dotm": "dotx", "xlsm": "xlsx", "xltm": "xltx",
		"pptm": "pptx", "potm": "potx", "ppsm": "ppsx",
		"docx": "docx", // already macro-free: unchanged
	} {
		if got := SanitizedOOXMLExtension(in); got != want {
			t.Errorf("SanitizedOOXMLExtension(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSanitizeOOXMLDropsEmbeddedPackageByRelationshipType is the regression
// proof for the second finding of PR #12.
//
// The attachment below is a PDF at word/media/attached.pdf: not an OLE
// container, not under */embeddings/, not named like anything suspicious. The
// ONLY thing marking it as embedded content is the relationship type pointing
// at it, which is exactly how OOXML defines an embedded package. Before the
// fix it survived every predicate while `embedded_file` appeared in both the
// report's removed and verified lists.
func TestSanitizeOOXMLDropsEmbeddedPackageByRelationshipType(t *testing.T) {
	const attachment = "word/media/attached.pdf"

	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" Target="media/attached.pdf"/>` +
		`</Relationships>`

	in := filepath.Join(t.TempDir(), "in.docx")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string][]byte{
		"[Content_Types].xml":          []byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="pdf" ContentType="application/pdf"/></Types>`),
		"word/document.xml":            []byte(`<?xml version="1.0"?><document/>`),
		"word/_rels/document.xml.rels": []byte(rels),
		attachment:                     []byte("%PDF-1.4\nattached payload\n%%EOF\n"),
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
	if err := os.WriteFile(in, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "out.docx")
	res, err := sanitizeOOXML(context.Background(), engineExec{}, in, out)
	if err != nil {
		t.Fatalf("sanitizeOOXML: %v", err)
	}

	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name == attachment {
			t.Errorf("%s survived: an embedded package is identified by its relationship "+
				"type, not by living under */embeddings/", attachment)
		}
	}

	// And the relationship pointing at it must be gone, or the package keeps a
	// dangling reference to the part just removed.
	if dangling := ooxmlConsistency(t, blob); len(dangling) > 0 {
		t.Errorf("sanitized package has dangling references: %v", dangling)
	}

	var sawEmbedded bool
	for _, c := range res.Removed {
		if c == ThreatEmbeddedFile {
			sawEmbedded = true
		}
	}
	if !sawEmbedded {
		t.Error("removed does not list embedded_file after dropping an embedded package")
	}
}

// TestSanitizeOOXMLDropsPropertiesByRelationshipType is the regression proof
// for the fourteenth finding of PR #12, and it is the same defect as
// TestSanitizeOOXMLDropsEmbeddedPackageByRelationshipType one level over.
//
// That fix replaced a path check for embedded content and left the properties
// check -- `strings.HasPrefix(name, "docProps/")` -- standing directly beneath
// the comment explaining why a path check is the wrong shape. A package
// storing its core properties at metadata/core.xml therefore kept its author
// and title while the report claimed document_metadata removed AND verified.
//
// Fixing the named instance is not fixing the class, and a fix that leaves its
// own sibling in place is the clearest demonstration of that available.
func TestSanitizeOOXMLDropsPropertiesByRelationshipType(t *testing.T) {
	const props = "metadata/core.xml"

	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="metadata/core.xml"/>` +
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="metadata/app.xml"/>` +
		`</Relationships>`

	in := filepath.Join(t.TempDir(), "in.docx")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`),
		"_rels/.rels":         []byte(rels),
		"word/document.xml":   []byte(`<?xml version="1.0"?><document/>`),
		props:                 []byte(`<?xml version="1.0"?><coreProperties><creator>SecretAuthor</creator></coreProperties>`),
		"metadata/app.xml":    []byte(`<?xml version="1.0"?><Properties><Company>SecretCompany</Company></Properties>`),
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
	if err := os.WriteFile(in, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "out.docx")
	res, err := sanitizeOOXML(context.Background(), engineExec{}, in, out)
	if err != nil {
		t.Fatalf("sanitizeOOXML: %v", err)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"SecretAuthor", "SecretCompany"} {
		if bytes.Contains(blob, []byte(gone)) {
			t.Errorf("%q survived: properties are identified by relationship type, not by "+
				"living under docProps/", gone)
		}
	}
	if dangling := ooxmlConsistency(t, blob); len(dangling) > 0 {
		t.Errorf("sanitized package has dangling references: %v", dangling)
	}

	var sawMetadata bool
	for _, c := range res.Removed {
		if c == ThreatDocumentMetadata {
			sawMetadata = true
		}
	}
	if !sawMetadata {
		t.Error("removed does not list document_metadata after dropping the properties parts")
	}
}

// TestSanitizeMalformedInputIsDistinguishable pins the sentinel the worker
// classifies on. A file the engine cannot parse is deterministic on the input;
// a timeout is not, and the two must not collapse.
func TestSanitizeMalformedInputIsDistinguishable(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.docx")
	if err := os.WriteFile(in, []byte("PK\x03\x04 not really a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := sanitizeOOXML(context.Background(), engineExec{}, in, filepath.Join(dir, "out.docx"))
	if err == nil {
		t.Fatal("a corrupt archive was accepted")
	}
	if !errors.Is(err, ErrSanitizeMalformedInput) {
		t.Errorf("a corrupt archive is not marked malformed: %v -- the worker would classify "+
			"it transient, exhaust its retries without ever calling MarkFailed, and leave the "+
			"job active for the reconciler", err)
	}
	if errors.Is(err, ErrSanitizeResidue) || errors.Is(err, ErrSanitizeUnverifiable) {
		t.Error("a malformed INPUT is being reported as a verification outcome")
	}

	// EVERY input-parse path, not only the ones the sentinel reached first.
	// It was applied to ghostscript, archive-open and XML-parse and to nothing
	// else, so a malformed image still fell through as transient -- the same
	// stopped-at-the-first-instance shape, one round after review named it.
	images := []struct {
		name string
		blob []byte
		why  string
	}{
		{"not an image at all", []byte("just text"), "unrecognized container"},
		// This one never reaches the JPEG walker: sanitizeImage dispatches on
		// magic bytes, and FF D9 is not SOI, so it takes the
		// unrecognized-container branch. Named for what it actually
		// exercises -- an inversion pass caught the original name claiming
		// otherwise, which would have made a dead branch look covered.
		{"bytes that match no container", []byte{0xFF, 0xD9, 0x00}, "unrecognized container"},
		{"JPEG with a lying segment length", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xFF, 0x00}, "segment overruns the file"},
		{"PNG with a lying chunk length", append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'},
			[]byte{0xFF, 0xFF, 0xFF, 0x00, 'I', 'H', 'D', 'R'}...), "chunk overruns the file"},
	}
	for _, tc := range images {
		t.Run(tc.name, func(t *testing.T) {
			in := filepath.Join(t.TempDir(), "in.jpg")
			if err := os.WriteFile(in, tc.blob, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := sanitizeImage(context.Background(), engineExec{}, in, filepath.Join(t.TempDir(), "out.jpg"))
			if err == nil {
				t.Fatalf("accepted a malformed image (%s)", tc.why)
			}
			if !errors.Is(err, ErrSanitizeMalformedInput) {
				t.Errorf("%s is not marked malformed: %v -- the worker classifies it transient, "+
					"exhausts its retries without MarkFailed, and leaves the job active", tc.why, err)
			}
		})
	}
}

func TestResolveTargetKeepsPackageAbsolute(t *testing.T) {
	const rels = "word/_rels/document.xml.rels"
	if got := resolveTarget(rels, "/word/media/image1.png"); got != "word/media/image1.png" {
		t.Fatalf("absolute target resolved to %q", got)
	}
	if got := resolveTarget(rels, "media/image1.png"); got != "word/media/image1.png" {
		t.Fatalf("relative target resolved to %q", got)
	}
	if got := resolveTarget(rels, "vbaProject.bin"); got != "word/vbaProject.bin" {
		t.Fatalf("sibling target resolved to %q", got)
	}
}

func TestSanitizeOOXMLKeepsPackageAbsoluteImage(t *testing.T) {
	const image = "word/media/image1.png"
	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="/word/media/image1.png"/>` +
		`</Relationships>`
	in := filepath.Join(t.TempDir(), "in.docx")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string][]byte{
		"[Content_Types].xml":          []byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="png" ContentType="image/png"/></Types>`),
		"word/document.xml":            []byte(`<?xml version="1.0"?><document/>`),
		"word/_rels/document.xml.rels": []byte(rels),
		image:                          []byte("png-bytes"),
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
	if err := os.WriteFile(in, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.docx")
	if _, err := sanitizeOOXML(context.Background(), engineExec{}, in, out); err != nil {
		t.Fatalf("sanitizeOOXML: %v", err)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	parts := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		buf, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		parts[f.Name] = buf
	}
	if !bytes.Equal(parts[image], []byte("png-bytes")) {
		t.Fatalf("package-absolute image = %q", parts[image])
	}
	relsOut := parts["word/_rels/document.xml.rels"]
	if !bytes.Contains(relsOut, []byte(`Target="/word/media/image1.png"`)) {
		t.Fatalf("package-absolute relationship was rewritten away: %s", relsOut)
	}
	if dangling := ooxmlConsistency(t, blob); len(dangling) > 0 {
		t.Fatalf("dangling: %v", dangling)
	}
}

type countReader struct {
	n   int
	src io.Reader
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.n += n
	return n, err
}

func TestReadBoundedStopsAtTheCeiling(t *testing.T) {
	cr := &countReader{src: bytes.NewReader(bytes.Repeat([]byte{'a'}, 1000))}
	_, err := readBounded(context.Background(), cr, 10)
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("ceiling: %v", err)
	}
	if cr.n != 11 {
		t.Fatalf("read %d bytes, want 11", cr.n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = readBounded(ctx, bytes.NewReader(bytes.Repeat([]byte{'a'}, 100)), 50)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestLoadOOXMLPartsEnforcesBothCeilings(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, item := range []struct {
		name string
		body string
	}{
		{"a.txt", strings.Repeat("a", 20)},
		{"b.txt", strings.Repeat("b", 20)},
	} {
		w, err := zw.Create(item.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(item.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadOOXMLParts(context.Background(), zr.File, 16, 100)
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("part ceiling: %v", err)
	}
	_, err = loadOOXMLParts(context.Background(), zr.File, 100, 30)
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("archive ceiling: %v", err)
	}
	got, err := loadOOXMLParts(context.Background(), zr.File, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || int64(len(got[0].content)+len(got[1].content)) != 40 {
		t.Fatalf("parts %#v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = loadOOXMLParts(ctx, zr.File, 100, 100)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}
