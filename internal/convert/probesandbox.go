// Package convert (this file): probesandbox.go is probe's half of the
// engineExec contract -- the measured grant (D-10), the per-job ruleset
// builder, the concurrency guard, and the preflight that proves all four
// engines (gs, pdfinfo, unzip, file) work inside the job directory and are
// denied a file outside it -- mirroring ocrsandbox.go's shape, but for a
// class whose call sites span sanitizepdf.go and sanitizeverify.go rather
// than living beside its own single converter file.
package convert

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"path/filepath"
	"strings"
)

// probeReadWrite is empty ON PURPOSE (D-05, measured 2026-09-25): ghostscript
// honours TMPDIR exactly -- every gs_* scratch file lands inside the
// TMPDIR probe's own exec sets, and zero files touch bare /tmp -- so probe
// needs no shared writable path at all, unlike html's chromium (CONF-06).
//
// Adding a /tmp entry here would re-arm ProbeConcurrencyGuard (sharedTmpGuard
// is keyed on the GRANT SET, not the class name) and require D-04's sweep
// machinery all over again. Re-measure with scripts/sandbox-paths-measure.sh
// before ever adding one; do not edit this to "fix" a failing test.
var probeReadWrite = []string{}

// probeReadOnly is what probe's four engines need to read, beyond their own
// binaries and the job directory, RE-MEASURED from the code's six exec
// sites (D-10) -- not from the stale 2026-09-20 record, which omitted file(1)
// entirely.
//
// /usr/share/poppler is kept CONSERVATIVELY: pdfinfo opens it (glyph/cmap
// tables) on a real PDF during the D-10 measurement, even though a single
// ASCII-metadata fixture worked without it (research Assumption A1) -- an
// unused grant costs nothing security-relevant, and removing it risks a
// silent mis-decode of a non-ASCII title/author field that still exits 0.
//
// /etc/magic and /usr/share/misc are deliberately NOT granted: both were
// proven unnecessary by removal. file(1) reaches its compiled-in magic
// database through the already-granted /usr/lib (the resolved symlink
// target of /usr/share/misc/magic.mgc), and /etc/magic's absence produces
// only a discarded stderr warning -- the stdout MIME answer this package
// parses is unaffected either way.
var probeReadOnly = []string{
	"/lib",
	"/usr/lib",
	"/usr/share/ghostscript",
	"/usr/share/color",
	"/usr/share/fonts",
	"/usr/share/poppler",
	"/var/lib/ghostscript",
	"/etc/ld.so.cache",
	"/etc/localtime",
	"/etc/papersize",
}

// probeEngines is every binary probe's job-path invokes: gs (both PDF
// passes), pdfinfo (page count), unzip (OOXML listing and extraction), file
// (OOXML part and image classification) -- six call sites, four binaries.
// Static and unconditional, for EVERY sanitized format, so one ruleset
// serves the whole task (research Pattern 2): a PDF job never touches
// unzip/file and an OOXML job never touches gs/pdfinfo, but granting all
// four unconditionally avoids a second, format-conditional ruleset-building
// path that would need its own test.
var probeEngines = []string{"gs", "pdfinfo", "unzip", "file"}

// WithSandbox returns c with Sandbox set to a *engineSandbox built from
// helper -- mirrors OCRConverter.WithSandbox's own shape: a method rather
// than a ConfinedSanitize-style constructor, because SanitizeConverter also
// carries MaxPages, and this lets cmd/probe-worker keep configuring it in
// one place: buildSanitizeConverter(...).WithSandbox(helper).
func (c SanitizeConverter) WithSandbox(helper []string) SanitizeConverter {
	c.Sandbox = newEngineSandbox(helper)
	return c
}

// exec builds this job's engineExec from outPath's directory -- the ONE
// ruleset shared by every probe engine call site of this job, whichever
// format (PDF, OOXML or image) it ends up taking. TMPDIR is set in the
// ENGINE's own environment (engineEnv(jobDir)), never as a process-wide
// os.Setenv on the worker: the worker's own environment is never touched,
// so the next job's os.MkdirTemp(os.TempDir(), ...) is unaffected and
// concurrent tasks cannot race on it.
func (c SanitizeConverter) exec(outPath string) engineExec {
	jobDir := filepath.Dir(outPath)
	return c.Sandbox.forJobRW(jobDir, probeReadWrite, probeReadOnly, probeEngines).withEnv(engineEnv(jobDir))
}

// ProbeConcurrencyGuard is D-03's guard, applied to probe: keyed on the
// GRANT SET (sharedTmpGuard checks whether probeReadWrite contains the
// shared /tmp), not on the class name. A no-op today because probeReadWrite
// is empty (D-05) -- called anyway, unconditionally, so re-adding /tmp to
// probe at some future point trips this guard by construction rather than
// by someone remembering to re-add a check that was removed here.
func ProbeConcurrencyGuard(c SanitizeConverter, concurrency int, concurrencyEnv string) error {
	return sharedTmpGuard(probeReadWrite, c.Sandbox, concurrency, concurrencyEnv)
}

// gsTextArgs is the txtwrite pass the preflight judges gs's output by:
// ghostscript's own text extractor, run directly (not through the two-pass
// sanitize path) so the preflight can prove the RAW input is readable, and
// -- run against a job's already-sanitized output -- that the production
// two-pass path preserved body text through TMPDIR and the relocated
// scratch directory. Measured 2026-09-26 against the real probe-worker
// image: "Body text that must survive sanitization intact." survives the
// round trip verbatim.
func gsTextArgs(pdfPath string) []string {
	return []string{
		"-q", "-dNOPAUSE", "-dBATCH", "-dSAFER",
		"-sDEVICE=txtwrite",
		"-sOutputFile=-",
		pdfPath,
	}
}

// probePreflightDOCXContentType is the REAL WordprocessingML main-part
// content type -- not the "application/xml" shortcut some unit tests use --
// so the preflight fixture matches what a production docx upload actually
// declares.
const probePreflightDOCXContentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"

// probePreflightDOCX builds a minimal, two-part OOXML package -- no .rels at
// all -- carrying marker as body text inside word/document.xml. Built with
// archive/zip directly (this is production code, not a test helper): a
// package this small is exactly what TestSanitizedPackageWithoutItsDocumentIsRejected's
// own "honest input" case already proves sanitizeOOXML/verifyOOXML accept,
// with no _rels/.rels needed.
func probePreflightDOCX(marker string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name, content string) {
		// Writing into an in-memory bytes.Buffer through archive/zip cannot
		// fail short of an out-of-memory condition -- the same convention
		// ocrPreflightPDF's bytes.Buffer use already relies on in this
		// package, so the error is not checked here either.
		w, _ := zw.Create(name)
		_, _ = io.WriteString(w, content)
	}
	write("[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`+
		`<Override PartName="/word/document.xml" ContentType="`+probePreflightDOCXContentType+`"/>`+
		`</Types>`)
	write("word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">`+
		`<w:body><w:p><w:r><w:t>`+marker+`</w:t></w:r></w:p></w:body></w:document>`)
	_ = zw.Close()
	return buf.Bytes()
}

// probePreflightJPEG encodes a tiny, solid-colour JPEG -- real enough that
// image.Decode, sanitizeImage's own magic-byte sniff and file(1)'s libmagic
// all agree on it, with no marker needed: the image route is judged by MIME
// type alone (sufficiency step (g), effectiveness's "not image/jpeg").
func probePreflightJPEG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	var buf bytes.Buffer
	// Same in-memory-buffer convention as probePreflightDOCX: jpeg.Encode
	// against a bytes.Buffer cannot fail for a 4x4 RGBA source.
	_ = jpeg.Encode(&buf, img, nil)
	return buf.Bytes()
}

// ProbePreflight proves the four probe engines actually run, under the
// ruleset c would build for a job, along every route a real job mix takes --
// PDF (gs x2, pdfinfo), OOXML (unzip x2), image (file) -- plus the negative
// run for each, before any job depends on it. Judged by output CONTENT in
// every direction (CONF-04): gs/pdfinfo/unzip fail LOUDLY when denied
// (D-10 measurement), but file(1) exits 0 and prints a non-MIME answer, so
// the exit status is never what decides this.
//
// nil when c is unconfined: nothing to prove for a deployment that has
// deliberately turned confinement off.
func ProbePreflight(ctx context.Context, c SanitizeConverter) error {
	if !c.Sandbox.confines() {
		return nil
	}

	// probe grants no /tmp at all (D-05): newPreflightWorkspace's ordinary
	// os.TempDir()-based outside directory already lies outside every grant,
	// but requireOutsideGrants is what PROVES that at run time rather than
	// assuming it from the path string alone.
	w, cleanup, err := newPreflightWorkspace("probe")
	if err != nil {
		return err
	}
	defer cleanup()

	if err := w.requireOutsideGrants(probeReadWrite, probeReadOnly); err != nil {
		return err
	}

	marker, err := preflightMarker()
	if err != nil {
		return err
	}

	if err := probePreflightSufficiency(ctx, c, w, marker); err != nil {
		return err
	}
	return probePreflightEffectiveness(ctx, c, w, marker)
}

// probePreflightSufficiency proves every route succeeds INSIDE the job
// directory. Split from probePreflightEffectiveness so a test can run this
// half alone against an UNCONFINED converter -- proving the fixtures and
// judgments themselves on the host, with no ruleset involved at all.
func probePreflightSufficiency(ctx context.Context, c SanitizeConverter, w preflightWorkspace, marker string) error {
	x := c.exec(filepath.Join(w.jobDir, "out"))

	// --- PDF route: the production two-pass path, then the raw input ---
	insidePDF, _, err := w.place("in.pdf", ocrPreflightPDF(marker))
	if err != nil {
		return err
	}
	outPDF := filepath.Join(w.jobDir, "out.pdf")
	if err := c.Convert(ctx, insidePDF, outPDF, nil); err != nil {
		return fmt.Errorf("pdf route: the engine cannot run under the sandbox: %w", err)
	}
	sanitizedText, err := x.run(ctx, "gs", gsTextArgs(outPDF)...)
	if err != nil {
		return fmt.Errorf("pdf route: the engine cannot run under the sandbox: %w", err)
	}
	if err := requireContains("gs txtwrite of the sanitized output", sanitizedText, []byte(marker)); err != nil {
		return fmt.Errorf("pdf route: %w", err)
	}

	count, err := probePDFPageCount(ctx, x, insidePDF)
	if err != nil {
		return fmt.Errorf("pdf route: page count: the engine cannot run under the sandbox: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("pdf route: page count: got %d, want 1", count)
	}

	rawText, err := x.run(ctx, "gs", gsTextArgs(insidePDF)...)
	if err != nil {
		return fmt.Errorf("pdf route: the engine cannot run under the sandbox: %w", err)
	}
	if err := requireContains("gs txtwrite of the input", rawText, []byte(marker)); err != nil {
		return fmt.Errorf("pdf route: %w", err)
	}

	// --- OOXML route: sanitized output, then the raw input's listing ---
	insideDOCX, _, err := w.place("in.docx", probePreflightDOCX(marker))
	if err != nil {
		return err
	}
	outDOCX := filepath.Join(w.jobDir, "out.docx")
	if err := c.Convert(ctx, insideDOCX, outDOCX, nil); err != nil {
		return fmt.Errorf("ooxml route: the engine cannot run under the sandbox: %w", err)
	}
	docBlob, err := x.run(ctx, "unzip", "-p", outDOCX, "word/document.xml")
	if err != nil {
		return fmt.Errorf("ooxml route: the engine cannot run under the sandbox: %w", err)
	}
	if err := requireContains("unzip -p of the sanitized output", docBlob, []byte(marker)); err != nil {
		return fmt.Errorf("ooxml route: %w", err)
	}
	listing, err := x.run(ctx, "unzip", "-Z1", insideDOCX)
	if err != nil {
		return fmt.Errorf("ooxml route: the engine cannot run under the sandbox: %w", err)
	}
	if err := requireContains("unzip -Z1 of the input", listing, []byte("word/document.xml")); err != nil {
		return fmt.Errorf("ooxml route: %w", err)
	}

	// --- image route ---
	insideJPG, _, err := w.place("in.jpg", probePreflightJPEG())
	if err != nil {
		return err
	}
	outJPG := filepath.Join(w.jobDir, "out.jpg")
	if err := c.Convert(ctx, insideJPG, outJPG, nil); err != nil {
		return fmt.Errorf("image route: the engine cannot run under the sandbox: %w", err)
	}
	mime, err := x.run(ctx, "file", "--mime-type", "-b", insideJPG)
	if err != nil {
		return fmt.Errorf("image route: the engine cannot run under the sandbox: %w", err)
	}
	if got := strings.TrimSpace(string(mime)); got != "image/jpeg" {
		return fmt.Errorf("image route: file(1) says %q, want image/jpeg", got)
	}

	return nil
}

// probePreflightEffectiveness proves every route is DENIED on the identical
// bytes, placed OUTSIDE the job directory, under the SAME ruleset.
//
// Convert on the outside docx/jpg would prove nothing (comment, not a
// call): the Go side of sanitizeOOXML/sanitizeImage reads its input
// UNCONFINED (D-09 -- probe confines only the external engine execs), and
// the engines themselves only ever read the job-directory OUTPUT of a
// completed Convert. The negative run instead points each engine directly
// at the outside copy, through the job's own ruleset, using the identical
// argv the production path uses.
func probePreflightEffectiveness(ctx context.Context, c SanitizeConverter, w preflightWorkspace, marker string) error {
	x := c.exec(filepath.Join(w.jobDir, "out"))

	_, outsidePDF, err := w.place("in.pdf", ocrPreflightPDF(marker))
	if err != nil {
		return err
	}
	if _, pcErr := probePDFPageCount(ctx, x, outsidePDF); pcErr == nil {
		return fmt.Errorf("pdf route: the engine read a file outside the job directory: " +
			"page count on the outside file succeeded")
	}
	if outsideText, textErr := x.run(ctx, "gs", gsTextArgs(outsidePDF)...); textErr == nil {
		if err := requireLacks("gs txtwrite of the outside file", outsideText, []byte(marker)); err != nil {
			return fmt.Errorf("pdf route: the engine read a file outside the job directory: %w", err)
		}
	}

	_, outsideDOCX, err := w.place("in.docx", probePreflightDOCX(marker))
	if err != nil {
		return err
	}
	if outsideListing, lsErr := x.run(ctx, "unzip", "-Z1", outsideDOCX); lsErr == nil {
		if err := requireLacks("unzip -Z1 of the outside file", outsideListing, []byte("word/document.xml")); err != nil {
			return fmt.Errorf("ooxml route: the engine read a file outside the job directory: %w", err)
		}
	}

	_, outsideJPG, err := w.place("in.jpg", probePreflightJPEG())
	if err != nil {
		return err
	}
	// file(1) exits 0 even when denied (D-10 measurement: "writable, regular
	// file, no read permission") -- the judgment below is on CONTENT alone,
	// never on the error returned here.
	outsideMime, _ := x.run(ctx, "file", "--mime-type", "-b", outsideJPG)
	if got := strings.TrimSpace(string(outsideMime)); got == "image/jpeg" || strings.HasPrefix(got, "image/") {
		return fmt.Errorf("image route: the engine read a file outside the job directory: "+
			"file(1) said %q", got)
	}

	return nil
}
