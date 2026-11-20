package convert

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// probeReadWrite is empty ON PURPOSE (D-05): a /tmp entry here re-arms the
// D-03 ProbeConcurrencyGuard and needs the D-04 sweep machinery all over
// again. Re-measure with scripts/sandbox-paths-measure.sh rather than
// editing this expectation.
func TestProbeReadWriteSetIsTheMeasuredOne(t *testing.T) {
	if len(probeReadWrite) != 0 {
		t.Fatalf("probeReadWrite has %d entries, want 0 -- D-05 measured that ghostscript honours "+
			"TMPDIR and zero opens land under bare /tmp; a /tmp entry here re-arms the D-03 "+
			"ProbeConcurrencyGuard and needs the D-04 sweep machinery all over again. Re-measure "+
			"with scripts/sandbox-paths-measure.sh rather than editing this expectation",
			len(probeReadWrite))
	}
}

// The measured set, pinned. Every entry here is proven by
// docs/SANDBOX-PATHS.md's "probe" section, re-measured from the
// code's six exec sites (D-10) -- not the stale 2026-09-20 record, which
// omitted file(1) entirely.
func TestProbeReadOnlySetIsTheMeasuredOne(t *testing.T) {
	want := []string{
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
	if len(probeReadOnly) != len(want) {
		t.Fatalf("probeReadOnly has %d paths, this test knows %d -- re-measure with "+
			"scripts/sandbox-paths-measure.sh rather than editing the expectation",
			len(probeReadOnly), len(want))
	}
	for i := range want {
		if probeReadOnly[i] != want[i] {
			t.Errorf("path %d is %q, want %q", i, probeReadOnly[i], want[i])
		}
	}
	for _, p := range probeReadOnly {
		if !filepath.IsAbs(p) {
			t.Errorf("%q is not absolute; the helper grants paths verbatim", p)
		}
	}
}

func TestProbeEnginesAreTheMeasuredOnes(t *testing.T) {
	want := []string{"gs", "pdfinfo", "unzip", "file"}
	if len(probeEngines) != len(want) {
		t.Fatalf("probeEngines has %d entries, this test knows %d -- re-measure with "+
			"scripts/sandbox-paths-measure.sh rather than editing the expectation",
			len(probeEngines), len(want))
	}
	for i := range want {
		if probeEngines[i] != want[i] {
			t.Errorf("probeEngines[%d] = %q, want %q", i, probeEngines[i], want[i])
		}
	}
}

// D-10 measured /etc/magic and /usr/share/misc unnecessary by removal:
// file(1) reaches its compiled magic through the already-granted /usr/lib.
// Neither path -- nor any ancestor of either, beyond what is already
// pinned above -- may be granted.
func TestProbeGrantsNeitherEtcMagicNorUsrShareMisc(t *testing.T) {
	forbidden := []string{"/etc/magic", "/usr/share/misc"}
	for _, f := range forbidden {
		for _, g := range probeReadOnly {
			if g == f {
				t.Errorf("probeReadOnly grants %q directly -- D-10 measured it unnecessary", f)
			}
			if strings.HasPrefix(f, g+"/") {
				t.Errorf("probeReadOnly grants %q, an ancestor of %q -- that re-introduces "+
					"exactly the grant D-10 measured unnecessary", g, f)
			}
		}
	}
}

// SanitizeConverter stays comparable: WithSandbox(nil) equals the zero
// value, a confined converter does not, and the type is usable as a map
// key -- fails to COMPILE if Sandbox stops being a pointer.
func TestSanitizeConverterStaysComparable(t *testing.T) {
	var a, b SanitizeConverter
	if a != b {
		t.Fatal("two zero converters differ")
	}
	if got := (SanitizeConverter{}).WithSandbox(nil); got != a {
		t.Error("WithSandbox(nil) does not equal the zero value")
	}

	confined := SanitizeConverter{}.WithSandbox([]string{"/usr/local/bin/probe-worker", "__sandbox-exec"})
	if confined == a {
		t.Error("a confined converter equals an unconfined one, so the field is not being compared at all")
	}
	seen := map[SanitizeConverter]bool{a: true}
	if !seen[b] {
		t.Error("the zero converter is not its own map key")
	}
}

// ProbeConcurrencyGuard is keyed on the GRANT SET, not the class name --
// probeReadWrite is empty (D-05), so this never trips regardless of
// concurrency.
func TestProbeConcurrencyGuardDoesNotTriggerWithoutSharedTmp(t *testing.T) {
	c := SanitizeConverter{}.WithSandbox([]string{"/usr/local/bin/probe-worker", "__sandbox-exec"})
	if err := ProbeConcurrencyGuard(c, 4, "PROBE_WORKER_CONCURRENCY"); err != nil {
		t.Errorf("ProbeConcurrencyGuard with an empty probeReadWrite tripped at concurrency 4: %v", err)
	}
}

func TestProbePreflightUnconfinedProvesNothing(t *testing.T) {
	if err := ProbePreflight(context.Background(), SanitizeConverter{}); err != nil {
		t.Errorf("ProbePreflight on an unconfined converter returned %v, want nil", err)
	}
}

// TestProbePreflightSufficiencyUnconfined proves the fixtures and content
// judgments THEMSELVES on the host, with no ruleset involved at all -- the
// unconfined half of the split ProbePreflight is built from (research
// Wave 0: "so Task 2 can run sufficiency unconfined").
func TestProbePreflightSufficiencyUnconfined(t *testing.T) {
	for _, bin := range []string{"gs", "pdfinfo", "unzip", "file"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found on PATH, skipping real-binary test", bin)
		}
	}

	c := SanitizeConverter{MaxPages: 200}
	w, cleanup, err := newPreflightWorkspace("probe-sufficiency")
	if err != nil {
		t.Fatalf("newPreflightWorkspace: %v", err)
	}
	defer cleanup()

	marker, err := preflightMarker()
	if err != nil {
		t.Fatalf("preflightMarker: %v", err)
	}

	if err := probePreflightSufficiency(context.Background(), c, w, marker); err != nil {
		t.Errorf("probePreflightSufficiency on an unconfined converter: %v", err)
	}
}

// ---- fakes shared by the two tests below ----

// probeFakeEngineSet writes gs/pdfinfo/unzip/file fakes into a fresh
// directory and prepends it to PATH -- gs echoes a fixed line (never a
// real ps2write output; sanitizePDF's own "intermediate missing" check is
// expected to fire, and that is fine: these two tests assert on what was
// GRANTED and on the recorded environment, never on Convert's outcome).
func probeFakeEngineSet(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	fakeEngine(t, dir, "gs", "echo fake-gs-output\n")
	fakeEngine(t, dir, "pdfinfo", "echo 'Pages: 1'\n")
	fakeEngine(t, dir, "unzip", "echo fake-unzip\n")
	fakeEngine(t, dir, "file", "echo application/octet-stream\n")
	pathWith(t, dir)
}

// TestSanitizeConvertGrantsTheJobDirOnly proves SanitizeConverter.Convert
// builds exactly one engineExec per job, granting the job directory alone
// as writable (no rw:/tmp -- probeReadWrite is empty) and probeReadOnly's
// static set as read-only, and that both pdfinfo (page ceiling) and gs
// (ps2write pass) actually run under it.
func TestSanitizeConvertGrantsTheJobDirOnly(t *testing.T) {
	probeFakeEngineSet(t)
	helper, calls := fakeSandboxHelper(t)

	jobDir := t.TempDir()
	in := filepath.Join(jobDir, "in.pdf")
	if err := os.WriteFile(in, []byte("%PDF-1.4 placeholder"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out := filepath.Join(jobDir, "out.pdf")

	c := SanitizeConverter{MaxPages: 5}.WithSandbox(helper)
	// The fixture is not a real PDF and the fake gs writes nothing to its
	// -sOutputFile= path, so Convert is expected to fail past the first gs
	// call -- what this test checks is what was GRANTED, not the outcome.
	_ = c.Convert(context.Background(), in, out, nil)

	invocations := calls()
	if len(invocations) == 0 {
		t.Fatal("no engine invocations recorded")
	}

	sawPdfinfo, sawGS := false, false
	for _, argv := range invocations {
		sep := indexOf(argv, "--")
		if sep < 0 {
			t.Fatalf("no -- separator in %v", argv)
		}
		var rw, ro []string
		for _, tok := range argv[:sep] {
			switch {
			case strings.HasPrefix(tok, "rw:"):
				rw = append(rw, strings.TrimPrefix(tok, "rw:"))
			case strings.HasPrefix(tok, "ro:"):
				ro = append(ro, strings.TrimPrefix(tok, "ro:"))
			}
		}
		if len(rw) != 1 || rw[0] != jobDir {
			t.Errorf("invocation %v: rw tokens = %v, want exactly [%s]", argv, rw, jobDir)
		}
		if indexOf(ro, "/usr/share/poppler") < 0 {
			t.Errorf("invocation %v: ro tokens %v missing /usr/share/poppler", argv, ro)
		}
		if sep+1 < len(argv) {
			switch filepath.Base(argv[sep+1]) {
			case "pdfinfo":
				sawPdfinfo = true
			case "gs":
				sawGS = true
			}
		}
	}
	if !sawPdfinfo {
		t.Error("pdfinfo never ran -- the page-ceiling guard did not use this job's engineExec")
	}
	if !sawGS {
		t.Error("gs never ran -- sanitizePDF did not use this job's engineExec")
	}
}

// TestSanitizeEnginesGetAJobScopedTmpdirAndNoSecrets proves TMPDIR travels in
// the ENGINE's own environment (engineEnv(jobDir), via c.exec's withEnv), is
// scoped per job, and that the environment replacement scrubs everything
// else -- including a secret the worker process itself carries.
func TestSanitizeEnginesGetAJobScopedTmpdirAndNoSecrets(t *testing.T) {
	t.Setenv("DATABASE_URL", "secret-canary")
	beforeTmpdir := os.Getenv("TMPDIR")

	engineDir := t.TempDir()
	logPath := filepath.Join(engineDir, "gs.envlog")
	gsScript := "{ printf 'TMPDIR=%s DATABASE_URL=%s\\n' \"$TMPDIR\" \"$DATABASE_URL\"; } >> \"" +
		logPath + "\"\n"
	fakeEngine(t, engineDir, "gs", gsScript)
	fakeEngine(t, engineDir, "pdfinfo", "echo 'Pages: 1'\n")
	fakeEngine(t, engineDir, "unzip", "echo fake-unzip\n")
	fakeEngine(t, engineDir, "file", "echo application/octet-stream\n")
	pathWith(t, engineDir)

	c := SanitizeConverter{MaxPages: 5}

	runOnce := func() string {
		jobDir := t.TempDir()
		in := filepath.Join(jobDir, "in.pdf")
		if err := os.WriteFile(in, []byte("%PDF-1.4 placeholder"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		out := filepath.Join(jobDir, "out.pdf")
		_ = c.Convert(context.Background(), in, out, nil)
		return jobDir
	}

	jobDirA := runOnce()
	jobDirB := runOnce()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read gs env log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("gs recorded %d invocation(s), want at least 2: %v", len(lines), lines)
	}

	for i, jobDir := range []string{jobDirA, jobDirB} {
		want := "TMPDIR=" + jobDir + " "
		if !strings.HasPrefix(lines[i], want) {
			t.Errorf("invocation %d = %q, want prefix %q", i, lines[i], want)
		}
		if strings.Contains(lines[i], "secret-canary") {
			t.Errorf("invocation %d leaked DATABASE_URL: %q", i, lines[i])
		}
	}
	if lines[0] == lines[1] {
		t.Error("both invocations recorded the same TMPDIR -- two different job directories must " +
			"produce different TMPDIR values")
	}

	if got := os.Getenv("TMPDIR"); got != beforeTmpdir {
		t.Errorf("worker process TMPDIR changed from %q to %q -- TMPDIR must never be set "+
			"process-wide", beforeTmpdir, got)
	}
}

// ---- sandbox-fault preservation, every wrap point ----

// probeWrapPointFixtures builds one job directory holding a placeholder
// input for each of the three formats the table below exercises. Their
// CONTENT does not matter for the PDF/OOXML rows: the failing sandbox
// helper aborts before pdfinfo/gs/unzip ever run. The PNG must actually
// decode, because verifyImage's in-process decode runs BEFORE the file(1)
// exec this table means to fail.
func probeWrapPointFixtures(t *testing.T) (jobDir, pdfPath, docxPath, pngPath string) {
	t.Helper()
	jobDir = t.TempDir()

	pdfPath = filepath.Join(jobDir, "in.pdf")
	if err := os.WriteFile(pdfPath, []byte("%PDF-1.4 placeholder"), 0o600); err != nil {
		t.Fatalf("write pdf fixture: %v", err)
	}
	docxPath = filepath.Join(jobDir, "in.docx")
	if err := os.WriteFile(docxPath, []byte("PK placeholder"), 0o600); err != nil {
		t.Fatalf("write docx fixture: %v", err)
	}

	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	pngPath = filepath.Join(jobDir, "in.png")
	if err := os.WriteFile(pngPath, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write png fixture: %v", err)
	}
	return jobDir, pdfPath, docxPath, pngPath
}

// probeWrapPointCases is the table shared by both tests below: page count
// (probePDFPageCount), the ps2write pass (sanitizePDF), the OOXML unzip
// listing (verifyOOXML), and the image file(1) classify (verifyImage) --
// every wrap point research Pattern 3 named.
func probeWrapPointCases(x engineExec, jobDir, pdfPath, docxPath, pngPath string) []struct {
	name string
	run  func() error
} {
	return []struct {
		name string
		run  func() error
	}{
		{"page count", func() error {
			_, err := probePDFPageCount(context.Background(), x, pdfPath)
			return err
		}},
		{"ps2write pass", func() error {
			_, err := sanitizePDF(context.Background(), x, pdfPath, filepath.Join(jobDir, "out.pdf"))
			return err
		}},
		{"unzip listing", func() error {
			_, err := verifyOOXML(context.Background(), x, "docx", docxPath)
			return err
		}},
		{"file classify", func() error {
			_, err := verifyImage(context.Background(), x, "png", pngPath)
			return err
		}},
	}
}

// TestProbeSandboxFaultSurvivesEveryWrapPoint proves a node that cannot
// establish the sandbox (helper exit 78, sandbox.SetupExit) is never
// misclassified as a client-file defect at any of the four wrap points --
// this is the sentinel-preservation fix itself (research Pattern 3).
func TestProbeSandboxFaultSurvivesEveryWrapPoint(t *testing.T) {
	jobDir, pdfPath, docxPath, pngPath := probeWrapPointFixtures(t)
	engineDir := t.TempDir()
	for _, name := range probeEngines {
		fakeEngine(t, engineDir, name, "echo should-never-run\n")
	}
	pathWith(t, engineDir)

	x := (&engineSandbox{Helper: failingSandboxHelper(t, 78), Confine: true}).
		forJob(jobDir, probeReadOnly, probeEngines)

	for _, tc := range probeWrapPointCases(x, jobDir, pdfPath, docxPath, pngPath) {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if !errors.Is(err, ErrEngineSandboxUnavailable) {
				t.Errorf("%v does not wrap ErrEngineSandboxUnavailable", err)
			}
			if errors.Is(err, ErrSanitizeMalformedInput) {
				t.Errorf("%v was misclassified as ErrSanitizeMalformedInput", err)
			}
			if errors.Is(err, ErrSanitizeUnverifiable) {
				t.Errorf("%v was misclassified as ErrSanitizeUnverifiable", err)
			}
		})
	}
}

// TestProbePlainEngineFailureKeepsItsClassification is the control: the
// SAME table, with a helper that fails for a REASON OTHER than sandbox
// setup (exit 1), must still classify exactly as before this plan -- proving
// the previous test passes BECAUSE of the sentinel check, not because these
// call sites happen to be sentinel-blind.
func TestProbePlainEngineFailureKeepsItsClassification(t *testing.T) {
	jobDir, pdfPath, docxPath, pngPath := probeWrapPointFixtures(t)
	engineDir := t.TempDir()
	for _, name := range probeEngines {
		fakeEngine(t, engineDir, name, "echo should-never-run\n")
	}
	pathWith(t, engineDir)

	x := (&engineSandbox{Helper: failingSandboxHelper(t, 1), Confine: true}).
		forJob(jobDir, probeReadOnly, probeEngines)

	want := map[string]error{
		"page count":    ErrSanitizeMalformedInput,
		"ps2write pass": ErrSanitizeMalformedInput,
		"unzip listing": ErrSanitizeUnverifiable,
		"file classify": ErrSanitizeUnverifiable,
	}

	for _, tc := range probeWrapPointCases(x, jobDir, pdfPath, docxPath, pngPath) {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if wantErr := want[tc.name]; !errors.Is(err, wantErr) {
				t.Errorf("%v does not wrap %v", err, wantErr)
			}
			if errors.Is(err, ErrEngineSandboxUnavailable) {
				t.Errorf("%v: a plain engine failure must never carry the sandbox sentinel", err)
			}
		})
	}
}
