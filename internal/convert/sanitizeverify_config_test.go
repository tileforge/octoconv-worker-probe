package convert

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// TestPDFCPUWritesNoConfig is the regression for a defect that was invisible
// because it was recovered.
//
// pdfcpu's NewDefaultConfiguration writes a config.yml on first use and calls
// fault.Fail -- a PANIC -- when it cannot. os.UserConfigDir returns
// $HOME/.config without an error whenever HOME is merely SET, and the worker
// runs as nobody, whose HOME on debian is /nonexistent. Every sanitize job
// therefore panicked inside api.ReadContextFile on the verification path;
// asynq recovered it, retried, exhausted the budget and left the job ACTIVE, so
// a client saw a job that never finished rather than a failure.
//
// Found by running the e2e tier, not by reading anything.
func TestPDFCPUWritesNoConfig(t *testing.T) {
	if model.ConfigPath != "disable" {
		t.Fatalf("model.ConfigPath = %q, want \"disable\" -- pdfcpu will try to write a config.yml "+
			"under the process's HOME and PANIC when it cannot", model.ConfigPath)
	}
}

// TestVerifyPDFSurvivesAnUnwritableHome reproduces the deployment shape
// directly: a child process with HOME pointing somewhere it cannot write, which
// is what the container gives this code.
//
// It runs the check in a SUBPROCESS because HOME is process-global and the
// panic it guards against happens during pdfcpu's one-time initialisation.
func TestVerifyPDFSurvivesAnUnwritableHome(t *testing.T) {
	if os.Getenv("OCTOCONV_PDFCPU_HOME_CHILD") == "1" {
		// In the child: exercise the same entry point the worker uses, on a
		// REAL PDF. The first version of this test used a file containing "not
		// a pdf" and passed under inversion -- verifySanitized rejects it
		// before pdfcpu is ever reached, so it proved nothing. Caught by
		// inverting the fix, which is the only reason it is not still here.
		src := filepath.Join("testdata", "ocr", "multipage_text.pdf")
		raw, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		path := filepath.Join(t.TempDir(), "in.pdf")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		// Any verdict is acceptable -- this fixture is not a sanitizer OUTPUT,
		// so it may well be reported as unverifiable. A PANIC is not.
		_, _ = verifySanitized(t.Context(), engineExec{}, "pdf", path)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run", "TestVerifyPDFSurvivesAnUnwritableHome", "-test.v")
	cmd.Env = append(os.Environ(),
		"OCTOCONV_PDFCPU_HOME_CHILD=1",
		"HOME=/nonexistent",
		"XDG_CONFIG_HOME=/nonexistent/.config",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the child failed with HOME=/nonexistent: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "config problem") || strings.Contains(string(out), "panic") {
		t.Fatalf("pdfcpu panicked under an unwritable HOME -- every sanitize job would be retried and "+
			"then left active:\n%s", out)
	}
}
