package convert

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"

	"github.com/tileforge/octoconv-worker-probe/internal/sandbox"
)

// engineSandbox is what a converter needs to run its engine confined: the
// helper argv prefix, and whether a filesystem ruleset is wanted at all.
//
// Held by POINTER in converters, and nil-safe in every method below, so that
// adding it does not make an exported converter non-comparable. LibvipsConverter
// was an empty struct and could be compared with ==; a slice field would have
// taken that away silently, and the property is easier to keep than to restore
// once something depends on it (codex, PR #28). A nil *engineSandbox means "run
// the engine directly", which is the zero value every test wants.
type engineSandbox struct {
	// Helper is the argv prefix from sandbox.ResolveHelper. Empty means the
	// engine is executed directly.
	Helper []string
	// Confine asks for the filesystem ruleset. False with a non-empty Helper
	// is meaningful for an engine that also carries a resource limit -- see
	// TectonicConverter -- and means "run through the helper, restrict
	// nothing", because an EMPTY ruleset denies everything rather than nothing.
	Confine bool
}

// wrapEngine turns (engine name, args) into the command actually executed.
//
// It resolves the engine through PATH here rather than leaving it to the
// helper, so a missing binary is reported as a missing binary instead of as a
// sandbox that failed to establish -- two failures an operator would otherwise
// have to tell apart from one exit status.
func (s *engineSandbox) wrapEngine(name string, spec []string, args []string) (string, []string, error) {
	enginePath, err := exec.LookPath(name)
	if err != nil {
		return "", nil, fmt.Errorf("locate engine %s: %w", name, err)
	}
	if s == nil || len(s.Helper) == 0 {
		return enginePath, args, nil
	}
	wrapped := append(append(append(
		append([]string{}, s.Helper[1:]...),
		spec...),
		"--", enginePath), args...)
	return s.Helper[0], wrapped, nil
}

// enginePathFor is wrapEngine's lookup alone, for a spec builder that needs
// the resolved binary before the argv is assembled -- every ruleset has to
// grant the engine its own executable, which no trace reports reliably.
func enginePathFor(name string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("locate engine %s: %w", name, err)
	}
	return p, nil
}

// confines reports whether a filesystem ruleset is wanted. Nil-safe for the
// same reason wrapEngine is: a converter built without a sandbox is the
// ordinary case in tests.
func (s *engineSandbox) confines() bool { return s != nil && s.Confine }

// spec is a thin alias so converters read as "paths, then spec" rather than
// repeating the SpecWith call with an empty Limits every time.
func spec(rw, ro []string) []string {
	return specWithSockets(rw, nil, ro)
}

// specWithSockets is spec with a third grant kind: the directories beneath
// which the engine may create a Unix-domain socket and nothing else (a
// sock: token, sandbox.Paths.Socket). With a nil sock it renders exactly the
// tokens spec always did, so every class that has no such directory keeps a
// byte-identical token stream.
func specWithSockets(rw, sock, ro []string) []string {
	return sandbox.Paths{ReadWrite: rw, Socket: sock, ReadOnly: ro}.SpecWith(sandbox.Limits{})
}

// ErrEngineSandboxUnavailable is that status, classified.
//
// The helper exited sandbox.SetupExit, so the engine never ran at all -- a
// property of THIS NODE (a Landlock ruleset it could not apply), never of the
// client's file. Mirrors ErrTeXSandboxUnavailable (tectonic.go); a plain
// converter that reads/writes files and never runs a program-as-input has no
// CPU-exhaustion or engine-starved cousin to it, so this is the only sentinel
// engineExec needs.
var ErrEngineSandboxUnavailable = errors.New("engine sandbox could not be established")

// newEngineSandbox builds the sandbox an engineExec wraps around a job.
//
// nil for an empty helper, so a converter built with one stays equal to the
// zero value -- ConfinedLibvips(nil) and LibvipsConverter{} must compare
// equal, and a non-nil *engineSandbox with Confine:false would not.
func newEngineSandbox(helper []string) *engineSandbox {
	if len(helper) == 0 {
		return nil
	}
	return &engineSandbox{Helper: helper, Confine: true}
}

// engineExec is one job's ruleset, built once and shared by every engine
// invocation that job makes.
//
// Splitting "build the ruleset" (forJob) from "run one command under it"
// (run) is what lets a class with several call sites -- OCR's tesseract AND
// pdfinfo AND pdftoppm AND pdftotext -- share one spec instead of rebuilding
// it, argument by argument, at each site.
type engineExec struct {
	sandbox *engineSandbox
	spec    []string
	// env is the environment the ENGINE gets. nil (every class before this
	// one, and every call site that never opts in) means "inherit this
	// process's environment" -- run's existing runCommandAs path, unchanged.
	// Non-nil REPLACES the environment entirely: it is not merged with the
	// process's own, because a merge would still leak whatever the caller
	// forgot to scrub into the engine's own /proc/self/environ (engineEnv's
	// doc comment says what that does and does not close).
	env []string
}

// withEnv returns a copy of e with its engine environment replaced by env.
// Copies the slice header only (env itself is not mutated in place by any
// caller), so two engineExec values built from the same forJobRW call never
// alias each other's environment.
func (e engineExec) withEnv(env []string) engineExec {
	e.env = append([]string{}, env...)
	return e
}

// forJob builds one job's engineExec: readOnly is the class's own measured
// set (e.g. pandocReadOnly), engines is every binary name that job's engine
// may invoke -- each resolved through PATH and added to the ruleset, because
// none of them appear in a filesystem trace (they are execve'd, not opened).
//
// When s does not confine (nil, or Confine: false), the returned engineExec
// carries no spec at all: wrapEngine then runs the engine directly for a nil
// sandbox, and passes an EMPTY spec through the helper for one with
// Confine: false -- "run through the helper, restrict nothing" (tectonic's
// own CPU-budget-without-filesystem-ruleset shape).
//
// The job directory is the ONLY writable path, and it is deliberately the
// ONLY path granted at all beyond the class's static set and its engines --
// unlike libvipsSpec, the input's own directory is never granted separately.
// The worker materialises every input inside the job directory before
// Convert ever runs, so a file anywhere else has no legitimate reason to be
// read, and the preflight's negative run depends on exactly that being
// denied.
func (s *engineSandbox) forJob(jobDir string, readOnly, engines []string) engineExec {
	return s.forJobRW(jobDir, nil, readOnly, engines)
}

// forJobRW is forJob with a class-specific extra writable set: every entry
// of extraRW is a path ALL tasks of the class share, not merely this job's
// own directory -- which is exactly what CONF-06 decides about (html's
// shared /tmp). The writable list is jobDir followed by extraRW, in the
// order given; forJob is this function called with a nil extraRW, so its
// token stream (a single rw: entry, the job directory) stays byte-identical
// for every class that has no such shared path.
func (s *engineSandbox) forJobRW(jobDir string, extraRW, readOnly, engines []string) engineExec {
	return s.forJobRWSock(jobDir, extraRW, nil, readOnly, engines)
}

// forJobRWSock is forJobRW with a class-specific socket-only set: every entry
// of sockDirs grants creating a Unix socket beneath it and nothing else -- no
// read, no write, no unlink (70-01 decision, measured in 70-02). soffice binds
// its single-instance socket under /tmp whatever TMPDIR says. forJobRW is this
// function called with a nil sockDirs.
func (s *engineSandbox) forJobRWSock(jobDir string, extraRW, sockDirs, readOnly, engines []string) engineExec {
	if !s.confines() {
		return engineExec{sandbox: s}
	}
	rw := append([]string{jobDir}, extraRW...)
	ro := append([]string{}, readOnly...)
	for _, name := range engines {
		// A name that does not resolve is skipped, not an error here: it
		// cannot be exec'd either way, and the call site that actually needs
		// it reports "locate engine" through wrapEngine when it tries.
		if p, err := exec.LookPath(name); err == nil {
			ro = append(ro, p)
		}
	}
	return engineExec{sandbox: s, spec: specWithSockets(rw, sockDirs, ro)}
}

// engineEnv is the allowlisted environment an engine gets when its class
// replaces the inherited one (engineExec.withEnv). PATH/HOME/LANG/LC_ALL are
// copied when set (an unset one stays unset, never invented); TMPDIR is
// appended only when tmpDir is non-empty, so a caller that has nothing
// job-scoped to point it at can still get the allowlist without a
// meaningless TMPDIR=.
//
// Mirrors tectonicEnv's own allowlist (tectonic.go), the same answer to the
// same leak.
//
// What the scrub closes is the ENGINE's OWN /proc/self/environ: that file is
// the environment the engine was started with, so handing the worker's on
// would hand over the database URL and the S3 keys (measured for tectonic before
// it was confined, and for html). Replacing the environment empties that file
// whatever the ruleset grants; tectonic's ruleset, for one, grants no /proc at
// all (tectonicSystemReadOnly).
//
// It does not decide whether a confined engine can open OTHER processes'
// /proc/<pid>/environ -- the worker's and PID 1's, which do hold the secrets.
// That depends on the class's /proc grant and was measured, not assumed (N3,
// scripts/document-sandbox-measure.sh; 70-08, SANDBOX-PATHS.md "/proc и другие
// процессы"): with /proc granted whole (veraPDF before 70-08, html today)
// opening them was denied, while the same processes' cmdline and status
// opened. The denial is at the open of environ itself and is not something the
// filesystem grant provides (the mechanism is inferred to be Landlock's ptrace
// check; the denial is what was measured), so a class should not lean on it:
// its /proc grant is the thing it controls.
func engineEnv(tmpDir string) []string {
	keep := []string{"PATH", "HOME", "LANG", "LC_ALL"}
	env := make([]string, 0, len(keep)+1)
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	if tmpDir != "" {
		env = append(env, "TMPDIR="+tmpDir)
	}
	return env
}

// sharedTmpDir is the one path a class's writable set can name that is NOT
// scoped to a single job -- the container's own /tmp, shared by every task
// that ever runs in it.
const sharedTmpDir = "/tmp"

// sharedTmpGuard is D-03: a confined class whose writable set grants
// sharedTmpDir is safe ONLY when exactly one task runs at a time in that
// container (D-01). Concurrency above 1 would let two tasks read and write
// each other's files there, and so would a value below 1: asynq treats
// Concurrency below 1 as runtime.NumCPU(), not as one. nil when s does not
// confine, when readWrite does not contain sharedTmpDir at all (the guard is
// keyed on the GRANT SET, not on a class name, so it applies to any class that
// ever grants /tmp -- CONF-06), or when concurrency is exactly 1. The value is
// refused, never clamped: a quiet correction would hide a misconfiguration.
func sharedTmpGuard(readWrite []string, s *engineSandbox, concurrency int, concurrencyEnv string) error {
	if !s.confines() || !slices.Contains(readWrite, sharedTmpDir) || concurrency == 1 {
		return nil
	}
	if concurrency < 1 {
		return fmt.Errorf(
			"%s=%d with the sandbox enabled: asynq treats a concurrency below 1 as the CPU count, "+
				"so several tasks would run over the container's shared %s, which this class's ruleset "+
				"grants read-write and each task sweeps; set %s=1 and scale with replicas (CONF-06)",
			concurrencyEnv, concurrency, sharedTmpDir, concurrencyEnv,
		)
	}
	return fmt.Errorf(
		"%s=%d with the sandbox enabled: this class's ruleset grants the container's shared %s "+
			"read-write, so concurrent tasks could read each other's files there; set %s=1 and "+
			"scale with replicas (CONF-06)",
		concurrencyEnv, concurrency, sharedTmpDir, concurrencyEnv,
	)
}

// run wraps and executes one engine invocation under e's ruleset, naming the
// ENGINE (not the helper) in every error runCommandAs produces, and turning a
// helper-exited-78 failure into the retryable ErrEngineSandboxUnavailable
// rather than an ordinary engine failure.
//
// e.env nil (every class before html, and every call site that never opts
// in) keeps today's runCommandAs call -- the engine inherits this process's
// environment, byte-identical to before this field existed. e.env non-nil
// routes through runCommandCore with that environment REPLACING the
// process's own; the CPU-usage return value runCommandCore also reports is
// discarded here, the same way runCommandAs already discards it.
func (e engineExec) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmdName, cmdArgs, err := e.sandbox.wrapEngine(name, e.spec, args)
	if err != nil {
		return nil, err
	}
	var out []byte
	if e.env == nil {
		out, err = runCommandAs(ctx, name, cmdName, cmdArgs...)
	} else {
		out, _, err = runCommandCore(ctx, 0, e.env, name, cmdName, cmdArgs...)
	}
	return out, e.sandboxFault(err)
}

// sandboxFault turns a helper exit of sandbox.SetupExit into
// ErrEngineSandboxUnavailable, keeping the original *exec.ExitError reachable
// through errors.As/errors.Unwrap. Any other error -- including a genuine
// engine failure that merely happens to exit some other code -- is returned
// unchanged.
func (e engineExec) sandboxFault(err error) error {
	if err == nil || e.sandbox == nil || len(e.sandbox.Helper) == 0 {
		return err
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == sandbox.SetupExit {
		return fmt.Errorf("%w: %w", ErrEngineSandboxUnavailable, err)
	}
	return err
}

func (e engineExec) runBounded(ctx context.Context, limit int, name string, args ...string) ([]byte, engineCPU, error) {
	cmdName, cmdArgs, err := e.sandbox.wrapEngine(name, e.spec, args)
	if err != nil {
		return nil, engineCPU{}, err
	}
	out, cpu, err := runCommandCore(ctx, limit, e.env, name, cmdName, cmdArgs...)
	return out, cpu, e.sandboxFault(err)
}
