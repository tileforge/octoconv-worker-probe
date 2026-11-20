// Package convert (this file): sandboxpreflight.go is the toolkit every
// confined engine class's own <Class>Preflight function is built from --
// LibvipsPreflight and TectonicPreflight each grew their own workspace and
// judgment before this landed; PandocPreflight and the classes after it
// share this one instead.
//
// The shape is the same for every class: convert something REAL through the
// REAL helper and judge the result by CONTENT, never by exit status alone --
// ghostscript was measured to exit 0 and write nothing when denied, which is
// the whole reason a preflight exists at all (LibvipsPreflight's own doc
// comment). This file adds the piece none of the earlier preflights needed
// on their own: a SECOND, sibling workspace outside the job directory, so a
// preflight can prove not just that confinement lets the right thing happen
// (sufficiency) but that it denies the wrong one (effectiveness) -- with the
// identical bytes, under the identical ruleset, so a failure outside is
// attributable only to location.
package convert

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// preflightWorkspace is a preflight's two directories: the job directory the
// ruleset grants, and a SIBLING directory it does not. Both are real
// directories on disk, not a single tree with an "outside" subdirectory --
// the ruleset must have a genuine reason to deny the second one, not merely
// a path that happens to fall outside a granted prefix by construction.
type preflightWorkspace struct {
	jobDir     string
	outsideDir string
}

// newPreflightWorkspace creates the two directories and returns a cleanup
// func that removes both. class names the caller (e.g. "pandoc") so a
// process running several preflights leaves distinguishable temp
// directories on a failed cleanup.
func newPreflightWorkspace(class string) (preflightWorkspace, func(), error) {
	return newPreflightWorkspaceOutside(class, "")
}

// newPreflightWorkspaceOutside is newPreflightWorkspace with the outside
// directory's PARENT chosen explicitly, rather than always os.TempDir().
// A class whose own writable grant includes the system temp dir (html's
// /tmp, CONF-06) cannot use newPreflightWorkspace's default -- an "outside"
// file placed there would be readable under that class's own ruleset, and
// the preflight would refuse to start for having nothing to test. outsideBase
// "" reproduces newPreflightWorkspace's exact prior behaviour (os.TempDir()),
// so every phase-68 class is unaffected by this function's existence.
func newPreflightWorkspaceOutside(class, outsideBase string) (preflightWorkspace, func(), error) {
	jobDir, err := os.MkdirTemp("", class+"-preflight-job-")
	if err != nil {
		return preflightWorkspace{}, nil, fmt.Errorf("preflight job directory: %w", err)
	}
	outsideDir, err := os.MkdirTemp(outsideBase, class+"-preflight-outside-")
	if err != nil {
		os.RemoveAll(jobDir)
		return preflightWorkspace{}, nil, fmt.Errorf("preflight outside directory: %w", err)
	}
	w := preflightWorkspace{jobDir: jobDir, outsideDir: outsideDir}
	cleanup := func() {
		os.RemoveAll(jobDir)
		os.RemoveAll(outsideDir)
	}
	return w, cleanup, nil
}

// requireOutsideGrants proves the workspace's own outside directory is not
// itself readable under any of the granted path sets -- a negative
// (effectiveness) preflight run is only evidence of confinement when the
// file it tries to read is genuinely outside every grant. Resolves both the
// outside directory and each granted path through filepath.EvalSymlinks
// (falling back to filepath.Clean when a path cannot be resolved, e.g. it
// does not exist on this host) before comparing, since Landlock itself
// restricts the RESOLVED path, not the string a class happens to write in
// its own readOnly/readWrite var.
func (w preflightWorkspace) requireOutsideGrants(granted ...[]string) error {
	outside := resolveOrClean(w.outsideDir)
	for _, set := range granted {
		for _, g := range set {
			gr := resolveOrClean(g)
			if outside == gr || strings.HasPrefix(outside, gr+string(filepath.Separator)) {
				return fmt.Errorf("preflight outside directory %s lies at or beneath granted path %s: "+
					"a negative run against it would prove nothing", w.outsideDir, g)
			}
		}
	}
	return nil
}

// resolveOrClean resolves symlinks in p, falling back to filepath.Clean when
// p cannot be resolved (most commonly: it does not exist).
func resolveOrClean(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// place writes identical bytes to both directories under name, then reads the
// OUTSIDE copy back through this process's own (unconfined) identity and
// compares it -- a canary this uid cannot even read before any ruleset is
// applied proves nothing when the ruleset later denies it too: the denial
// would say nothing about confinement, only about permissions that already
// existed.
func (w preflightWorkspace) place(name string, data []byte) (inside, outside string, err error) {
	inside = filepath.Join(w.jobDir, name)
	outside = filepath.Join(w.outsideDir, name)
	if err := os.WriteFile(inside, data, 0o600); err != nil {
		return "", "", fmt.Errorf("preflight fixture (inside): %w", err)
	}
	if err := os.WriteFile(outside, data, 0o600); err != nil {
		return "", "", fmt.Errorf("preflight fixture (outside): %w", err)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		return "", "", fmt.Errorf("preflight canary: the outside fixture cannot be read even before "+
			"any ruleset is applied, so a later denial would prove nothing: %w", err)
	}
	if !bytes.Equal(got, data) {
		return "", "", fmt.Errorf("preflight canary: the outside fixture read back different bytes " +
			"than it was written, before any ruleset was applied")
	}
	return inside, outside, nil
}

// requireOutput is the sufficiency judgment: path must exist, be non-empty,
// and -- when want is non-nil -- contain it. Judging by content, not merely
// existence, is what catches an engine that exits 0 and writes an empty or
// unrelated file when denied (LibvipsPreflight's ghostscript finding).
func requireOutput(path string, want []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no output at %s: %w", path, err)
	}
	if len(data) == 0 {
		return fmt.Errorf("output at %s is empty", path)
	}
	if want != nil && !bytes.Contains(data, want) {
		return fmt.Errorf("output at %s does not contain the expected marker", path)
	}
	return nil
}

// requireDenied is the effectiveness judgment, the mirror of requireOutput:
// the conversion of a file OUTSIDE the job directory must have failed
// (convErr == nil is itself a failure of the judgment -- confinement is not
// in effect), and outPath must carry no trace of having succeeded partway --
// absent, or present but not carrying marker when one was given.
func requireDenied(convErr error, outPath string, marker []byte) error {
	if convErr == nil {
		return fmt.Errorf("converted a file outside the job directory: confinement is not in effect")
	}
	if marker == nil {
		data, err := os.ReadFile(outPath)
		if err != nil {
			return nil // no output at all: the denial is clean
		}
		if len(data) > 0 {
			return fmt.Errorf("the denied conversion still produced %d bytes of output at %s",
				len(data), outPath)
		}
		return nil
	}
	return requireAbsent(outPath, marker)
}

// requireAbsent is the marker judgment on its own, extracted so a preflight
// that cannot route its negative run through requireDenied's convErr check
// (html's own: chromium exits 0 and writes a blank PDF when denied, so
// "convErr == nil is itself a failure" cannot judge it -- see htmlsandbox.go)
// still shares the same byte judgment requireDenied's marker branch uses. A
// nil marker is itself an error here: a denial judged without a marker to
// look for proves nothing, and this function exists specifically for a
// caller that has one.
func requireAbsent(outPath string, marker []byte) error {
	if marker == nil {
		return fmt.Errorf("requireAbsent: no marker given -- a denial judged without one proves nothing")
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil // missing or unreadable: a clean denial
	}
	if bytes.Contains(data, marker) {
		return fmt.Errorf("output at %s carries the marker from the denied file: it was converted anyway",
			outPath)
	}
	return nil
}

// requireContains is the sufficiency judgment for an engine's own STDOUT
// rather than a file on disk -- probe's preflight reads gs/unzip/file output
// directly, never through a path requireOutput could open. what names the
// check in the returned error, mirroring requireOutput's shape.
func requireContains(what string, got, want []byte) error {
	if len(got) == 0 {
		return fmt.Errorf("%s produced no output", what)
	}
	if !bytes.Contains(got, want) {
		return fmt.Errorf("%s does not contain the expected marker", what)
	}
	return nil
}

// requireLacks is requireContains's effectiveness mirror, for an engine's own
// stdout: got must not carry marker. Unlike requireAbsent (a FILE that may be
// entirely missing on a clean denial), an engine invocation that ran at all
// always produces SOME stdout, even a permission-denied message -- so this
// never treats empty output as a synonym for "clean"; it only checks content.
func requireLacks(what string, got, marker []byte) error {
	if bytes.Contains(got, marker) {
		return fmt.Errorf("%s carries the marker from the denied file: it was processed anyway", what)
	}
	return nil
}

// preflightMarker is a value a preflight can plant in a fixture and then
// search for in output -- unique per run, so a marker found in an output
// could only have come from THIS preflight's own fixture, never a stale file
// left by an earlier one.
func preflightMarker() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("preflight marker: %w", err)
	}
	return "octoconv-preflight-" + hex.EncodeToString(b), nil
}
