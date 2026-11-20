package convert

// This file (probebounds.go): the probe engine's page ceiling.
//
// It was ONE bound with TWO enforcement points -- the worker, and an admission
// gate in cmd/api. The admission gate was removed after six review rounds
// (63-CONTEXT.md D-04, reversed); what is left is enforced in the worker alone,
// where an accurate count is affordable.
//
// WHY A PAGE CEILING AT ALL, AND WHY THIS NUMBER
//
// Phase 60 measured PROBE_ENGINE_TIMEOUT rather than picking it, and the
// measurement's finding was the cost MODEL, not the number: sanitize cost is
// per PAGE and dead linear -- 20 pages/39.738s, 100 pages/200.437s,
// 240 pages/481.308s, i.e. 1.99-2.01 s/page. A 219 KB document took 481s
// while a 2.2 MB one took 39.7s. Byte size is irrelevant.
//
// PROBE_ENGINE_TIMEOUT=600s was then derived, in OCR's own shape
// (per-unit cost x ceiling x margin):
//
//	PROBE_ENGINE_TIMEOUT = ceil(2.0 s/page x 200 pages x 1.5) = 600s
//
// The 200 in that expression is a page ceiling the engine did not have. Until
// this file, the timeout was the only bound on the input, which made the
// failure for an over-long document LATE (ten minutes of CPU), RETRIED (a
// probe timeout is TRANSIENT by isProbeTerminal, correctly, because a timeout
// normally means load) and OPAQUE (engine_error, not "this document has more
// pages than the service will sanitize").
//
// DefaultProbeMaxPages is therefore 200: the exact number
// PROBE_ENGINE_TIMEOUT's own derivation already assumed. It is not a round
// number chosen and justified afterwards -- picking anything else would mean
// the timeout and the ceiling disagreed about what this service sanitizes.
//
// It is PROVISIONAL in the same sense PROBE_ENGINE_TIMEOUT was before it was
// measured, and for a narrower reason: 2.0 s/page is measured, but "200 pages
// of full-page scans is a generous document bound" is reasoned, from a corpus
// chosen by hand rather than from what clients actually submit. An operator
// with a real corpus should raise or lower PROBE_MAX_PAGES from it. The hard
// ceiling nothing may exceed is not this number but the one the reconciler
// sets: RECONCILER_ACTIVE_STALE_AFTER=900s at 2.0 s/page is 450 pages.
//
// WHY ITS OWN SENTINEL RATHER THAN ErrOCRTooManyPages
//
// The two report the same CODE (too_many_pages) for the same client-facing
// condition, and that sharing is deliberate -- two codes for one condition is
// a vocabulary defect (D-04). The SENTINELS stay separate: the engines' bounds
// are different numbers derived from different measurements, and a shared
// sentinel would make ocrFailureCode's and isOCRTerminal's branches silently
// cover the probe path too. A shared error value is a shared classification,
// which is exactly what these two must not have.

import (
	"errors"
	"fmt"
)

// DefaultProbeMaxPages is the code-level default for PROBE_MAX_PAGES.
//
// ONE process reads it: cmd/probe-worker. It began as a shared constant for
// two -- cmd/api enforced the same ceiling at admission -- and that gate was
// removed after six review rounds (63-CONTEXT.md D-04, reversed), because a
// page count cannot be derived reliably from untrusted bytes in that process.
//
// It stays a named constant rather than collapsing into a literal at the one
// remaining call site, because this is where the derivation is written down.
// A literal in main.go would separate the number from the arithmetic that
// produced it, and this engine's OTHER bound has already been damaged by
// exactly that: cmd/api omitted PROBE_ENGINE_TIMEOUT and published
// estimated_max_seconds: 0 while the worker used its own default (PR #12).
//
// See this file's header for the derivation and for why it is PROVISIONAL.
const DefaultProbeMaxPages = 200

// ErrProbeTooManyPages is returned when a PDF's page count exceeds the
// configured probe ceiling -- fail-closed BEFORE the first ghostscript pass.
var ErrProbeTooManyPages = errors.New("probe: pdf page count exceeds bound")

// EnforceProbeMaxPages is the comparison the sanitize path makes.
//
// max == 0 means "no cap configured", matching enforceMaxPages's zero-value
// convention in ocrguards.go exactly -- a bare zero is never a fail-closed
// reject-all, it is a bound that was not set.
//
// The error carries BOTH numbers, like OCR's does, so the message says what
// the file had and what the bound was rather than only that a bound existed.
func EnforceProbeMaxPages(count, max int) error {
	if max > 0 && count > max {
		return fmt.Errorf("%w: declared page count %d exceeds bound %d", ErrProbeTooManyPages, count, max)
	}
	return nil
}
