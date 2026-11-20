package convert

// This file (sanitizeconverter.go): the registry face of the sanitize
// operation -- what makes `operation=sanitize` a value the API accepts and
// routes, rather than a function only this package can call.
//
// It is the first converter that declares an operation other than
// OperationConvert, using the OperationalConverter interface phase 57 added
// for exactly this case and left unimplemented by all seven existing
// converters. Nothing about them changes here.
//
// PAIRS ARE (format -> ITS SANITIZED FORM), WHICH IS USUALLY BUT NOT ALWAYS
// THE SAME FORMAT
//
// For PDF and images the pair is (f, f): sanitize is not a conversion, and a
// client asking for a disarmed copy of a PDF expects a PDF back. Registering
// that as a pair makes it a fact the registry enforces -- pdf -> docx under
// operation=sanitize fails the pair gate before it costs an S3 byte -- rather
// than a convention the handler has to remember.
//
// For MACRO-ENABLED OOXML the pair is (docm -> docx), (xlsm -> xlsx) and so
// on, because that is what the output IS. D-06 decided this: the sanitizer
// rewrites [Content_Types].xml to the macro-free content type, so a file
// still named .docm would present itself as macro-enabled while containing no
// macros, and Office warns on or rejects that mismatch.
//
// The first version of this file registered identity pairs for every format,
// which left SanitizedOOXMLExtension -- written and tested by Plan 60-03 for
// exactly this -- called from nowhere. A helper that implements a decision
// and is never invoked is the same defect as a comment promising a route that
// does not exist; caught in review (PR #12), not by a test, because every
// test called the sanitizer directly and none went through the registry.
//
// The pair set is derived from sanitizeFormats rather than typed out, so a
// format added to the sanitizer becomes routable in the same edit. A typed
// list would let the two drift, and the drift would be silent in the
// direction that matters: a format the sanitizer handles but the registry
// does not know is a format the API rejects with "unsupported conversion"
// while the code to do it sits right there.

import (
	"context"
	"fmt"
	"sort"
)

// SanitizeConverter is the probe engine's registry entry.
//
// MaxPages is the PROBE_MAX_PAGES ceiling (probebounds.go), zero meaning "no
// cap configured" -- the same zero-value convention OCRConverter.MaxPages and
// ocrguards.go's enforceMaxPages already use. converters.go registers the
// zero value at init; cmd/probe-worker replaces it with the configured one at
// startup, exactly as cmd/ocr-worker does for OCRConverter.
//
// Sandbox mirrors every other confined class (OCRConverter, PandocConverter,
// ChromiumConverter): a *engineSandbox held by pointer, nil-safe, so
// WithSandbox(nil) still equals the zero value.
type SanitizeConverter struct {
	MaxPages int
	Sandbox  *engineSandbox
}

// Engine reports the eighth engine class.
func (SanitizeConverter) Engine() string { return EngineProbe }

// Operation declares that this converter's pairs belong to sanitize, not
// convert. This is what keeps `probe` out of GET /v1/formats' "engines" key
// and out of the job-list engine filter -- both walk OperationConvert only.
func (SanitizeConverter) Operation() string { return OperationSanitize }

// Pairs returns one pair per sanitizable format, each mapping the format to
// the form its sanitized copy actually takes, sorted so the registry's
// iteration order and every derived listing stay stable.
func (SanitizeConverter) Pairs() []Pair {
	formats := make([]string, 0, len(sanitizeFormats))
	for f := range sanitizeFormats {
		formats = append(formats, f)
	}
	sort.Strings(formats)

	pairs := make([]Pair, 0, len(formats))
	for _, f := range formats {
		pairs = append(pairs, Pair{From: f, To: SanitizedOOXMLExtension(f)})
	}
	return pairs
}

// sanitizeReportSuffix is appended to the primary output's path to name the
// report sidecar.
//
// The report is written to disk beside the output rather than returned,
// because Converter.Convert has no channel for a second result and widening
// that interface would touch all seven engines that have no report to give.
// A file in the job's own temp directory is a legitimate channel between two
// steps of one pipeline, and it has a property a returned value would not:
// the report is written by the same call that produced the output, so the two
// cannot go stale relative to each other.
//
// internal/worker's ProbeDescriptor reads it back. If it is missing, that is a
// failure and not a job without a report -- see the descriptor.
const sanitizeReportSuffix = ".report.json"

// SanitizeReportPath is the sidecar path for a given primary output path.
// Exported so internal/worker derives it from the same expression this writes
// to, rather than from a second copy of the same string.
func SanitizeReportPath(outPath string) string { return outPath + sanitizeReportSuffix }

// Convert sanitizes inPath into outPath and writes the report sidecar.
//
// opts is accepted and ignored. Sanitize has no options: every knob would be
// a way to ask for less removal, and an operation whose contract is "the
// enumerated classes are gone" cannot have a switch that makes that untrue.
// The parameter stays because the Converter interface has it, and the
// argument is not silently dropped -- a caller passing options gets an error
// rather than a quiet best effort.
func (c SanitizeConverter) Convert(ctx context.Context, inPath, outPath string, opts map[string]any) error {
	if len(opts) > 0 {
		return fmt.Errorf("sanitize takes no options, got %d", len(opts))
	}

	format := formatFromPath(inPath)

	// x is this job's ONE engineExec, built ONCE here -- before the page
	// ceiling and before any format dispatch -- and threaded through both.
	// probeEngines is a STATIC set (gs, pdfinfo, unzip, file) granted
	// unconditionally regardless of which format this job actually takes,
	// exactly as every other multi-call-site class (OCR) builds one ruleset
	// per job rather than a format-conditional one.
	x := c.exec(outPath)

	// PROBE-02: the page ceiling, enforced BEFORE sanitizeFile and therefore
	// before the first ghostscript pass. It lives HERE rather than inside
	// sanitizeFile for one reason: the bound is CONFIGURATION, held by this
	// converter (the registry entry cmd/probe-worker replaces with the
	// env-resolved value), and sanitizeFile takes no configuration at all.
	// Threading it through changed that function's signature at every one of
	// its own test call sites -- x engineExec is one of them, added in the
	// same plan for a different reason (CONF-01), not because of the ceiling.
	//
	// Every production path reaches the sanitizer through this method -- the
	// worker resolves a Converter from the registry and calls Convert -- so
	// "a caller could forget the gate" is not the same risk it is for
	// verification, which sanitizeFile keeps inside itself precisely because
	// its callers include this one.
	if enforce, ok := sanitizePageCeilings[format]; ok {
		if err := enforce(ctx, x, inPath, c.MaxPages); err != nil {
			return err
		}
	}

	res, err := sanitizeFile(ctx, x, format, inPath, outPath)
	if err != nil {
		return err
	}

	rep, err := BuildSanitizeReport(format, res)
	if err != nil {
		return fmt.Errorf("sanitize: %w", err)
	}
	blob, err := MarshalSanitizeReport(rep)
	if err != nil {
		return fmt.Errorf("sanitize: marshal report: %w", err)
	}
	if err := writeNewFile(SanitizeReportPath(outPath), blob, 0o644); err != nil {
		return fmt.Errorf("sanitize: write report: %w", err)
	}
	return nil
}

// formatFromPath derives the format from the worker's own naming convention
// for the downloaded input ("in.<source_format>"), normalized through the
// same entry point the registry uses.
func formatFromPath(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return NormalizeFormat(path[i+1:])
		}
		if path[i] == '/' {
			break
		}
	}
	return ""
}

// sanitizePageCeilings maps a sanitizable format to the guard that enforces
// the probe page ceiling on it, and it has exactly one entry on purpose.
//
// The ceiling exists because sanitize cost is per PAGE and linear -- but that
// is a fact about GHOSTSCRIPT rasterizing a PDF (~2.0 s/page, measured in
// phase 60), not about sanitizing in general. OOXML sanitization rewrites a
// zip's parts and images are re-encoded once; neither has a per-page cost
// model, and phase 60 established that inventing one without a measurement is
// not worth doing. A format absent from this map is therefore not "forgotten",
// it is a format whose cost this bound does not describe.
//
// A map rather than a switch, and a package-level literal rather than init()
// registration, for the same reasons sanitizeFormats gives above its own
// declaration.
var sanitizePageCeilings = map[string]func(ctx context.Context, x engineExec, inPath string, max int) error{
	"pdf": enforcePDFPageCeiling,
}

// SanitizeOptsFromMap re-parses a persisted Opts map strictly, keeping only
// the error -- the same "parse strictly, use nothing" contract every other
// engine's OptsFromMap adapter has (D-10: garbage in jobs.options is terminal,
// because a corrupt column value cannot fix itself on retry).
//
// For sanitize the strict parse is simply "there must be nothing here", which
// mirrors Convert's own refusal above rather than restating it in a second
// place with a second opinion.
func SanitizeOptsFromMap(m map[string]any) (any, error) {
	if len(m) > 0 {
		return nil, fmt.Errorf("sanitize takes no options, got %d", len(m))
	}
	return nil, nil
}
