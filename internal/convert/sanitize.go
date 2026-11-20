package convert

// This file (sanitize.go): the shared shape of the sanitize operation --
// the dispatcher and the result type. Per-format work lives beside it
// (sanitizepdf.go, sanitizeooxml.go, sanitizeimage.go), mirroring the
// ocr.go / ocrpdf.go split.
//
// WHAT SANITIZE IS, AND WHAT IT IS NOT
//
// It is Content Disarm and Reconstruction: the enumerated carriers in
// findings.go are removed and their absence is then proven by an
// implementation that did not do the removing (Plan 60-04). It is NOT an
// antivirus, it does not decide whether anything was malicious, and it makes
// no claim about content outside those enumerated classes. See findings.go's
// header for why that restriction is mechanical rather than advisory.

import (
	"context"
	"fmt"
	"os"
)

// SanitizeResult is what one sanitize run reports about itself.
//
// Removed and LostCapabilities are two structurally separate lists on purpose
// (D-02). A client reading "this document lost its fillable form fields"
// inside a list of removed THREATS would reasonably conclude the form was an
// attack. It was not: it is the price of rebuilding the document through an
// interpreter that draws marks and has no concept of a form. Filing both under
// one heading tells a client something false about both.
//
// Verified is narrower than Removed and deliberately so: "we removed
// JavaScript" and "we confirmed no JavaScript is present in the output" are
// different claims, and SANI-04 requires the second. Plan 60-04 fills it in
// from the independent verifier; a class in Removed but absent from Verified
// means the removal ran and nothing checked it.
type SanitizeResult struct {
	// Removed lists the threat classes found and removed from this document.
	Removed []ThreatClass
	// LostCapabilities lists document features the sanitization method
	// destroys as a side effect -- fillable forms, bookmarks, tagged
	// accessibility structure. Not threats; costs.
	LostCapabilities []LostCapability
	// Verified lists the classes an independent implementation confirmed
	// absent from the OUTPUT bytes. Filled by Plan 60-04.
	Verified []ThreatClass
}

// SanitizeFormats is the closed set of source formats the sanitize operation
// accepts, mapped to the function that handles each. The output format is the
// input's SANITIZED FORM -- the same format for PDF and images, and the
// macro-free equivalent for macro-enabled OOXML (a sanitized .docm is a
// .docx, D-06). SanitizeConverter.Pairs derives that from
// SanitizedOOXMLExtension; this map only names what can be sanitized at all.
//
// # WHY THIS IS A MAP LITERAL AND NOT PER-FILE init() REGISTRATION
//
// It was the latter, and the eighth-engine cross-check in
// TestAllEnginesCoversEveryEngineClass caught what that cost. Go runs a
// package's init() functions in FILE-NAME order, and converters.go sorts
// before every sanitize*.go, so SanitizeConverter was registered with the
// registry while this map was still empty -- its Pairs() returned nothing,
// no triple was registered, and operation=sanitize would have kept returning
// 422 with the whole implementation sitting right there.
//
// A literal has no ordering to get wrong: package-level variables are
// initialized by dependency, not by file name. The cost is that the closed
// set of sanitizable formats lives here rather than beside each handler,
// which for a set this document-visible is arguably where it belongs.
var sanitizeFormats = map[string]func(context.Context, engineExec, string, string) (SanitizeResult, error){
	"pdf": sanitizePDF,

	// The six OOXML formats the API can actually ADMIT. dotm, potm, ppsm and
	// xltm are deliberately absent even though sanitizeOOXML handles them
	// perfectly well: SniffContainer identifies a package by its root part,
	// and a .dotm has the same root part as a .docm, so a .dotm upload is
	// detected as "docm" and rejected as a declared/detected mismatch before
	// it can reach any of this. Registering a pair the API cannot admit is a
	// promise of something that does not happen -- the same defect class as a
	// helper implementing a decision and never being called (PR #12).
	//
	// Closing that needs detection to read [Content_Types].xml's main-part
	// override rather than the root part's name, which touches the convert
	// path and its pinned goldens. Tracked as an open item.
	"docm": sanitizeOOXML,
	"docx": sanitizeOOXML,
	"xlsm": sanitizeOOXML,
	"xlsx": sanitizeOOXML,
	"pptm": sanitizeOOXML,
	"pptx": sanitizeOOXML,

	"jpg": sanitizeImage,
	"png": sanitizeImage,
}

// sanitizeFile sanitizes inPath into outPath, dispatching on the NORMALIZED
// source format.
//
// The format is normalized through NormalizeFormat, the same entry point the
// registry uses, so "JPEG"/"jpeg"/"jpg" reach one handler rather than three
// map misses. An unknown format is an error, never a pass-through copy: a
// sanitizer that silently returns the input unchanged for a format it does not
// handle is the worst available outcome, because the job goes green and the
// client believes the file was disarmed.
//
// x is the ONE engineExec built for this job (SanitizeConverter.Convert
// builds it once, before any dispatch) and threaded through every format
// handler and the verifier below. sanitizeOOXML/sanitizeImage never exec
// anything and carry x unused -- the map's value type is shared across all
// six functions, and a caller reaching this function directly (every test)
// passes engineExec{} for "run the engine unconfined".
//
// It is package-private on purpose (Codex P2, PR #30): its x parameter is the
// package-private engineExec, so an exported version could not be called from
// outside this package. The only way to make it callable would be an exported
// variant that fills x itself -- and that would have to pass a zero engineExec,
// i.e. run the engine with no sandbox, bypassing the Landlock ruleset
// SanitizeConverter.Convert builds for every job. Production reaches this
// function only through SanitizeConverter.Convert.
func sanitizeFile(ctx context.Context, x engineExec, format, inPath, outPath string) (SanitizeResult, error) {
	norm := NormalizeFormat(format)
	fn, ok := sanitizeFormats[norm]
	if !ok {
		return SanitizeResult{}, fmt.Errorf("sanitize: unsupported format %q", format)
	}
	res, err := fn(ctx, x, inPath, outPath)
	if err != nil {
		return SanitizeResult{}, err
	}

	// Verification is INSIDE this function, not left to the caller, because a
	// caller that forgets it produces a file that went through an operation
	// named sanitize and was never checked -- and nothing downstream can tell
	// that file from a verified one. There is no skip flag for the same
	// reason (SANI-04, D-07).
	verified, verr := verifySanitized(ctx, x, norm, outPath)
	if verr != nil {
		// Delete the output before returning. The requirement is that
		// nothing unverified reaches S3; the strongest form of that is that
		// unverified bytes stop existing, rather than existing next to a
		// promise that no one will upload them.
		_ = os.Remove(outPath)
		return SanitizeResult{}, verr
	}
	res.Verified = verified
	return res, nil
}

// SanitizeSupports reports whether format has a registered sanitize handler.
//
// Its consumer is the timing harness (probetiming_test.go), which needs to
// skip a corpus file this build cannot sanitize before timing it. The API does
// NOT use it: the registry answers "is this (operation, from, to) supported"
// through EngineForOp, which is a stricter question and the one a request
// actually asks.
//
// An earlier version of this comment claimed "used by the registry wiring in
// Plan 60-06", which was never true. That is the same defect as a helper
// implementing a decision and never being called -- a comment cannot fail, so
// it says what is, not what was planned.
func SanitizeSupports(format string) bool {
	_, ok := sanitizeFormats[NormalizeFormat(format)]
	return ok
}
