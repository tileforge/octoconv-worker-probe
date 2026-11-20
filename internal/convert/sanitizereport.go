package convert

// This file (sanitizereport.go): the JSON report the sanitize operation hands
// back to a client, assembled from the two closed vocabularies in findings.go
// and nothing else (SANI-05).
//
// NO PROSE IS GENERATED HERE, AND THAT IS THE DESIGN
//
// Every field carries codes. The words that explain what each code means live
// in docs/SANITIZE.md, held equal to the vocabulary by doc_sync_test.go. Code
// that writes sentences into a report is code no test can check: a doc-sync
// test can compare a set of tokens to a set of tokens, and cannot compare
// prose to prose. The first person to soften "removed the VBA project part"
// into "cleaned up macros" would break nothing and be caught by nothing.
//
// THREE FIELDS, THREE DIFFERENT CLAIMS
//
//	removed            -- classes found and removed          (what we did)
//	lost_capabilities  -- document features the method broke  (what it cost)
//	verified           -- classes confirmed absent from the OUTPUT, by an
//	                      implementation that did not do the removing
//
// The first and third are not the same claim and must not share a field.
// "We removed JavaScript" says something about our code path; "we confirmed no
// JavaScript is present in the output" says something about the bytes the
// client is about to receive. SANI-04 requires the second, and a client cannot
// tell them apart if they are merged. A class in `removed` but absent from
// `verified` means the removal ran and nothing checked it -- which is a state
// this build cannot reach, because sanitizeFile refuses to return unverified
// output at all, but the report is still structured so that the distinction is
// expressible rather than assumed away.
//
// The first and second are separated for the reason D-02 gives and
// findings.go's LostCapability doc comment repeats: a lost form is not a
// found attack.
//
// WHAT THE REPORT MAY NOT SAY
//
// There is no summary field, no verdict field, and no boolean. A `"clean":
// true` would be the exact claim the roadmap forbids -- CDR removes carriers
// and does not determine whether code is malicious -- and it would be one
// refactor away from existing if the shape left room for it. The absence is
// load-bearing.

import (
	"encoding/json"
	"fmt"
)

// SanitizeReport is the JSON body written as the job's second output, with
// role=report. That mechanism is phase 57's and is reused rather than
// reinvented: a report is an output of the job, and the job already knows how
// to carry more than one.
type SanitizeReport struct {
	// Format is the normalized SOURCE format that was sanitized. The output
	// carries the sanitized form of it, which differs for macro-enabled OOXML
	// -- a sanitized .docm is reported here as "docm" and delivered as a
	// .docx, because this field answers "what was sanitized", not "what came
	// out". The outputs array of GET /v1/jobs/{id} answers the second.
	Format string `json:"format"`

	// Removed lists the threat classes found and removed, as codes from the
	// closed vocabulary. Never empty for a successful job: a format's handler
	// declares which classes it removes, and a run that removed none of them
	// would mean the handler did nothing.
	Removed []ThreatClass `json:"removed"`

	// LostCapabilities lists document features the sanitization method
	// destroyed as a side effect. Codes, from a vocabulary of its own. May be
	// empty -- the image path is lossless, and reports so by carrying nothing
	// here rather than by an explanatory sentence.
	LostCapabilities []LostCapability `json:"lost_capabilities"`

	// Verified lists the classes an independent implementation confirmed
	// absent from the output bytes. See this file's header for why it is not
	// merged with Removed.
	Verified []ThreatClass `json:"verified"`

	// GuaranteeScope is a fixed reference, not a sentence this code composed.
	// It points at the document that states what the operation does and does
	// not claim, so a client reading only the JSON is not left with an
	// implied guarantee the JSON never made.
	GuaranteeScope string `json:"guarantee_scope"`
}

// guaranteeScopeRef is the single, constant value of the report's
// guarantee_scope field.
//
// A constant rather than a composed string on purpose: composed text drifts,
// and this is the field whose whole job is to stop a client from reading more
// into the report than it says. docs/SANITIZE.md carries the wording; this
// carries the pointer.
const guaranteeScopeRef = "docs/SANITIZE.md#scope-of-the-guarantee"

// BuildSanitizeReport assembles the report from a completed SanitizeResult,
// refusing any code the vocabulary does not declare.
//
// THE VALIDATION IS THE POINT, NOT A FORMALITY. docs/SANITIZE.md is held equal
// to the vocabulary by a bidirectional test, which is what lets a client look
// up any code it receives and find a documented meaning. A report carrying a
// code outside that set breaks the guarantee at the only place it is visible
// -- and a per-format handler's list is an ordinary Go slice that a typo can
// reach. Nothing checked it until now: IsKnownThreatClass and
// IsKnownLostCapability existed with no production caller at all, which made
// them documentation of an intent rather than an enforcement of it.
//
// An unknown code is an ERROR rather than a filtered-out entry. Dropping it
// silently would emit a report that is internally consistent and quietly
// missing something the sanitizer believed it removed.
//
// It copies rather than aliases: the result's slices belong to the per-format
// handler that produced them, and a report that shared them would let a
// caller's edit reach back into the package's own declared lists.
func BuildSanitizeReport(format string, res SanitizeResult) (SanitizeReport, error) {
	for _, c := range res.Removed {
		if !IsKnownThreatClass(c) {
			return SanitizeReport{}, fmt.Errorf(
				"sanitize report: removed carries undeclared threat class %q; "+
					"a code with no row in docs/SANITIZE.md has no meaning to a client", c)
		}
	}
	for _, c := range res.Verified {
		if !IsKnownThreatClass(c) {
			return SanitizeReport{}, fmt.Errorf(
				"sanitize report: verified carries undeclared threat class %q", c)
		}
	}
	for _, c := range res.LostCapabilities {
		if !IsKnownLostCapability(c) {
			return SanitizeReport{}, fmt.Errorf(
				"sanitize report: lost_capabilities carries undeclared capability %q", c)
		}
	}

	return SanitizeReport{
		Format:           NormalizeFormat(format),
		Removed:          append([]ThreatClass{}, res.Removed...),
		LostCapabilities: append([]LostCapability{}, res.LostCapabilities...),
		Verified:         append([]ThreatClass{}, res.Verified...),
		GuaranteeScope:   guaranteeScopeRef,
	}, nil
}

// MarshalSanitizeReport renders the report as the JSON bytes uploaded as the
// role=report output.
//
// Non-empty-but-zero-length slices are preserved as `[]`, not `null`: a client
// distinguishing "nothing was lost" from "the field is missing" should not
// have to guess, and Go's zero value for a slice would otherwise turn the
// lossless image path's empty list into a null.
func MarshalSanitizeReport(rep SanitizeReport) ([]byte, error) {
	if rep.Removed == nil {
		rep.Removed = []ThreatClass{}
	}
	if rep.LostCapabilities == nil {
		rep.LostCapabilities = []LostCapability{}
	}
	if rep.Verified == nil {
		rep.Verified = []ThreatClass{}
	}
	return json.MarshalIndent(rep, "", "  ")
}
