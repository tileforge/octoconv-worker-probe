package convert

// This file (findings.go): the closed, versioned vocabulary of THREAT CLASSES
// the sanitize operation finds and removes (Phase 60, D-08).
//
// It is a third vocabulary alongside internal/errcode ("why was the REQUEST
// rejected") and internal/inspect ("what was FOUND IN THE FILE"), and it
// answers a question neither of them does: "what was REMOVED FROM THE FILE".
// The three overlap in subject and differ in verb -- inspect can report a
// pdf_javascript finding on a file nobody ever sanitizes, and sanitize removes
// constructs on files nobody ever inspected.
//
// CLOSED BY MEANING, NOT BY SPELLING
//
// Several distinct tokens collapse into one class on purpose. /OpenAction and
// /AA are two different PDF dictionary keys and one client-visible fact: the
// document tried to run something on open. A client deciding what to do with
// the sanitized file needs to know an auto-triggered action was removed; which
// key carried it is an implementation detail of the format, not of the risk.
//
// The same rule going the other way is what keeps the vocabulary honest: a new
// spelling of an existing threat extends an existing class, while a genuinely
// different client-visible fact earns a new constant. "We found a new token"
// is not a reason to grow this list.
//
// WHAT THIS VOCABULARY MAY NEVER SAY
//
// No constant, and no text assembled from these constants, may assert that a
// file is safe, clean, virus-free, or free of malicious content. The report
// built from this vocabulary states which ENUMERATED classes were looked for
// and removed, and nothing wider. CDR removes carriers; it does not determine
// whether code is malicious, and a service that removes seven classes of
// carrier and reports "safe" has made a claim it did not test.
//
// That restriction is mechanical, not advisory: Plan 60-05 adds a doc-sync
// test that fails on the affirmative phrasings, in both this file and
// docs/SANITIZE.md. Adding a class here means adding a row there.

// ThreatClass is one client-visible class of construct the sanitizer finds and
// removes. Compared exactly, with no case normalization -- the same discipline
// as inspect.Code and errcode.Code.
type ThreatClass string

const (
	// ThreatJavaScript is embedded JavaScript: a /JavaScript name tree entry
	// or a /S /JavaScript action. Auto-executing in most readers.
	ThreatJavaScript ThreatClass = "javascript"

	// ThreatActionDict is an automatic action dictionary -- /OpenAction on
	// the catalog, or /AA (additional actions) anywhere. Both mean the
	// document asked for something to happen without the reader choosing it.
	ThreatActionDict ThreatClass = "action_dict"

	// ThreatLaunchAction is a /Launch action: the document asks the reader to
	// start an external program.
	ThreatLaunchAction ThreatClass = "launch_action"

	// ThreatEmbeddedFile is an attached file -- an /EmbeddedFiles name tree,
	// a /Filespec with an /EF stream, or an OOXML part carrying one. The
	// attachment travels with the document and is opened by hand later,
	// which is why inspect classifies the same construct as a passive rather
	// than an active risk.
	ThreatEmbeddedFile ThreatClass = "embedded_file"

	// ThreatExternalReference is a reference to a resource outside the file:
	// a /URI action, or an OOXML relationship with TargetMode="External".
	// Removing it is what stops a document from phoning home when opened.
	ThreatExternalReference ThreatClass = "external_reference"

	// ThreatDocumentMetadata is authorship and provenance metadata: PDF
	// /Info, an XMP packet, or image EXIF/GPS/IPTC. Grouped as one class
	// because the client-visible fact is identical across all three -- who
	// made this, when, with what, and where -- even though the carriers are
	// entirely different formats.
	ThreatDocumentMetadata ThreatClass = "document_metadata"

	// ThreatVBAMacro is a VBA project in an OOXML container. Removed as a
	// whole part rather than by editing module source: VBA stomping keeps
	// benign-looking source and hides behaviour in compiled p-code, so any
	// sanitizer that reads source and keeps the part is defeated by
	// construction (60-CONTEXT.md D-05).
	ThreatVBAMacro ThreatClass = "vba_macro"

	// ThreatOLEObject is an embedded OLE compound-file object inside an
	// OOXML container -- distinct from ThreatVBAMacro, which is specifically
	// the VBA project part. Wired up by Plan 60-03.
	ThreatOLEObject ThreatClass = "ole_object"
)

// allThreatClasses is the closed set, in the order the report presents them:
// active/auto-triggered risks first, then passive ones, then metadata. The
// order is part of the contract -- docs/SANITIZE.md's table mirrors it, and
// Plan 60-05's doc-sync test compares both membership and nothing else, so a
// reordering here is a documentation edit, not a behavioural one.
var allThreatClasses = []ThreatClass{
	ThreatJavaScript,
	ThreatActionDict,
	ThreatLaunchAction,
	ThreatVBAMacro,
	ThreatOLEObject,
	ThreatEmbeddedFile,
	ThreatExternalReference,
	ThreatDocumentMetadata,
}

// AllThreatClasses returns a fresh copy of the closed set, so a caller
// ranging over it cannot mutate the package's own slice.
//
// WHO ACTUALLY CALLS THIS, stated because the answer is not what the shape
// suggests. inspect.AllCodes has eleven production call sites and errcode.All
// has eight, because each builds a CLOSED section into its response. This
// report deliberately has no closed section -- it lists what was removed, not
// one entry per class -- so nothing in production ranges over the whole set.
//
// Its consumers are the doc-sync contract (doc_sync_test.go holds this equal
// to docs/SANITIZE.md in both directions) and any external client validating a
// code it received. That is a real job, and it is not the same job the two
// older accessors do; writing "the same as inspect.AllCodes" here, as an
// earlier version did, implied a parity that does not hold.
//
// The per-code predicates below ARE wired into production: BuildSanitizeReport
// refuses a report carrying a code this vocabulary does not declare.
func AllThreatClasses() []ThreatClass {
	out := make([]ThreatClass, len(allThreatClasses))
	copy(out, allThreatClasses)
	return out
}

// IsKnownThreatClass reports whether c is one of the closed set. Exact
// comparison, no case normalization -- "JavaScript" is not "javascript".
func IsKnownThreatClass(c ThreatClass) bool {
	for _, known := range allThreatClasses {
		if c == known {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// lost capabilities
// ---------------------------------------------------------------------------

// LostCapability is a document feature the sanitization METHOD destroys as a
// side effect. It is a second closed vocabulary, deliberately separate from
// ThreatClass, and the separation is the whole point (D-02).
//
// A client reading "this document lost its fillable form fields" inside a list
// of removed THREATS would reasonably conclude the form was an attack. It was
// not. It is the price of rebuilding the document through an interpreter that
// draws marks and has no concept of a form. One heading over both lists tells
// the client something false about both entries.
//
// These were plain []string until Plan 60-05. Free text in a report is text
// nothing can check: no doc-sync test can compare prose to prose, and the
// first person to write "forms may not work" instead of a token would have
// broken nothing and been caught by nothing. A code is a thing the document
// and the vocabulary can be held equal on.
type LostCapability string

const (
	// LostFillableForms: AcroForm fields become static marks. The document
	// still SHOWS the form; it can no longer be filled in.
	LostFillableForms LostCapability = "fillable_form_fields"

	// LostBookmarks: the outline/bookmark tree is gone. PostScript has no
	// notion of one, so nothing survives the round trip to rebuild it from.
	LostBookmarks LostCapability = "bookmarks_outline"

	// LostTaggedStructure: the tagged accessibility tree is gone. This is the
	// costliest entry in the list and the one most likely to matter to a
	// client with an accessibility obligation, which is why it is reported
	// rather than left to be discovered.
	LostTaggedStructure LostCapability = "tagged_accessibility_structure"

	// LostDocumentAnnotations: document-level annotations -- comments, review
	// markup, stamps -- do not survive the interpreter.
	LostDocumentAnnotations LostCapability = "document_level_annotations"

	// LostVBAMacroFunctionality: the OOXML package's macros no longer run.
	// This is the same event as ThreatVBAMacro seen from the other side: what
	// the sanitizer calls a removed carrier, the client's workflow calls a
	// feature it depended on. Reporting it under both headings is not
	// duplication -- the client needs the threat entry to understand the risk
	// and this entry to understand what will break on Monday.
	LostVBAMacroFunctionality LostCapability = "vba_macro_functionality"

	// LostEmbeddedOLEObjects: embedded OLE objects -- charts, equations,
	// attached workbooks -- are gone from the package.
	LostEmbeddedOLEObjects LostCapability = "embedded_ole_objects"

	// LostDocumentProperties: the OOXML core/app properties part is gone, so
	// title, author and company no longer travel with the file.
	LostDocumentProperties LostCapability = "document_properties"
)

// allLostCapabilities is the closed set, in the order the report presents
// them: PDF-side losses first, then OOXML-side. docs/SANITIZE.md's second
// table mirrors this, and Plan 60-05's doc-sync test compares membership only.
var allLostCapabilities = []LostCapability{
	LostFillableForms,
	LostBookmarks,
	LostTaggedStructure,
	LostDocumentAnnotations,
	LostVBAMacroFunctionality,
	LostEmbeddedOLEObjects,
	LostDocumentProperties,
}

// AllLostCapabilities returns a fresh copy of the closed set. Same consumers
// as AllThreatClasses above -- the doc-sync contract and external clients, not
// production code.
func AllLostCapabilities() []LostCapability {
	out := make([]LostCapability, len(allLostCapabilities))
	copy(out, allLostCapabilities)
	return out
}

// IsKnownLostCapability reports whether c is one of the closed set.
func IsKnownLostCapability(c LostCapability) bool {
	for _, known := range allLostCapabilities {
		if c == known {
			return true
		}
	}
	return false
}
