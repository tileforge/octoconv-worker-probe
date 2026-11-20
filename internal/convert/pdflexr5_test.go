package convert

import (
	"context"
	"testing"
)

// Round 5 of PR #14 — the last one AGENTS.md allows. Three findings, and two of
// them are "the round-4 fix stopped one step short", which is worth naming: a
// check moved to the right place still has to be a check.

// TestNameEscapesAreDecodedBeforeMatching covers PDF name escaping.
//
// "/Len#67th" IS "/Length" (ISO 32000-1 7.3.5), and a dictionary may spell it
// that way. Comparing raw bytes left such a stream unresolved -- and the lexical
// walker the tokenizer replaced never required a literal spelling, so this was a
// rejection of valid input introduced BY the fix. Rejection deletes the client's
// output.
func TestNameEscapesAreDecodedBeforeMatching(t *testing.T) {
	body := "abcde"

	for _, tc := range []struct{ name, key string }{
		{"plain", "/Length"},
		{"one escaped byte", "/Len#67th"},
		{"first byte escaped", "/#4cength"},
		{"every byte escaped", "/#4c#65#6e#67#74#68"},
		{"lowercase hex", "/Len#67t#68"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte("%PDF-1.4\n1 0 obj\n<< " + tc.key + " 5 >>\nstream\n" + body +
				"\nendstream\nendobj\ntrailer\n<< /Size 2 >>\nstartxref\n0\n%%EOF\n")
			ranges, err := pdfStreamRanges(raw)
			if err != nil {
				t.Fatalf("pdfStreamRanges rejected a valid file: %v", err)
			}
			if len(ranges) != 1 || ranges[0][1]-ranges[0][0] != len(body) {
				t.Errorf("ranges = %v, want one range of %d bytes", ranges, len(body))
			}
		})
	}

	// A "#" that is not a valid escape stays a literal "#", so a name that is
	// not /Length does not become one.
	raw := []byte("%PDF-1.4\n1 0 obj\n<< /Len#zzth 5 /Length 5 >>\nstream\nabcde\nendstream\nendobj\n")
	if _, err := pdfStreamRanges(raw); err != nil {
		t.Errorf("a malformed escape broke a dictionary that also carries a real /Length: %v", err)
	}
}

// TestTypesRootMustBeTheOPCTypesElement is round 5's second finding.
//
// A document can put a foreign <x:Types> at the root while declaring the OPC
// namespace as the DEFAULT for its children -- so the children look right and
// their parent is not the OPC Types element at all. The round-4 depth check
// asked about the child and said nothing about the parent.
func TestTypesRootMustBeTheOPCTypesElement(t *testing.T) {
	opc := "http://schemas.openxmlformats.org/package/2006/content-types"

	foreignRoot := []byte(`<?xml version="1.0"?>` +
		`<x:Types xmlns:x="urn:foreign" xmlns="` + opc + `">` +
		`<Override PartName="/word/document.xml" ContentType="application/xml"/>` +
		`</x:Types>`)
	if contentTypeDeclares(foreignRoot, "word/document.xml") {
		t.Error("a declaration whose parent is a FOREIGN Types element was accepted")
	}

	wrongLocalName := []byte(`<?xml version="1.0"?>` +
		`<Package xmlns="` + opc + `">` +
		`<Override PartName="/word/document.xml" ContentType="application/xml"/>` +
		`</Package>`)
	if contentTypeDeclares(wrongLocalName, "word/document.xml") {
		t.Error("a declaration under an element that is not <Types> was accepted")
	}

	good := []byte(`<?xml version="1.0"?><Types xmlns="` + opc + `">` +
		`<Override PartName="/word/document.xml" ContentType="application/xml"/></Types>`)
	if !contentTypeDeclares(good, "word/document.xml") {
		t.Error("a genuine OPC Types document was rejected")
	}

	prefixed := []byte(`<?xml version="1.0"?><ct:Types xmlns:ct="` + opc + `">` +
		`<ct:Override PartName="/word/document.xml" ContentType="application/xml"/></ct:Types>`)
	if !contentTypeDeclares(prefixed, "word/document.xml") {
		t.Error("a prefixed but correctly-namespaced document was rejected -- the check " +
			"is about the namespace, not the spelling")
	}
}

// TestMainPartMustParseToACleanEOF is round 5's third finding, and the same
// shape as its first: xmlRootElement returns on the first start token, so
// "<document><broken>" satisfied it while carrying a document nothing can open.
//
// The round-4 fix put the check in the right place and stopped one token short
// of making it mean anything.
func TestMainPartMustParseToACleanEOF(t *testing.T) {
	requireVerifierBinaries(t)

	ct := []byte(`<?xml version="1.0"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Override PartName="/word/document.xml" ContentType="application/xml"/>` +
		`</Types>`)

	for _, tc := range []struct {
		name string
		doc  string
		ok   bool
	}{
		{"right root, unclosed child", `<?xml version="1.0"?><document><broken>`, false},
		{"right root, mismatched close", `<?xml version="1.0"?><document></wrong>`, false},
		{"right root, trailing garbage", `<?xml version="1.0"?><document/><`, false},
		{"right root, complete", `<?xml version="1.0"?><document><body/></document>`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := buildOOXMLPackage(t, map[string][]byte{
				"[Content_Types].xml": ct,
				"word/document.xml":   []byte(tc.doc),
			})
			_, err := verifySanitized(context.Background(), engineExec{}, "docx", path)
			if tc.ok && err != nil {
				t.Errorf("a complete document was rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("a main part that does not parse to the end was verified")
			}
		})
	}
}

// TestRoundFiveFixesDoNotBreakTheCorpus is the same cheap guard every round has
// had: a fix that is correct in isolation and wrong in place.
func TestRoundFiveFixesDoNotBreakTheCorpus(t *testing.T) {
	requireGhostscript(t)
	requireVerifierBinaries(t)

	for _, tc := range []struct{ format, name string }{
		{"pdf", "threat_all_classes.pdf"},
		{"pdf", "endstream_in_stream.pdf"},
		{"jpg", "icc_multichunk.jpg"},
		{"jpg", "exif_gps.jpg"},
		{"docm", "macro_enabled.docm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := t.TempDir() + "/out"
			if _, err := sanitizeFile(context.Background(), engineExec{}, tc.format,
				sanitizeCorpusDir+"/"+tc.name, out); err != nil {
				t.Errorf("sanitizeFile: %v", err)
			}
		})
	}
}
