package convert

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestSanitizeReportKeepsTheTwoListsApart is the D-02 test. A lost form is not
// a found attack, and the only structural way to keep a client from reading it
// as one is for the two never to appear in the same field.
func TestSanitizeReportKeepsTheTwoListsApart(t *testing.T) {
	rep, err := BuildSanitizeReport("pdf", SanitizeResult{
		Removed:          []ThreatClass{ThreatJavaScript, ThreatActionDict},
		LostCapabilities: []LostCapability{LostFillableForms, LostBookmarks},
		Verified:         []ThreatClass{ThreatJavaScript},
	})

	for _, lost := range rep.LostCapabilities {
		for _, removed := range rep.Removed {
			if string(lost) == string(removed) {
				t.Errorf("%q appears in both lists; a client cannot tell a cost from a threat", lost)
			}
		}
	}

	blob, err := MarshalSanitizeReport(rep)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"removed", "lost_capabilities", "verified"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("report has no %q field", field)
		}
	}
}

// TestSanitizeReportCarriesOnlyVocabularyCodes is the "no prose" rule made
// mechanical. Every string in either list must be a declared code -- a report
// that grew a free-text entry would otherwise pass every other test here.
func TestSanitizeReportCarriesOnlyVocabularyCodes(t *testing.T) {
	rep, err := BuildSanitizeReport("docm", SanitizeResult{
		Removed:          AllThreatClasses(),
		LostCapabilities: AllLostCapabilities(),
		Verified:         AllThreatClasses(),
	})
	if err != nil {
		t.Fatalf("BuildSanitizeReport rejected the full vocabulary: %v", err)
	}

	for _, c := range append(rep.Removed, rep.Verified...) {
		if !IsKnownThreatClass(c) {
			t.Errorf("report carries an undeclared threat class %q", c)
		}
	}
	for _, c := range rep.LostCapabilities {
		if !IsKnownLostCapability(c) {
			t.Errorf("report carries an undeclared lost capability %q", c)
		}
	}
}

// TestSanitizeReportEmptyListsMarshalAsArrays covers the lossless image path.
// "Nothing was lost" and "the field is missing" are different facts and a
// client should not have to guess which one a null means.
func TestSanitizeReportEmptyListsMarshalAsArrays(t *testing.T) {
	rep, err := BuildSanitizeReport("jpg", SanitizeResult{
		Removed:  []ThreatClass{ThreatDocumentMetadata},
		Verified: []ThreatClass{ThreatDocumentMetadata},
		// LostCapabilities deliberately nil: the image path loses nothing.
	})
	blob, err := MarshalSanitizeReport(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "null") {
		t.Errorf("report marshalled a null:\n%s", blob)
	}
	if !strings.Contains(string(blob), `"lost_capabilities": []`) {
		t.Errorf("empty lost_capabilities did not marshal as an empty array:\n%s", blob)
	}
}

// TestSanitizeReportFromARealRun ties the report to what the operation
// actually did, rather than to hand-built inputs. It is the one test here that
// would notice if a format's handler stopped filling a field.
func TestSanitizeReportFromARealRun(t *testing.T) {
	requireGhostscript(t)
	requireVerifierBinaries(t)

	out := filepath.Join(t.TempDir(), "out.pdf")
	res, err := sanitizeFile(context.Background(), engineExec{}, "pdf",
		filepath.Join(sanitizeCorpusDir, "threat_all_classes.pdf"), out)
	if err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}

	rep, err := BuildSanitizeReport("pdf", res)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) == 0 {
		t.Error("removed is empty after a successful run")
	}
	if len(rep.Verified) == 0 {
		t.Error("verified is empty: the removal ran and nothing confirmed it")
	}
	if len(rep.LostCapabilities) == 0 {
		t.Error("lost_capabilities is empty for the PostScript round trip, which does lose things")
	}
	if rep.GuaranteeScope == "" {
		t.Error("guarantee_scope is empty: the report points nowhere")
	}
}

// TestSanitizeReportDoesNotAliasThePackageLists proves the defensive copy. A
// caller mutating the report must not be able to edit the per-format handler's
// own declared list, which every later job would then inherit.
func TestSanitizeReportDoesNotAliasThePackageLists(t *testing.T) {
	res := SanitizeResult{
		Removed:          append([]ThreatClass(nil), pdfThreatClasses...),
		LostCapabilities: append([]LostCapability(nil), pdfLostCapabilities...),
	}
	rep, err := BuildSanitizeReport("pdf", res)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) == 0 || len(rep.LostCapabilities) == 0 {
		t.Fatal("fixture is empty; this test proves nothing")
	}

	rep.Removed[0] = "mutated"
	rep.LostCapabilities[0] = "mutated"

	if pdfThreatClasses[0] == "mutated" {
		t.Error("report aliases pdfThreatClasses; a caller's edit reaches the package's list")
	}
	if pdfLostCapabilities[0] == "mutated" {
		t.Error("report aliases pdfLostCapabilities")
	}
}

// TestSanitizeReportRefusesUndeclaredCodes is what gives
// IsKnownThreatClass/IsKnownLostCapability a production job.
//
// Both predicates existed with zero production callers -- found by sweeping
// this phase's own exported symbols after PR #12 showed that "declared but
// unconnected" was this phase's dominant defect. Compare the two established
// vocabularies: inspect.AllCodes has 11 production references and errcode.All
// has 8. A predicate nothing calls documents an intent instead of enforcing
// one.
//
// The enforcement matters because docs/SANITIZE.md is held equal to the
// vocabulary, which is what lets a client look up any code it receives. A
// per-format handler's list is an ordinary Go slice, and a typo in one would
// put a meaningless code in front of a client with nothing in the way.
func TestSanitizeReportRefusesUndeclaredCodes(t *testing.T) {
	cases := []struct {
		name string
		res  SanitizeResult
		want string
	}{
		{
			name: "undeclared threat class in removed",
			res:  SanitizeResult{Removed: []ThreatClass{"javascrpt"}},
			want: "removed carries undeclared threat class",
		},
		{
			name: "undeclared threat class in verified",
			res:  SanitizeResult{Verified: []ThreatClass{ThreatJavaScript, "made_up"}},
			want: "verified carries undeclared threat class",
		},
		{
			name: "undeclared lost capability",
			res:  SanitizeResult{LostCapabilities: []LostCapability{"forms_maybe_broken"}},
			want: "lost_capabilities carries undeclared capability",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildSanitizeReport("pdf", tc.res)
			if err == nil {
				t.Fatal("BuildSanitizeReport accepted a code the vocabulary does not declare")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the offending list", err)
			}
		})
	}

	// The rejection must not be so broad that honest input trips it.
	if _, err := BuildSanitizeReport("pdf", SanitizeResult{
		Removed:          pdfThreatClasses,
		LostCapabilities: pdfLostCapabilities,
		Verified:         pdfThreatClasses,
	}); err != nil {
		t.Errorf("a real PDF result was rejected: %v", err)
	}
}
