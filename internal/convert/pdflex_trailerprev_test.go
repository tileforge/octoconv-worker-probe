package convert

import (
	"os"
	"testing"
)

// pdfTrailerPrev walks the /Prev chain that pdfXrefObjects follows, and it used
// to do it with two byte searches: the first ">>" and the first "/Prev"
// substring inside it. Every way that is wrong was reproduced by RUNNING the
// old implementation, and the results are the table below.
//
// WHY THIS MATTERS MORE THAN IT LOOKS. It is not a security hole:
// pdfXrefObjects verifies that every offset it takes actually carries that
// object's own "N G obj" header, so a chain led astray yields FEWER objects,
// never wrong ones. But fewer means a forward "/Length 6 0 R" goes unresolved,
// and verifySanitized then fails closed ON A VALID FILE -- refusing valid work
// is the defect class this project has paid for most (63-02 removed an entire
// admission gate for it).
//
// Raised as an aside in PR #15's todo ("also open, and independent of all the
// above"), where it was noted as affecting the sanitize worker TODAY rather
// than only inspect.
func TestTrailerPrevReadsTheKeyNotASubstring(t *testing.T) {
	cases := []struct {
		name string
		dict string
		want int
		ok   bool
		was  string
	}{
		{
			name: "a decoy inside a literal string",
			dict: "<< /Note (/Prev 999) /Prev 12345 >>",
			want: 12345, ok: true,
			was: "followed 999 -- the decoy, because the search was for bytes and a string is bytes",
		},
		{
			name: "a nested dictionary's own /Prev",
			dict: "<< /Sub << /Prev 999 >> /Prev 12345 >>",
			want: 12345, ok: true,
			was: "followed 999 -- the first /Prev in the file, at any depth",
		},
		{
			name: "a key that merely starts with Prev",
			dict: "<< /PrevPage 999 /Prev 12345 >>",
			want: 12345, ok: true,
			was: "found nothing: it matched /PrevPage, then failed to read 'Page' as an integer",
		},
		{
			name: "an angle pair inside a string",
			dict: "<< /Note (>>) /Prev 12345 >>",
			want: 12345, ok: true,
			was: "found nothing: the dictionary was cut at the >> inside the string",
		},
		{
			name: "a reference where the spec requires a direct integer",
			dict: "<< /Prev 5 0 R >>",
			want: 0, ok: false,
			was: "returned 5 -- an OBJECT NUMBER used as a byte offset",
		},
		{
			name: "a name written with an escape",
			dict: "<< /P#72ev 12345 >>",
			want: 12345, ok: true,
			was: "found nothing: /P#72ev is /Prev, and a byte search cannot know that",
		},
		{
			name: "the ordinary case",
			dict: "<< /Size 9 /Prev 12345 /Root 1 0 R >>",
			want: 12345, ok: true,
		},
		{
			name: "no /Prev at all",
			dict: "<< /Size 9 /Root 1 0 R >>",
			want: 0, ok: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := pdfTrailerPrev([]byte(tc.dict), 0)
			if ok != tc.ok || got != tc.want {
				msg := "pdfTrailerPrev(%q) = (%d, %v), want (%d, %v)"
				if tc.was != "" {
					msg += "\n  before the tokenizer walk, this " + tc.was
				}
				t.Fatalf(msg, tc.dict, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestTrailerPrevStillReadsRealFiles is the other half, and the one that would
// catch a "fix" that refuses everything: the xref chains of the PDFs this
// repository actually pins must still resolve. A stricter reader that fails
// closed on real ghostscript output would trade a wrong number for a refused
// document, which is the worse of the two.
func TestTrailerPrevStillReadsRealFiles(t *testing.T) {
	for _, name := range []string{
		"testdata/sanitize/threat_all_classes.pdf",
		"testdata/sanitize/endstream_in_stream.pdf",
		"testdata/ocr/multipage_text.pdf",
		"testdata/ocr/multipage_image_only.pdf",
		"testdata/verapdf_noncompliant.pdf",
	} {
		t.Run(name, func(t *testing.T) {
			raw := readFixtureOrSkip(t, name)
			if _, err := pdfStreamPayloads(raw); err != nil {
				t.Fatalf("a pinned file no longer resolves: %v", err)
			}
		})
	}
}

// readFixtureOrSkip keeps this file honest about what it did NOT read: a
// missing fixture skips loudly rather than passing quietly, because a table of
// real files that silently contains none of them asserts nothing.
func readFixtureOrSkip(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Skipf("fixture %s is not present: %v", name, err)
	}
	if len(raw) == 0 {
		t.Fatalf("fixture %s is empty", name)
	}
	return raw
}
