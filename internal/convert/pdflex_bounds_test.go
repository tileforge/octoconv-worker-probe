package convert

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"

	"github.com/tileforge/octoconv-worker-probe/internal/convert/pdfref805d49da"
)

// Two allocation bounds, both measured before they existed and both on paths
// that run in the API process -- internal/inspect reads up to its 8 MiB budget
// through this tokenizer for every POST /v1/inspect, and the sanitize worker
// reads whole uploads through it.
//
// They are asserted as ALLOCATION, not as wall time: time is a property of the
// machine, and a bound that only holds on a fast laptop is not a bound.

// allocDuring reports bytes allocated while f runs.
func allocDuring(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestScanPDFDoesNotGrowOnALongIntegerRun is the one that was NOT in the todo
// and turned out to be the real cost.
//
// The walk keeps "the last two integer tokens", and it kept them by trimming
// with ints = ints[len(ints)-2:] -- which re-slices the SAME backing array, so
// append grows that array for the life of the walk. A cross-reference table is
// a long run of integers and nothing else, so it was the worst case:
//
//	20 971 614 bytes in, 48.0 MB allocated in scanPDF alone (~2.3x the input)
//
// After: 0.0 MB, and the walk itself went from 96ms to 54ms.
func TestScanPDFDoesNotGrowOnALongIntegerRun(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n1 0 obj\n<< /Type /Pages /Count 2 >>\nendobj\n")
	xrefAt := buf.Len()
	buf.WriteString("xref\n0 1048576\n")
	for i := 0; i < 1048575; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", 9)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 1048576 >>\nstartxref\n%d\n%%%%EOF\n", xrefAt)
	big := buf.Bytes()

	var got pdfScan
	alloc := allocDuring(func() { got = scanPDF(big) })

	// Generous by design: the point is that allocation does not SCALE with the
	// run, not that it is exactly zero. Before the fix this was 48 MB on this
	// very input.
	const ceiling = 1 << 20
	if alloc > ceiling {
		t.Fatalf("scanPDF allocated %.1f MB walking a %d-byte file that is mostly an xref table; "+
			"the last-two-integers window is growing its backing array again",
			float64(alloc)/(1<<20), len(big))
	}
	if len(got.objects) != 1 {
		t.Fatalf("objects = %d, want 1 -- the walk stopped seeing structure", len(got.objects))
	}
}

// TestTypedDictScanIsBoundedByNestingDepth is the second finding the todo
// recorded, and the reason PDFTypedDictUints could not be restored as it was:
// maxDicts bounds how many dictionaries are visited, and nothing bounded how
// deep they nest, so the frame stack grew with the nesting.
//
//	2 097 169 bytes of "<<" cost 131.4 MB before maxPDFDictDepth existed.
func TestTypedDictScanIsBoundedByNestingDepth(t *testing.T) {
	deep := append([]byte("%PDF-1.4\n1 0 obj\n"), bytes.Repeat([]byte("<<"), 1<<20)...)

	var values []int
	var ceiling bool
	alloc := allocDuring(func() { values, ceiling = PDFTypedDictUints(deep, "Pages", "Count", 1<<20, nil) })

	if !ceiling {
		t.Fatal("a file nesting a million dictionaries did not report a ceiling: a walk that answers " +
			"here is answering from a stack it grew to the file's own depth")
	}
	if values != nil {
		t.Fatalf("values = %v alongside a ceiling; an inflated integer is worse than an honest unknown", values)
	}
	const ceilingBytes = 1 << 20
	if alloc > ceilingBytes {
		t.Fatalf("PDFTypedDictUints allocated %.1f MB on %d bytes of nesting", float64(alloc)/(1<<20), len(deep))
	}
}

// TestRealFilesStillResolveAfterTheBounds is the other half. A bound that
// refuses ordinary documents trades a resource finding for a correctness one,
// which is the worse trade -- so the files this repository pins must still
// parse, with their streams found.
func TestRealFilesStillResolveAfterTheBounds(t *testing.T) {
	for _, name := range []string{
		"testdata/sanitize/threat_all_classes.pdf",
		"testdata/ocr/multipage_text.pdf",
		"testdata/verapdf_noncompliant.pdf",
	} {
		t.Run(name, func(t *testing.T) {
			raw := readFixtureOrSkip(t, name)
			ranges, err := pdfStreamPayloads(raw)
			if err != nil {
				t.Fatalf("a pinned file stopped resolving: %v", err)
			}
			if len(ranges) == 0 {
				t.Fatal("no streams found in a real PDF: the walk is not seeing structure")
			}
		})
	}
}

func TestNamesOutsideDictionariesAreNotDecoded(t *testing.T) {
	body := bytes.Repeat([]byte("/a"), (8<<20)/2)

	var values []int
	var ceiling bool
	alloc := allocDuring(func() { values, ceiling = PDFTypedDictUints(body, "Pages", "Count", 8192, nil) })

	if len(values) != 0 || ceiling {
		t.Fatalf("a file of bare names answered (values=%v ceiling=%v); it declares no dictionary at all",
			values, ceiling)
	}
	const ceilingBytes = 1 << 20
	if alloc > ceilingBytes {
		t.Fatalf("walking %d bytes of bare names allocated %.1f MB: names are being decoded where they "+
			"cannot be keys, in the API process, on a window a client supplies",
			len(body), float64(alloc)/(1<<20))
	}
}

// TestUnrelatedDictionariesDoNotExhaustTheLookup is PR #18's P2, and it is the
// opposite kind of defect: a bound that refuses valid work.
//
// The first version of the cap counted EVERY dictionary, so an ordinary
// annotated document -- a form, a PDF with many resources -- hit a work ceiling
// before its page tree was reached, and the public page_count characteristic
// went from an integer to null.
func TestUnrelatedDictionariesDoNotExhaustTheLookup(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	for i := 0; i < 9000; i++ {
		buf.WriteString("<< /Annot 1 >>")
	}
	buf.WriteString("1 0 obj\n<< /Type /Pages /Count 42 >>\nendobj\n")

	values, ceiling := PDFTypedDictUints(buf.Bytes(), "Pages", "Count", 8192, nil)
	if ceiling {
		t.Fatal("9 000 unrelated dictionaries exhausted the page lookup: the cap is counting " +
			"dictionaries that have nothing to do with what was asked for")
	}
	if len(values) != 1 || values[0] != 42 {
		t.Fatalf("values = %v, want [42]", values)
	}
}

// TestXrefIndexCapIsTheCallersChoice is PR #18's third finding. The cap was
// derived for the 8 MiB inspect window and applied unconditionally, including
// to pdfStreamPayloads -- which verifies whole sanitizer OUTPUT inside a
// cgroup, under a measured timeout, on a file the service produced itself. A
// silently partial index there can leave a forward /Length unresolved, and
// verifySanitized would then reject a valid job to save memory the worker has.
func TestXrefIndexCapIsTheCallersChoice(t *testing.T) {
	raw := readFixtureOrSkip(t, "testdata/ocr/multipage_text.pdf")

	uncapped := pdfXrefObjects(raw)
	if len(uncapped) == 0 {
		t.Skip("this fixture has no classic xref table to index")
	}
	capped := pdfXrefObjectsLimited(raw, 1)
	if len(capped) > 1 {
		t.Fatalf("a cap of 1 indexed %d entries: the limit is not applied", len(capped))
	}
	if len(uncapped) <= len(capped) {
		t.Fatalf("the uncapped index (%d) is no larger than a cap of 1 (%d) -- the worker's path is "+
			"still taking the inspect window's limit", len(uncapped), len(capped))
	}
}

func TestSkipNameAgreesWithReadName(t *testing.T) {
	for _, src := range []string{
		"/Length", "/Length1", "/Count300", "/a", "/",
		"/P#72ev", "/P#7", "/P#zz", "/P#7z", "/#41#42",
		"/Name/Next", "/Name<</k 1>>", "/Name[1]", "/Name(str)", "/Name%c\n",
		"/Name ", "/Name\t", "/Name\n", "/Name\x00",
	} {
		t.Run(src, func(t *testing.T) {
			b := []byte(src)
			_, want := pdfref805d49da.ReadName(b, 0)
			got := pdfSkipName(b, 0)
			if got != want {
				t.Fatalf("pdfSkipName ended at %d, the 805d49da ReadName at %d, for %q: the two walks would "+
					"read the next token from different places", got, want, src)
			}
		})
	}
}

// TestNameBetweenDictionaryAndStreamIsNotAStream pins a rule the fast path for
// names silently broke, and that no existing test noticed.
//
// "stream" is a stream keyword only DIRECTLY after a dictionary. The walk
// tracks that with dictClosed, which every token that is not the keyword
// clears -- and the skip-without-decoding path added for the allocation finding
// cleared awaitLength and the integer window but not dictClosed. The effect was
// fail-OPEN, which is the wrong direction for a sanitizer's verifier:
//
//	<< /Length 20 >> /Foo stream ... endstream
//	before the fast path   no stream (a name intervenes)
//	with it                a 20-byte payload accepted on a malformed file
//
// Found by reading my own diff against the branch it replaced, after the review
// that prompted it had already passed.
func TestNameBetweenDictionaryAndStreamIsNotAStream(t *testing.T) {
	src := []byte("%PDF-1.4\n1 0 obj\n<< /Length 20 >> /Foo stream\n" +
		"AAAAAAAAAAAAAAAAAAAA\nendstream\nendobj\n")

	sc := scanPDF(src)
	if len(sc.streams) != 0 {
		t.Fatalf("streams = %v, want none: a name sits between the dictionary and the keyword, so "+
			"that keyword is not this dictionary's stream", sc.streams)
	}
}
