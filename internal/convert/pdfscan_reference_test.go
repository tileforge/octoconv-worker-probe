package convert

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/tileforge/octoconv-worker-probe/internal/convert/pdfref805d49da"
)

type lexInput struct {
	name string
	data []byte
}

func repositoryPDFsForLexer(t *testing.T) []lexInput {
	t.Helper()
	var paths []string
	for _, g := range []string{
		filepath.Join("testdata", "*.pdf"),
		filepath.Join("testdata", "*", "*.pdf"),
		filepath.Join("testdata", "*", "*", "*.pdf"),
		filepath.Join("..", "inspect", "testdata", "pdf", "*.pdf"),
		filepath.Join("..", "e2e", "testdata", "*.pdf"),
		filepath.Join("..", "..", "scripts", "fixtures", "*.pdf"),
	} {
		m, err := filepath.Glob(g)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, m...)
	}
	sort.Strings(paths)
	if len(paths) < 20 {
		t.Fatalf("found %d repository PDFs, want every PDF of internal/convert/testdata, internal/inspect/testdata/pdf, internal/e2e/testdata and scripts/fixtures", len(paths))
	}
	var in []lexInput
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		in = append(in, lexInput{name: filepath.ToSlash(p), data: data})
	}
	return in
}

func lexXrefPayloadPDF(scanned, inPayload int, pages string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	b.WriteString(pages)
	for n := 1; n <= scanned; n++ {
		fmt.Fprintf(&b, "%d 0 obj\n", n)
	}
	var payload bytes.Buffer
	offsets := make([]int, inPayload)
	first := scanned + 1
	for i := range offsets {
		offsets[i] = payload.Len()
		fmt.Fprintf(&payload, "%d 0 obj\n", first+i)
	}
	header := fmt.Sprintf("<</Length %d>>\nstream\n", payload.Len())
	base := b.Len() + len(header)
	b.WriteString(header)
	b.Write(payload.Bytes())
	b.WriteString("\nendstream\n")
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n%d %d\n", first, len(offsets))
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", base+off)
	}
	fmt.Fprintf(&b, "trailer\n<<>>\nstartxref\n%d\n%%%%EOF\n", xref)
	return b.Bytes()
}

func lexXrefChain(prevKey string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	obj1 := b.Len()
	b.WriteString("1 0 obj\n<</Length 2 0 R>>\nstream\nabcde\nendstream\nendobj\n")
	oldXref := b.Len()
	fmt.Fprintf(&b, "xref\n1 1\n%010d 00000 n \ntrailer\n<<>>\n", obj1)
	obj2 := b.Len()
	b.WriteString("2 0 obj\n5\nendobj\n")
	newXref := b.Len()
	fmt.Fprintf(&b, "xref\n2 1\n%010d 00000 n \ntrailer\n<</Size 3 /%s %d>>\nstartxref\n%d\n%%%%EOF\n", obj2, prevKey, oldXref, newXref)
	return b.Bytes()
}

func lexRepeat(unit string, n int) string {
	return strings.Repeat(unit, n/len(unit)+1)[:n]
}

var (
	lexLongP = strings.Repeat("P", 200)
	lexLongC = strings.Repeat("C", 200)
)

func lexGeneratedInputs() []lexInput {
	const kib64 = 64 << 10
	name64 := strings.Repeat("a", kib64)
	pages := "1 0 obj\n<</Type /Pages /Count 2>>\nendobj\n"
	var in []lexInput
	add := func(name string, data string) {
		in = append(in, lexInput{name: "gen/" + name, data: []byte(data)})
	}
	add("escaped_type", "%PDF-1.4\n1 0 obj\n<</T#79pe /Pages /Count 5>>\nendobj\n")
	add("escaped_type_upper", "%PDF-1.4\n1 0 obj\n<</T#59pe /Pages /Count 5>>\nendobj\n")
	add("escaped_pages", "%PDF-1.4\n1 0 obj\n<</Type /P#61ges /Count 5>>\nendobj\n")
	add("escaped_pages_upper_hex", "%PDF-1.4\n1 0 obj\n<</Type /P#61#67#65s /Count 5>>\nendobj\n")
	add("escaped_count", "%PDF-1.4\n1 0 obj\n<</Type /Pages /C#6funt 5>>\nendobj\n")
	add("escaped_count_upper_hex", "%PDF-1.4\n1 0 obj\n<</Type /Pages /C#6Funt 5>>\nendobj\n")
	add("escaped_space_in_name", "%PDF-1.4\n1 0 obj\n<</Type#20 /Pages /Type /Pages /Count 5>>\nendobj\n")
	add("escaped_length", "%PDF-1.4\n1 0 obj\n<</Le#6egth 5>>\nstream\nabcde\nendstream\nendobj\n"+pages)
	add("escaped_length_bad_hex", "%PDF-1.4\n1 0 obj\n<</Le#6gth 5>>\nstream\nabcde\nendstream\nendobj\n"+pages)
	add("escaped_length_in_dict_value", "%PDF-1.4\n1 0 obj\n<</X /L#65ngth /Length 5>>\nstream\nabcde\nendstream\nendobj\n")
	add("prev_chain_plain", string(lexXrefChain("Prev")))
	add("prev_chain_escaped", string(lexXrefChain("P#72ev")))
	add("prev_chain_prefix", string(lexXrefChain("PrevPage")))
	add("prev_chain_bad_hex", string(lexXrefChain("P#7zev")))
	add("escape_at_end_1", "%PDF-1.4\n"+pages+"<</Type /Pages /Count 2 /X#4")
	add("escape_at_end_2", "%PDF-1.4\n"+pages+"<</Type /Pages /Count 2 /X#")
	add("escape_at_end_3", "%PDF-1.4\n"+pages+"<</Type /Pages#")
	add("escape_at_end_4", "%PDF-1.4\n"+pages+"<</Type /Pa#67")
	add("escape_at_end_5", "%PDF-1.4\n"+pages+"<</Length#")
	add("escape_at_end_6", "%PDF-1.4\n"+pages+"<</Le#6")
	add("long_dict_name", "%PDF-1.4\n1 0 obj\n<</"+name64+" 5>>\nendobj\n"+pages)
	add("long_type_value", "%PDF-1.4\n1 0 obj\n<</Type /"+name64+" /Count 4>>\nendobj\n"+pages)
	add("long_pages_prefix", "%PDF-1.4\n1 0 obj\n<</Type /Pages"+name64+" /Count 4>>\nendobj\n"+pages)
	add("long_keyword", "%PDF-1.4\n"+name64+"\n"+pages)
	add("long_keyword_in_dict", "%PDF-1.4\n1 0 obj\n<</Type /Pages /Count "+name64+" /Count 3>>\nendobj\n")
	add("long_name_before_stream", "%PDF-1.4\n1 0 obj\n<</Length 3 /"+name64+" 1>>\nstream\nabc\nendstream\nendobj\n"+pages)
	add("long_name_in_trailer", "%PDF-1.4\n"+pages+"xref\n0 1\n0000000000 65535 f \ntrailer\n<</"+name64+" 1 /Prev 9>>\nstartxref\n"+fmt.Sprint(len("%PDF-1.4\n")+len(pages))+"\n%%EOF\n")
	add("nested_length", "%PDF-1.4\n1 0 obj\n<</A <</Length 9>> /Length 3>>\nstream\nabc\nendstream\nendobj\n"+pages)
	add("nested_pages", "%PDF-1.4\n1 0 obj\n<</Kids [<</Type /Pages /Count 9>>] /Type /Pages /Count 3>>\nendobj\n")
	add("nested_deep", "%PDF-1.4\n"+strings.Repeat("<</A ", 70)+"<</Type /Pages /Count 1>>"+strings.Repeat(">>", 70))
	add("array_length", "%PDF-1.4\n1 0 obj\n<</Length 5 /Foo [/Length 900]>>\nstream\nabcde\nendstream\nendobj\n")
	add("array_count", "%PDF-1.4\n1 0 obj\n<</Type /Pages /Extra [/Count 300] /Count 2>>\nendobj\n")
	add("indirect_length_after", "%PDF-1.4\n1 0 obj\n<</Length 2 0 R>>\nstream\nabcde\nendstream\nendobj\n2 0 obj\n5\nendobj\n")
	add("indirect_count", "%PDF-1.4\n1 0 obj\n<</Type /Pages /Count 2 0 R>>\nendobj\n2 0 obj\n6\nendobj\n")
	add("unresolved_length", "%PDF-1.4\n1 0 obj\n<</Length 99>>\nstream\nabcde\nendstream\nendobj\n"+pages)
	add("unresolved_indirect", "%PDF-1.4\n1 0 obj\n<</Length 7 0 R>>\nstream\nabcde\nendstream\nendobj\n"+pages)
	add("many_resolved_streams", "%PDF-1.4\n"+lexRepeat("<</Length 0>>stream\nendstream\n", kib64)+"\n"+pages)
	add("objx", "%PDF-1.4\n1 0 objx\n2 0 obj\n3 0 obj1\n4 0 ob\n5 0 obj\n"+pages)
	add("streamline", "%PDF-1.4\n1 0 obj\n<</Length 3>>streamline\nabc\nendstream\nendobj\n2 0 obj\n<</Length 3>>stream\nabc\nendstream\nendobj\n"+pages)
	add("stream_prefix", "%PDF-1.4\n1 0 obj\n<</Length 3>>strea\nabc\nendstream\nendobj\n"+pages)
	add("endstreamx", "%PDF-1.4\n1 0 obj\n<</Length 3>>\nstream\nabc\nendstreamx\nendobj\n"+pages)
	add("long_type_name_exact", "%PDF-1.4\n1 0 obj\n<</Type /"+lexLongP+" /Count 4>>\nendobj\n"+pages)
	add("long_type_name_longer", "%PDF-1.4\n1 0 obj\n<</Type /"+lexLongP+"P /Count 4>>\nendobj\n"+pages)
	add("long_type_name_shorter", "%PDF-1.4\n1 0 obj\n<</Type /"+lexLongP[1:]+" /Count 4>>\nendobj\n"+pages)
	add("long_type_name_escaped", "%PDF-1.4\n1 0 obj\n<</Type /P#50"+lexLongP[2:]+" /Count 6>>\nendobj\n"+pages)
	add("long_key_exact", "%PDF-1.4\n1 0 obj\n<</Type /Pages /"+lexLongC+" 7>>\nendobj\n")
	add("long_key_escaped", "%PDF-1.4\n1 0 obj\n<</Type /Pages /#43"+lexLongC[1:]+" 8>>\nendobj\n")
	add("long_key_longer", "%PDF-1.4\n1 0 obj\n<</Type /Pages /"+lexLongC+"C 7>>\nendobj\n")
	add("page_rotate", "%PDF-1.4\n1 0 obj\n<</Type /Page /Rotate 90>>\nendobj\n2 0 obj\n<</Type /Page /Rot#61te 180>>\nendobj\n")
	add("catalog_version", "%PDF-1.4\n1 0 obj\n<</Type /Catalog /Version 3>>\nendobj\n2 0 obj\n<</Type /Cat#61log /Version 4>>\nendobj\n")
	for _, union := range []int{pdfMaxIndexedObjects - 1, pdfMaxIndexedObjects, pdfMaxIndexedObjects + 1} {
		scanned := pdfMaxIndexedObjects / 2
		add(fmt.Sprintf("xref_in_payload/union=%d", union), string(lexXrefPayloadPDF(scanned, union-scanned, "")))
		add(fmt.Sprintf("xref_in_payload_pages/union=%d", union), string(lexXrefPayloadPDF(scanned, union-scanned, "<</Type /Pages /Count 3>>\n<</Type /Page /Rotate 90>>\n<</Type /Catalog /Version 2>>\n")))
	}
	return in
}

var lexMutationTokens = []string{
	"obj", "objx", "stream", "streamline", "endstream", "endobj", " R", "(", ")", "<", ">", "<<", ">>", "[", "]", "%", "\n", "\\", "#", "#4", "#6",
	"/Length ", "/Le#6egth ", "/Prev ", "/P#72ev ", "/Type /Pages /Count 9", "/Type /Page /Rotate 270", "/" + lexLongP, "/" + lexLongC, " 0 R", "1 0 obj\n",
}

func lexMutations(bases []lexInput, n int) []lexInput {
	rng := rand.New(rand.NewPCG(78, 17))
	out := make([]lexInput, 0, n)
	for i := 0; i < n; i++ {
		base := bases[rng.IntN(len(bases))]
		data := append([]byte(nil), base.data...)
		for ops := 1 + rng.IntN(4); ops > 0 && len(data) > 0; ops-- {
			at := rng.IntN(len(data))
			switch rng.IntN(6) {
			case 0:
				data[at] ^= byte(1 + rng.IntN(255))
			case 1:
				tok := lexMutationTokens[rng.IntN(len(lexMutationTokens))]
				data = append(data[:at], append([]byte(tok), data[at:]...)...)
			case 2:
				end := min(len(data), at+1+rng.IntN(64))
				data = append(data[:at], data[end:]...)
			case 3:
				data = data[:at]
			case 4:
				end := min(len(data), at+1+rng.IntN(256))
				seg := append([]byte(nil), data[at:end]...)
				data = append(data[:end], append(seg, data[end:]...)...)
			case 5:
				data[at] = "()<>%\n\\/#"[rng.IntN(9)]
			}
		}
		out = append(out, lexInput{name: fmt.Sprintf("mutation/%04d/%s", i, base.name), data: data})
	}
	return out
}

func lexerReferenceCorpus(t *testing.T) []lexInput {
	t.Helper()
	in := repositoryPDFsForLexer(t)
	for i, s := range pdfLexFuzzSeeds {
		in = append(in, lexInput{name: fmt.Sprintf("fuzz_seed/%02d", i), data: s})
	}
	gen := lexGeneratedInputs()
	in = append(in, gen...)
	var bases []lexInput
	for _, c := range append(append([]lexInput{}, gen...), in[:len(in)-len(gen)]...) {
		if len(c.data) <= 256<<10 {
			bases = append(bases, c)
		}
	}
	in = append(in, lexMutations(bases, 2000)...)
	return in
}

func sameStreams(a, b [][2]int) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func scanDiffers(got pdfScan, want pdfref805d49da.ScanResult) string {
	var d []string
	if !reflect.DeepEqual(got.objects, want.Objects) {
		d = append(d, fmt.Sprintf("objects %d vs %d", len(got.objects), len(want.Objects)))
	}
	if !sameStreams(got.streams, want.Streams) {
		d = append(d, fmt.Sprintf("streams %d vs %d", len(got.streams), len(want.Streams)))
	}
	if got.unresolved != want.Unresolved {
		d = append(d, fmt.Sprintf("unresolved %d vs %d", got.unresolved, want.Unresolved))
	}
	if got.objectsCapped != want.ObjectsCapped {
		d = append(d, fmt.Sprintf("objectsCapped %v vs %v", got.objectsCapped, want.ObjectsCapped))
	}
	return strings.Join(d, ", ")
}

func TestPDFScanMatchesTheReference805d49da(t *testing.T) {
	corpus := lexerReferenceCorpus(t)
	streams, objects := 0, 0
	for _, c := range corpus {
		b := c.data
		ref := pdfref805d49da.ScanPDF(b)
		if d := scanDiffers(scanPDF(b), ref); d != "" {
			t.Errorf("%s: scanPDF differs from 805d49da: %s", c.name, d)
		}
		streams += len(ref.Streams)
		objects += len(ref.Objects)
		xref := pdfXrefObjects(b)
		refXref := pdfref805d49da.XrefObjects(b)
		if !reflect.DeepEqual(xref, refXref) {
			t.Errorf("%s: pdfXrefObjects differs from 805d49da: %d vs %d entries", c.name, len(xref), len(refXref))
		}
		if d := scanDiffers(scanPDFSeeded(b, xref), pdfref805d49da.ScanPDFSeeded(b, refXref)); d != "" {
			t.Errorf("%s: scanPDFSeeded(b, pdfXrefObjects(b)) differs from 805d49da: %s", c.name, d)
		}
		limited := scanPDFLimited(b, nil, pdfMaxIndexedObjects, nil)
		refLimited := pdfref805d49da.ScanPDFLimited(b, pdfref805d49da.MaxIndexedObjects)
		if len(limited.streams) != 0 {
			t.Errorf("%s: the page-count scan kept %d streams, want none", c.name, len(limited.streams))
		}
		refLimited.Streams = nil
		if d := scanDiffers(limited, refLimited); d != "" {
			t.Errorf("%s: the page-count scan differs from 805d49da: %s", c.name, d)
		}
	}
	t.Logf("scanPDF, scanPDFSeeded(b, pdfXrefObjects(b)), pdfXrefObjects and scanPDFLimited compared with 805d49da on %d inputs (%d streams and %d objects in the reference scans)", len(corpus), streams, objects)
}

var typedDictPairs = []struct{ typeName, key string }{
	{"Pages", "Count"},
	{"Page", "Rotate"},
	{"Catalog", "Version"},
	{lexLongP, "Count"},
	{"Pages", lexLongC},
}

func TestPDFTypedDictUintsMatchesTheReferenceOutsideTheClosedList(t *testing.T) {
	corpus := lexerReferenceCorpus(t)
	fired, differed, answered := 0, 0, 0
	var example string
	for _, c := range corpus {
		b := c.data
		capped := pdfref805d49da.MergedObjects(b) > pdfref805d49da.MaxIndexedObjects
		for _, p := range typedDictPairs {
			got, gotHit := PDFTypedDictUints(b, p.typeName, p.key, 8192, nil)
			want, wantHit := pdfref805d49da.PDFTypedDictUints(b, p.typeName, p.key, 8192)
			if len(want) > 0 {
				answered++
			}
			if capped {
				fired++
				if want != nil || !wantHit {
					differed++
					if example == "" {
						example = fmt.Sprintf("%s (%.20s, %.20s): reference %v/%v, C1 (nil, true)", c.name, p.typeName, p.key, want, wantHit)
					}
				}
				want, wantHit = nil, true
			}
			if !reflect.DeepEqual(got, want) || gotHit != wantHit {
				t.Errorf("%s (%.20s, %.20s): PDFTypedDictUints = %v/%v, want %v/%v (C1 %v)", c.name, p.typeName, p.key, got, gotHit, want, wantHit, capped)
			}
		}
	}
	t.Logf("PDFTypedDictUints compared with 805d49da on %d inputs x %d pairs (%d answers with values in the reference); C1 fired %d times, the reference differed from (nil, true) %d times, e.g. %s", len(corpus), len(typedDictPairs), answered, fired, differed, example)
	if fired == 0 {
		t.Error("C1 never fired on the corpus")
	}
	if differed == 0 {
		t.Error("C1 fired and never differed from the reference")
	}
}

func lexTokenHeads(n int) []lexInput {
	head := "%PDF-1.4\n"
	xrefHead := head + "xref\n0 1\n0000000000 65535 f \ntrailer\n<</"
	xrefTail := " /Prev 0>>\nstartxref\n9\n%%EOF\n"
	return []lexInput{
		{"dict_name", []byte(head + "1 0 obj\n<</" + strings.Repeat("a", n-len(head)-len("1 0 obj\n<</>>\nendobj\n")) + ">>\nendobj\n")},
		{"keyword", []byte(head + strings.Repeat("a", n-len(head)))},
		{"type_value", []byte(head + "1 0 obj\n<</Type /" + strings.Repeat("a", n-len(head)-len("1 0 obj\n<</Type />>\nendobj\n")) + ">>\nendobj\n")},
		{"trailer_name_before_prev", []byte(xrefHead + strings.Repeat("a", n-len(xrefHead)-len(xrefTail)) + xrefTail)},
	}
}

func TestPDFTokensDoNotMaterialize(t *testing.T) {
	const n = 8 << 20
	const ceiling = 1 << 20
	for _, c := range lexTokenHeads(n) {
		b := c.data
		for _, call := range []struct {
			name string
			run  func()
		}{
			{"PDFTypedDictUints", func() { _, _ = PDFTypedDictUints(b, "Pages", "Count", 8192, nil) }},
			{"scanPDF", func() { _ = scanPDF(b) }},
			{"pdfXrefObjects", func() { _ = pdfXrefObjects(b) }},
		} {
			alloc := allocDuring(call.run)
			t.Logf("%s (%d B): %s allocated %d B (%.2f MiB), ceiling %d B", c.name, len(b), call.name, alloc, float64(alloc)/(1<<20), ceiling)
			if alloc > ceiling {
				t.Errorf("%s: %s allocated %d B on a %d B head, want at most %d B: a token is materialized", c.name, call.name, alloc, len(b), ceiling)
			}
		}
	}
}

func TestPDFPageCountScanKeepsNoStreamList(t *testing.T) {
	const n = 8 << 20
	b := []byte("%PDF-1.4\n" + lexRepeat("<</Length 0>>stream\nendstream\n", n-len("%PDF-1.4\n")))
	var values []int
	var hit bool
	alloc := allocDuring(func() { values, hit = PDFTypedDictUints(b, "Pages", "Count", 8192, nil) })
	got := scanPDF(b)
	want := pdfref805d49da.ScanPDF(b)
	t.Logf("%d B of resolved streams: PDFTypedDictUints = %v/%v allocated %d B (%.2f MiB); scanPDF %d streams, 805d49da %d", len(b), values, hit, alloc, float64(alloc)/(1<<20), len(got.streams), len(want.Streams))
	if alloc > 1<<20 {
		t.Errorf("PDFTypedDictUints allocated %d B, want at most %d B: the page-count scan keeps a stream list nobody reads", alloc, 1<<20)
	}
	if len(want.Streams) == 0 || !sameStreams(got.streams, want.Streams) {
		t.Errorf("scanPDF found %d streams, 805d49da %d: the sanitizer's scan must keep every stream", len(got.streams), len(want.Streams))
	}
}

var lexerNameConstants = []string{"Length", "Prev", "Type", "Pages", "Count", "Page", "Rotate", "Catalog", "Version", lexLongP, lexLongC, ""}

var lexerKeywordConstants = []string{"obj", "stream", "endstream", "endobj", "R", ""}

func changedByOneByte(s string) []string {
	if s == "" {
		return []string{"a"}
	}
	b := []byte(s)
	b[len(b)/2] ^= 1
	return []string{string(b), s[:len(s)-1], s + "a", s + "#"}
}

func randomNameBuffers(n int) [][]byte {
	rng := rand.New(rand.NewPCG(78, 171))
	alphabet := "aAzZ#0146efF \n/()<>[]%"
	var out [][]byte
	for i := 0; i < n; i++ {
		var b bytes.Buffer
		b.WriteByte('/')
		if rng.IntN(2) == 0 {
			c := lexerNameConstants[rng.IntN(len(lexerNameConstants))]
			for j := 0; j < len(c); j++ {
				if rng.IntN(3) == 0 {
					hex := fmt.Sprintf("#%02x", c[j])
					if rng.IntN(2) == 0 {
						hex = strings.ToUpper(hex)
					}
					b.WriteString(hex)
				} else {
					b.WriteByte(c[j])
				}
			}
		}
		for j := rng.IntN(8); j > 0; j-- {
			b.WriteByte(alphabet[rng.IntN(len(alphabet))])
		}
		data := b.Bytes()
		if rng.IntN(3) == 0 && len(data) > 1 {
			data = data[:1+rng.IntN(len(data)-1)]
		}
		out = append(out, data)
	}
	return out
}

func tokenStarts(b []byte, limit int) []int {
	var out []int
	for i := 0; i < len(b) && len(out) < limit; i++ {
		if isPDFSpace(b[i]) {
			continue
		}
		if i == 0 || isPDFSpace(b[i-1]) || isPDFDelimiter(b[i-1]) {
			out = append(out, i)
		}
	}
	return out
}

func TestPDFNameAndKeywordComparisonsMatchTheReference(t *testing.T) {
	var buffers [][]byte
	for _, c := range lexerReferenceCorpus(t) {
		buffers = append(buffers, c.data)
	}
	buffers = append(buffers, randomNameBuffers(5000)...)
	names, keywords, compared := 0, 0, 0
	for _, b := range buffers {
		slashes := 0
		for i := 0; i < len(b) && slashes < 4096; i++ {
			if b[i] != '/' {
				continue
			}
			slashes++
			names++
			ref, refNext := pdfref805d49da.ReadName(b, i)
			if got := pdfSkipName(b, i); got != refNext {
				t.Fatalf("name at %d of %.40q: pdfSkipName ends at %d, the 805d49da ReadName at %d", i, b[i:], got, refNext)
			}
			candidates := append(append([]string{ref}, changedByOneByte(ref)...), lexerNameConstants...)
			for _, s := range candidates {
				compared++
				if got, want := pdfNameEquals(b, i, s), ref == s; got != want {
					t.Fatalf("name at %d of %.40q decodes to %.40q: pdfNameEquals(%.40q) = %v, want %v", i, b[i:], ref, s, got, want)
				}
			}
		}
		for _, i := range tokenStarts(b, 4096) {
			keywords++
			ref, refNext := pdfref805d49da.ReadKeyword(b, i)
			word, next := pdfKeywordAt(b, i)
			if string(word) != ref || next != refNext {
				t.Fatalf("keyword at %d of %.40q: pdfKeywordAt = %.40q ending at %d, the 805d49da ReadKeyword %.40q ending at %d", i, b[i:], word, next, ref, refNext)
			}
			candidates := append(append([]string{ref}, changedByOneByte(ref)...), lexerKeywordConstants...)
			for _, s := range candidates {
				compared++
				if got, want := pdfKeywordIs(word, s), ref == s; got != want {
					t.Fatalf("keyword at %d of %.40q is %.40q: pdfKeywordIs(%.40q) = %v, want %v", i, b[i:], ref, s, got, want)
				}
			}
		}
	}
	t.Logf("%d names and %d keywords over %d buffers, %d comparisons equal to the decoded 805d49da token", names, keywords, len(buffers), compared)
}
