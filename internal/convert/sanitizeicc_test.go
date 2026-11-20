package convert

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// iccChunksOf pulls the (sequence, count, data) triples out of a JPEG's APP2
// ICC chunks, walking the file independently of both production walkers so a
// bug in either cannot make these tests agree with it.
func iccChunksOf(t *testing.T, raw []byte) (seqs []int, counts []int, assembled []byte) {
	t.Helper()
	tag := []byte("ICC_PROFILE\x00")
	i := 2
	for i+3 < len(raw) {
		if raw[i] != 0xFF {
			break
		}
		for i+2 < len(raw) && raw[i+1] == 0xFF {
			i++
		}
		marker := raw[i+1]
		if marker == 0xD9 {
			break
		}
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			i += 2
			continue
		}
		segLen := int(binary.BigEndian.Uint16(raw[i+2 : i+4]))
		if segLen < 2 || i+2+segLen > len(raw) {
			break
		}
		end := i + 2 + segLen
		if marker == 0xDA {
			next, err := skipEntropyCodedScan(raw, end)
			if err != nil {
				break
			}
			i = next
			continue
		}
		if p := raw[i+4 : end]; marker == 0xE2 && bytes.HasPrefix(p, tag) && len(p) >= 14 {
			seqs = append(seqs, int(p[12]))
			counts = append(counts, int(p[13]))
			assembled = append(assembled, p[14:]...)
		}
		i = end
	}
	return seqs, counts, assembled
}

// TestSanitizeKeepsAMultiChunkICCProfileWhole is SANI-07.
//
// The fixture's chunk 2 begins with 00 00 00 04. Those four bytes are the
// profile's size field in chunk 1 and ordinary profile data everywhere else, so
// the per-chunk check this replaced read them as a declared size of 4, decided
// a 64-byte chunk could not belong to a 4-byte profile, and dropped it --
// leaving a file that still decodes, still reports its colour profile as
// preserved, and renders with the wrong colours.
//
// Observed before the fix: three chunks in, two out.
func TestSanitizeKeepsAMultiChunkICCProfileWhole(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(sanitizeCorpusDir, "icc_multichunk.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	inSeqs, inCounts, inProfile := iccChunksOf(t, raw)
	if len(inSeqs) != 3 {
		t.Fatalf("fixture has %d ICC chunks, want 3; it cannot test what it exists to test", len(inSeqs))
	}

	out, err := stripJPEGMetadata(raw)
	if err != nil {
		t.Fatalf("stripJPEGMetadata: %v", err)
	}
	outSeqs, outCounts, outProfile := iccChunksOf(t, out)

	if len(outSeqs) != len(inSeqs) {
		t.Fatalf("ICC chunks: %d in, %d out -- a profile lost a chunk", len(inSeqs), len(outSeqs))
	}
	for i := range inSeqs {
		if outSeqs[i] != inSeqs[i] || outCounts[i] != inCounts[i] {
			t.Errorf("chunk %d: sequence/count changed from %d/%d to %d/%d",
				i, inSeqs[i], inCounts[i], outSeqs[i], outCounts[i])
		}
	}
	if !bytes.Equal(inProfile, outProfile) {
		t.Errorf("the assembled profile changed: %d bytes in, %d bytes out", len(inProfile), len(outProfile))
	}

	// The same file's APP1 must still be gone. A "fix" that kept every APP
	// segment would pass every assertion above.
	if bytes.Contains(out, []byte("Exif\x00\x00")) {
		t.Error("the APP1/Exif segment survived; the fix turned into 'keep everything'")
	}
}

// TestSanitizeDropsAnIncompleteICCSetWhole pins the other half: a profile that
// is not whole is not kept in part. Half a profile is not a smaller profile --
// it decodes, it looks preserved, and it is wrong.
func TestSanitizeDropsAnIncompleteICCSetWhole(t *testing.T) {
	profile := func(n int) []byte {
		b := make([]byte, n)
		binary.BigEndian.PutUint32(b[:4], uint32(n))
		for i := 4; i < n; i++ {
			b[i] = byte(i)
		}
		return b
	}

	cases := []struct {
		name   string
		chunks [][]byte
	}{
		{
			name: "gap in the sequence",
			chunks: [][]byte{
				append(append([]byte("ICC_PROFILE\x00"), 1, 3), profile(96)[:32]...),
				append(append([]byte("ICC_PROFILE\x00"), 3, 3), profile(96)[64:]...),
			},
		},
		{
			name: "chunks disagree about the count",
			chunks: [][]byte{
				append(append([]byte("ICC_PROFILE\x00"), 1, 2), profile(64)[:32]...),
				append(append([]byte("ICC_PROFILE\x00"), 2, 3), profile(64)[32:]...),
			},
		},
		{
			name: "a sequence number repeats",
			chunks: [][]byte{
				append(append([]byte("ICC_PROFILE\x00"), 1, 2), profile(64)[:32]...),
				append(append([]byte("ICC_PROFILE\x00"), 1, 2), profile(64)[32:]...),
			},
		},
		{
			// ISOLATES the sequence-completeness check. Everything else is
			// consistent: both chunks agree the count is 3, both sequence
			// numbers are in range and distinct, and the assembled data is
			// exactly the declared 64 bytes. Only "there are 2 chunks and the
			// set claims 3" rejects this. Written this way because the first
			// version of this case was ALSO caught by the size check, so
			// removing the completeness check left every test green -- found
			// by inverting, not by reading.
			name: "count says three, only two chunks are present",
			chunks: [][]byte{
				append(append([]byte("ICC_PROFILE\x00"), 1, 3), profile(64)[:32]...),
				append(append([]byte("ICC_PROFILE\x00"), 2, 3), profile(64)[32:]...),
			},
		},
		{
			// ISOLATES the assembled-size check. One chunk, count 1, sequence
			// 1 -- every structural check passes -- but the profile's own size
			// field says 64 and 96 bytes arrived, so 32 bytes are riding along
			// that the profile does not describe. This is the proposition the
			// old per-chunk comparison was reaching for, applied where it is
			// actually meaningful.
			name: "assembled data does not match the declared profile size",
			chunks: [][]byte{
				append(append([]byte("ICC_PROFILE\x00"), 1, 1),
					append(profile(64), make([]byte, 32)...)...),
			},
		},
		{
			name: "sequence zero",
			chunks: [][]byte{
				append(append([]byte("ICC_PROFILE\x00"), 0, 1), profile(64)...),
			},
		},
		{
			name: "tagged but too short to carry a sequence",
			chunks: [][]byte{
				[]byte("ICC_PROFILE\x00"),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			segs := make([][]byte, 0, len(tc.chunks))
			for _, c := range tc.chunks {
				segs = append(segs, jpegSegment(0xE2, c))
			}
			raw := buildJPEGWithSegments(t, segs...)

			out, err := stripJPEGMetadata(raw)
			if err != nil {
				t.Fatalf("stripJPEGMetadata: %v", err)
			}
			if n := bytes.Count(out, []byte("ICC_PROFILE\x00")); n != 0 {
				t.Errorf("%d of %d chunks survived from an invalid set; it must be all or nothing",
					n, len(tc.chunks))
			}
		})
	}
}

// TestVerifierAgreesWithTheSanitizerAboutICCSets is the one that would have
// caught this phase's own near-miss.
//
// The verifier carried an independent copy of the same per-chunk size read. Had
// only the sanitizer been fixed, every multi-chunk profile it now correctly
// preserves would have been reported as residue by the verifier -- and a
// sanitize job that produces a correct file and then refuses to deliver it is
// a worse outcome than the bug. The two are written apart on purpose; this
// holds them to the same verdict on the same bytes.
func TestVerifierAgreesWithTheSanitizerAboutICCSets(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(sanitizeCorpusDir, "icc_multichunk.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := stripJPEGMetadata(raw)
	if err != nil {
		t.Fatal(err)
	}

	if what, found, err := jpegMetadataResidue(out); err != nil || found {
		t.Errorf("the verifier calls the sanitizer's own output residue: %s", what)
	}

	keep, err := iccChunkSetIsValid(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := verifierICCSetComplete(out); got != keep {
		t.Errorf("sanitizer says set-valid=%v, verifier says set-complete=%v -- "+
			"two independent implementations of one rule have drifted", keep, got)
	}
}

// TestSanitizeICCEndToEnd drives the real entry point, because every test above
// this one calls an unexported function and would keep passing if the wiring
// between them broke.
func TestSanitizeICCEndToEnd(t *testing.T) {
	requireVerifierBinaries(t)

	src := filepath.Join(sanitizeCorpusDir, "icc_multichunk.jpg")
	out := filepath.Join(t.TempDir(), "out.jpg")
	if _, err := sanitizeFile(context.Background(), engineExec{}, "jpg", src, out); err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(blob, []byte("ICC_PROFILE\x00")); n != 3 {
		t.Errorf("delivered file carries %d ICC chunks, want 3", n)
	}
	if bytes.Contains(blob, []byte("Exif\x00\x00")) {
		t.Error("EXIF survived the end-to-end path")
	}
}
