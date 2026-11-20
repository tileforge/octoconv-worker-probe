package convert

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

// TestSanitizeImageRemovesEXIFAndGPS is the SANI-02 proof, checked in the
// OUTPUT BYTES rather than through a metadata library: "physically absent"
// is the requirement, and a library that reports no EXIF could be reporting
// that it failed to find the block, not that the block is gone.
func TestSanitizeImageRemovesEXIFAndGPS(t *testing.T) {
	in := filepath.Join(sanitizeCorpusDir, "exif_gps.jpg")
	src, err := os.ReadFile(in)
	if err != nil {
		t.Fatalf("read fixture: %v -- committed by Plan 60-01", err)
	}
	for _, m := range []string{"Exif\x00\x00", "OctoConvCam", "FixtureModel X1"} {
		if !bytes.Contains(src, []byte(m)) {
			t.Fatalf("fixture lacks %q -- regenerate with scripts/sanitize-corpus.py", m)
		}
	}

	out := filepath.Join(t.TempDir(), "clean.jpg")
	res, err := sanitizeFile(context.Background(), engineExec{}, "jpg", in, out)
	if err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range []string{"Exif\x00\x00", "OctoConvCam", "FixtureModel X1"} {
		if bytes.Contains(got, []byte(m)) {
			t.Errorf("marker %q survived into the sanitized output", m)
		}
	}
	// The GPS IFD's own tag pointer (0x8825) is what makes the coordinates
	// reachable; checking for it separately means a future EXIF block written
	// without the camera-model strings is still caught.
	if bytes.Contains(got, []byte{0x88, 0x25}) {
		t.Error("the GPS IFD pointer tag survived into the sanitized output")
	}

	if len(res.Removed) != 1 || res.Removed[0] != ThreatDocumentMetadata {
		t.Errorf("Removed = %v, want exactly [document_metadata] -- an image container holds no actions, macros or attachments, and claiming otherwise would be false", res.Removed)
	}
}

// TestSanitizeImageStaysDecodable checks the file is still an image: same
// dimensions, decodes without error.
func TestSanitizeImageStaysDecodable(t *testing.T) {
	in := filepath.Join(sanitizeCorpusDir, "exif_gps.jpg")
	out := filepath.Join(t.TempDir(), "clean.jpg")
	if _, err := sanitizeFile(context.Background(), engineExec{}, "jpg", in, out); err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}

	before, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()
	cfgBefore, _, err := image.DecodeConfig(before)
	if err != nil {
		t.Fatalf("decode input: %v", err)
	}

	after, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	cfgAfter, _, err := image.DecodeConfig(after)
	if err != nil {
		t.Fatalf("sanitized image no longer decodes: %v", err)
	}

	if cfgBefore.Width != cfgAfter.Width || cfgBefore.Height != cfgAfter.Height {
		t.Errorf("dimensions changed: %dx%d -> %dx%d",
			cfgBefore.Width, cfgBefore.Height, cfgAfter.Width, cfgAfter.Height)
	}
}

// TestSanitizeImageIsLossless backs the empty LostCapabilities list with
// evidence.
//
// The structural strip copies the entropy-coded scan data verbatim, so the
// compressed image bytes must be IDENTICAL before and after -- not merely
// visually similar, which is the most a re-encoding route could claim. If
// this ever fails, the empty LostCapabilities list has become a false
// statement and the report owes the client a quality-loss entry.
func TestSanitizeImageIsLossless(t *testing.T) {
	in := filepath.Join(sanitizeCorpusDir, "exif_gps.jpg")
	out := filepath.Join(t.TempDir(), "clean.jpg")
	res, err := sanitizeFile(context.Background(), engineExec{}, "jpg", in, out)
	if err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}
	if len(res.LostCapabilities) != 0 {
		t.Fatalf("LostCapabilities = %v, want empty -- this test exists to back that claim", res.LostCapabilities)
	}

	src, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	// The scan data is everything from the SOS marker onward.
	scanOf := func(b []byte) []byte {
		if i := bytes.Index(b, []byte{0xFF, 0xDA}); i >= 0 {
			return b[i:]
		}
		return nil
	}
	sBefore, sAfter := scanOf(src), scanOf(got)
	if sBefore == nil || sAfter == nil {
		t.Fatal("no SOS marker found in one of the files")
	}
	if !bytes.Equal(sBefore, sAfter) {
		t.Errorf("compressed scan data changed (%d -> %d bytes) -- the strip is not lossless, and LostCapabilities must say so",
			len(sBefore), len(sAfter))
	}
}

// TestSanitizeImagePNGChunks covers the second container. A PNG carrying tEXt
// and eXIf must come out with the metadata chunks gone and IDAT untouched.
func TestSanitizeImagePNGChunks(t *testing.T) {
	src := buildPNGWithMetadata(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "meta.png")
	if err := os.WriteFile(in, src, 0o644); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte("tEXt")) || !bytes.Contains(src, []byte("eXIf")) {
		t.Fatal("test input lacks the metadata chunks it exists to carry")
	}

	out := filepath.Join(dir, "clean.png")
	if _, err := sanitizeFile(context.Background(), engineExec{}, "png", in, out); err != nil {
		t.Fatalf("sanitizeFile: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range []string{"tEXt", "eXIf", "SecretAuthor"} {
		if bytes.Contains(got, []byte(m)) {
			t.Errorf("%q survived into the sanitized PNG", m)
		}
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, err := image.DecodeConfig(f); err != nil {
		t.Errorf("sanitized PNG no longer decodes: %v", err)
	}
}

// buildPNGWithMetadata produces a minimal valid PNG carrying a tEXt and an
// eXIf chunk, by inserting them into a stdlib-encoded image.
func buildPNGWithMetadata(t *testing.T) []byte {
	t.Helper()

	var base bytes.Buffer
	img := image.NewGray(image.Rect(0, 0, 2, 2))
	if err := png.Encode(&base, img); err != nil {
		t.Fatal(err)
	}
	raw := base.Bytes()

	chunk := func(ctype string, data []byte) []byte {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
		b.WriteString(ctype)
		b.Write(data)
		crc := crc32.NewIEEE()
		crc.Write([]byte(ctype))
		crc.Write(data)
		_ = binary.Write(&b, binary.BigEndian, crc.Sum32())
		return b.Bytes()
	}

	// Insert after IHDR (signature 8 + length 4 + type 4 + data 13 + crc 4).
	at := 8 + 4 + 4 + 13 + 4
	var out bytes.Buffer
	out.Write(raw[:at])
	out.Write(chunk("tEXt", []byte("Author\x00SecretAuthor")))
	out.Write(chunk("eXIf", []byte("MM\x00\x2a\x00\x00\x00\x08\x00\x00")))
	out.Write(raw[at:])
	return out.Bytes()
}

// buildJPEGWithSegments assembles a minimal JPEG carrying the given
// pre-formed APPn segments before its tables.
func buildJPEGWithSegments(t *testing.T, segments ...[]byte) []byte {
	t.Helper()
	qt := bytes.Repeat([]byte{16}, 64)
	dqt := append([]byte{0xFF, 0xDB, 0x00, 0x43, 0x00}, qt...)
	sof0 := []byte{0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00}
	dht := func(cls byte) []byte {
		payload := append([]byte{cls, 1}, bytes.Repeat([]byte{0}, 15)...)
		payload = append(payload, 0x00)
		out := []byte{0xFF, 0xC4, 0x00, byte(len(payload) + 2)}
		return append(out, payload...)
	}
	sos := []byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00}

	var b bytes.Buffer
	b.Write([]byte{0xFF, 0xD8})
	for _, seg := range segments {
		b.Write(seg)
	}
	b.Write(dqt)
	b.Write(sof0)
	b.Write(dht(0x00))
	b.Write(dht(0x10))
	b.Write(sos)
	b.WriteByte(0x00)
	b.Write([]byte{0xFF, 0xD9})
	return b.Bytes()
}

// iccChunk builds one APP2 ICC payload: the tag, a sequence number, a total
// count, and profile data whose first four bytes are the profile's own size
// (ICC.1:2010 §7.2.2). Written as a helper because getting that size field
// right is the difference between a fixture that tests the ICC path and one
// that tests the malformed-input path -- the earlier version of this file used
// tag+"profile", whose bytes 12 and 13 are 'p' and 'r', so it declared itself
// chunk 112 of 114 and only survived because the check it faced was broken.
func iccChunk(seq, count byte, data []byte) []byte {
	body := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(body[:4], uint32(4+len(data)))
	copy(body[4:], data)
	return append(append([]byte("ICC_PROFILE\x00"), seq, count), body...)
}

func jpegSegment(marker byte, payload []byte) []byte {
	out := []byte{0xFF, marker, byte((len(payload) + 2) >> 8), byte((len(payload) + 2) & 0xFF)}
	return append(out, payload...)
}

// TestSanitizeImageKeepsColourManagement is the regression proof for the
// fourth finding of PR #12.
//
// Dropping APP2/ICC and APP14/Adobe alongside the metadata made this path's
// losslessness claim false in the only sense a client cares about: the scan
// bytes survived and the rendered picture changed — a wide-gamut image
// displayed as sRGB, and a CMYK image with inverted channels.
//
// Both are matched by PAYLOAD, so the FPXR segment below — also APP2 — must
// still be dropped. A marker-number allowlist would have readmitted exactly
// the vendor extensions the original drop-everything rule was guarding
// against.
func TestSanitizeImageKeepsColourManagement(t *testing.T) {
	// A real ICC chunk shape: tag, sequence number, chunk count, then a
	// profile whose first four bytes are its own declared size. The first
	// version of this fixture appended arbitrary text, so the size check read
	// garbage as the declared length and passed by accident -- a fixture that
	// satisfies a rule for the wrong reason tests nothing about it.
	iccProfile := make([]byte, 64)
	binary.BigEndian.PutUint32(iccProfile[0:4], uint32(len(iccProfile)))
	icc := jpegSegment(0xE2, append(append([]byte("ICC_PROFILE\x00"), 0x01, 0x01), iccProfile...))
	adobe := jpegSegment(0xEE, append([]byte("Adobe"), []byte{0x00, 0x64, 0, 0, 0, 0, 2}...))
	fpxr := jpegSegment(0xE2, append([]byte("FPXR\x00"), []byte("flashpix-vendor-blob")...))
	exif := jpegSegment(0xE1, append([]byte("Exif\x00\x00"), []byte("MM\x00\x2aSECRET")...))
	comment := jpegSegment(0xFE, []byte("a comment"))

	dir := t.TempDir()
	in := filepath.Join(dir, "in.jpg")
	if err := os.WriteFile(in, buildJPEGWithSegments(t, icc, adobe, fpxr, exif, comment), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.jpg")
	if _, err := sanitizeImage(context.Background(), engineExec{}, in, out); err != nil {
		t.Fatalf("sanitizeImage: %v", err)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	for _, kept := range []struct{ name, marker string }{
		{"ICC profile (APP2)", "ICC_PROFILE\x00"},
		{"Adobe colour transform (APP14)", "Adobe"},
	} {
		if !bytes.Contains(blob, []byte(kept.marker)) {
			t.Errorf("%s was dropped; the scan bytes survive but the picture does not", kept.name)
		}
	}
	for _, gone := range []struct{ name, marker string }{
		{"EXIF (APP1)", "Exif\x00\x00"},
		{"FlashPix (APP2, matched by payload not by marker)", "FPXR\x00"},
		{"COM comment", "a comment"},
	} {
		if bytes.Contains(blob, []byte(gone.marker)) {
			t.Errorf("%s survived", gone.name)
		}
	}
}

// TestVerifierDoesNotMistakePayloadForStructure is the regression proof for
// the fifth finding of PR #12.
//
// The PNG below is clean: it has no tEXt chunk. Its IDAT stream carries the
// literal bytes "tEXt" as image data, which a large enough real image
// eventually does by chance. The old whole-file byte scan reported residue —
// and because verification failure DELETES the output, that did not merely
// mislabel the job, it destroyed a correct result.
func TestVerifierDoesNotMistakePayloadForStructure(t *testing.T) {
	requireVerifierBinaries(t)

	payload := append([]byte("tEXtiTXtzTXteXIftIME"), bytes.Repeat([]byte{0}, 40)...)
	png := buildPNGWithRawIDAT(t, payload)

	dir := t.TempDir()
	out := filepath.Join(dir, "clean.png")
	if err := os.WriteFile(out, png, 0o600); err != nil {
		t.Fatal(err)
	}

	// Sanity: the forbidden strings really are in the bytes, or this test
	// proves nothing.
	if !bytes.Contains(png, []byte("tEXt")) {
		t.Fatal("fixture does not contain the literal bytes the old scan tripped on")
	}

	if _, err := verifySanitized(context.Background(), engineExec{}, "png", out); err != nil {
		t.Fatalf("a clean PNG was rejected because its IMAGE DATA contained a chunk-type "+
			"sequence: %v", err)
	}
}

// buildPNGWithRawIDAT produces a valid PNG whose IDAT stream carries payload
// verbatim, by using a zlib stream of STORED (uncompressed) blocks. This is
// what makes "these four bytes appear in the file" true without any chunk of
// that type existing -- the exact situation a whole-file byte scan cannot
// distinguish from real residue.
func buildPNGWithRawIDAT(t *testing.T, payload []byte) []byte {
	t.Helper()

	chunk := func(ctype string, data []byte) []byte {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
		b.WriteString(ctype)
		b.Write(data)
		crc := crc32.NewIEEE()
		crc.Write([]byte(ctype))
		crc.Write(data)
		_ = binary.Write(&b, binary.BigEndian, crc.Sum32())
		return b.Bytes()
	}

	// One row per scanline: filter byte 0 followed by width grayscale bytes.
	width := len(payload)
	height := 1
	scan := append([]byte{0}, payload...)

	var z bytes.Buffer
	zw, err := zlib.NewWriterLevel(&z, zlib.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(scan); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], uint32(width))
	binary.BigEndian.PutUint32(ihdr[4:8], uint32(height))
	ihdr[8] = 8 // bit depth
	ihdr[9] = 0 // colour type: grayscale

	var out bytes.Buffer
	out.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'})
	out.Write(chunk("IHDR", ihdr))
	out.Write(chunk("IDAT", z.Bytes()))
	out.Write(chunk("IEND", nil))
	return out.Bytes()
}

// buildJPEGWithPostScanSegments assembles a JPEG whose APPn/COM segments sit
// AFTER the entropy-coded scan, which is legal and is what progressive JPEGs
// and several camera producers do.
func buildJPEGWithPostScanSegments(t *testing.T, scan []byte, after ...[]byte) []byte {
	t.Helper()
	qt := bytes.Repeat([]byte{16}, 64)
	dqt := append([]byte{0xFF, 0xDB, 0x00, 0x43, 0x00}, qt...)
	sof0 := []byte{0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00}
	dht := func(cls byte) []byte {
		payload := append([]byte{cls, 1}, bytes.Repeat([]byte{0}, 15)...)
		payload = append(payload, 0x00)
		return append([]byte{0xFF, 0xC4, 0x00, byte(len(payload) + 2)}, payload...)
	}
	sos := []byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00}

	var b bytes.Buffer
	b.Write([]byte{0xFF, 0xD8})
	b.Write(dqt)
	b.Write(sof0)
	b.Write(dht(0x00))
	b.Write(dht(0x10))
	b.Write(sos)
	b.Write(scan)
	for _, seg := range after {
		b.Write(seg)
	}
	b.Write([]byte{0xFF, 0xD9})
	return b.Bytes()
}

// TestSanitizeImageStripsSegmentsAfterTheScan is the regression proof for the
// twelfth finding of PR #12, and the worst one in the set: it produced a FALSE
// "verified".
//
// Both the sanitizer and the verifier treated the first SOS as the end of the
// file. A JPEG may carry several scans, and may legally carry APP or COM
// segments after one -- so EXIF placed there survived sanitization AND was
// reported as document_metadata verified. Two independent implementations
// sharing one wrong assumption prove nothing, which is why the verifier's own
// walker was fixed separately rather than by calling the sanitizer's.
//
// The scan below contains FF 00 (byte stuffing) and FF D0 (a restart marker),
// because a walker that stops at the first 0xFF would "work" on a scan without
// them and truncate every real photograph.
func TestSanitizeImageStripsSegmentsAfterTheScan(t *testing.T) {
	scan := []byte{0x00, 0xFF, 0x00, 0x12, 0xFF, 0xD0, 0x34, 0xFF, 0x00}
	exif := jpegSegment(0xE1, append([]byte("Exif\x00\x00"), []byte("MM\x00\x2aPOSTSCAN-SECRET")...))
	comment := jpegSegment(0xFE, []byte("post-scan comment"))
	// A REAL single-chunk ICC segment: tag, sequence 1, count 1, then profile
	// bytes. It used to be tag+"profile", which is not an ICC chunk at all --
	// bytes 12 and 13 there are 'p' and 'r', so it declared itself chunk 112
	// of 114. The old per-chunk check kept it anyway (it only compared lengths
	// against four bytes it read as a size), so this test passed while
	// asserting that a malformed chunk survives. Corrected with the SANI-07
	// fix: what the test means -- colour management is kept wherever it sits --
	// is unchanged, and now it is asserted about something that is actually a
	// colour profile.
	icc := jpegSegment(0xE2, iccChunk(1, 1, []byte("profile")))

	dir := t.TempDir()
	in := filepath.Join(dir, "in.jpg")
	raw := buildJPEGWithPostScanSegments(t, scan, exif, comment, icc)
	if err := os.WriteFile(in, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Half one: the verifier must REFUSE this file. If it does not, its
	// "clean" on the sanitized output says nothing.
	if _, err := verifySanitized(context.Background(), engineExec{}, "jpg", in); err == nil {
		t.Error("the verifier called a file with post-scan EXIF clean -- it is blind in the " +
			"same place the sanitizer was, so its verdict on the output is worthless")
	}

	// Half two: the sanitizer must remove them, and keep the scan intact.
	out := filepath.Join(dir, "out.jpg")
	if _, err := sanitizeImage(context.Background(), engineExec{}, in, out); err != nil {
		t.Fatalf("sanitizeImage: %v", err)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"POSTSCAN-SECRET", "post-scan comment"} {
		if bytes.Contains(blob, []byte(gone)) {
			t.Errorf("%q survived after the scan", gone)
		}
	}
	if !bytes.Contains(blob, []byte("ICC_PROFILE\x00")) {
		t.Error("the post-scan ICC profile was dropped; colour management is kept wherever it sits")
	}
	if !bytes.Contains(blob, scan) {
		t.Error("the entropy-coded scan was altered -- stuffing or a restart marker was " +
			"mistaken for a segment boundary")
	}
	if _, err := verifySanitized(context.Background(), engineExec{}, "jpg", out); err != nil {
		t.Errorf("the sanitized output does not verify: %v", err)
	}
}

// TestVerifierRequiresAFullDecode is the regression proof for the thirteenth
// finding of PR #12.
//
// image.DecodeConfig reads only enough structure to report dimensions. A file
// with an intact header and a truncated compressed stream passed it, the
// sanitizer copied the damaged payload through unchanged, libmagic still
// recognised the header, and the job finished successfully with an output no
// decoder can open -- while the report claimed document_metadata verified.
//
// The fixture is the corpus JPEG with ONE scan byte removed: header valid,
// dimensions readable, entropy-coded data unusable.
func TestVerifierRequiresAFullDecode(t *testing.T) {
	requireVerifierBinaries(t)

	raw, err := os.ReadFile(filepath.Join(sanitizeCorpusDir, "exif_gps.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(raw, []byte{0xFF, 0xDA})
	if i < 0 {
		t.Fatal("fixture has no SOS")
	}
	end := i + 2 + int(raw[i+2])<<8 + int(raw[i+3])
	broken := append(append([]byte(nil), raw[:end]...), raw[end+1:]...)

	// The fixture must be exactly the awkward case: header fine, pixels not.
	if _, _, err := image.DecodeConfig(bytes.NewReader(broken)); err != nil {
		t.Fatalf("fixture fails DecodeConfig too, so it does not test the gap: %v", err)
	}
	if _, _, err := image.Decode(bytes.NewReader(broken)); err == nil {
		t.Fatal("fixture decodes fully, so it does not test the gap")
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "broken.jpg")
	if err := os.WriteFile(out, broken, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = verifySanitized(context.Background(), engineExec{}, "jpg", out)
	if err == nil {
		t.Fatal("the verifier accepted an image that cannot be decoded; the job would " +
			"finish successfully with an unusable output and a report claiming it verified")
	}
	if !errors.Is(err, ErrSanitizeUnverifiable) {
		t.Errorf("want ErrSanitizeUnverifiable for a file that does not decode, got %v", err)
	}

	// And the whole pipeline must refuse it, not merely the verifier in
	// isolation -- sanitizeFile deletes an unverified output.
	in := filepath.Join(dir, "in.jpg")
	if err := os.WriteFile(in, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	produced := filepath.Join(dir, "out.jpg")
	if _, err := sanitizeFile(context.Background(), engineExec{}, "jpg", in, produced); err == nil {
		t.Error("sanitizeFile succeeded on an image that cannot be decoded")
	}
	if _, err := os.Stat(produced); !os.IsNotExist(err) {
		t.Errorf("the unverified output still exists (stat err = %v)", err)
	}
}

// TestSanitizeImageAcceptsMarkerFillBytes is the regression proof for the
// eighteenth finding of PR #12.
//
// A marker may be preceded by any number of FF fill bytes (ISO/IEC 10918-1
// B.1.1.2) and real encoders emit them. endOfEntropyCodedData already skipped
// runs of FF inside the scan; the segment walker above it did not, in the same
// file. So a legal file passed the API's dimension decode and then failed
// asynchronously as malformed input -- an upload the service accepted and then
// refused, for a reason that was not the client's.
//
// Both walkers are covered here: the verifier's had the identical gap, and a
// verifier that stops early reports CLEAN on segments it never reached.
func TestSanitizeImageAcceptsMarkerFillBytes(t *testing.T) {
	requireVerifierBinaries(t)

	base := buildJPEGWithSegments(t,
		jpegSegment(0xE1, append([]byte("Exif\x00\x00"), []byte("MM\x00\x2aFILLBYTES")...)))

	// Insert a run of fill bytes before the first marker after SOI.
	withFill := append([]byte{}, base[:2]...)
	withFill = append(withFill, 0xFF, 0xFF, 0xFF)
	withFill = append(withFill, base[2:]...)

	if _, _, err := image.DecodeConfig(bytes.NewReader(withFill)); err != nil {
		t.Fatalf("the fixture is not a legal JPEG, so it tests nothing: %v", err)
	}

	dir := t.TempDir()
	in := filepath.Join(dir, "in.jpg")
	if err := os.WriteFile(in, withFill, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.jpg")
	if _, err := sanitizeImage(context.Background(), engineExec{}, in, out); err != nil {
		t.Fatalf("a legal JPEG with marker fill bytes was refused: %v", err)
	}

	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("FILLBYTES")) {
		t.Error("the EXIF after the fill bytes survived -- the walker stopped before reaching it")
	}

	// And the verifier must have walked past the fill bytes too, or its
	// verdict covers only what it happened to reach.
	if found, isResidue, err := jpegMetadataResidue(withFill); err != nil || !isResidue {
		t.Errorf("the verifier called the UNSANITIZED file clean (found=%q, err=%v); it stops at the "+
			"fill bytes and never sees the APP1 behind them", found, err)
	}
}

func TestStripJPEGMetadataRejectsTrailingFill(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if len(raw) < 2 || raw[len(raw)-2] != 0xFF || raw[len(raw)-1] != 0xD9 {
		t.Fatalf("encoded JPEG has no EOI: %x", raw[len(raw)-2:])
	}
	raw[len(raw)-1] = 0xFF
	if _, _, err := image.DecodeConfig(bytes.NewReader(raw)); err != nil {
		t.Fatalf("DecodeConfig rejected the fixture, so it does not match the reported input: %v", err)
	}

	_, err := stripJPEGMetadata(raw)
	if !errors.Is(err, ErrSanitizeMalformedInput) {
		t.Fatalf("stripJPEGMetadata: %v", err)
	}
	if _, err := endOfEntropyCodedData(raw, len(raw)-2); !errors.Is(err, ErrSanitizeMalformedInput) {
		t.Fatalf("endOfEntropyCodedData: %v", err)
	}
	if _, err := skipEntropyCodedScan(raw, len(raw)-2); !errors.Is(err, ErrSanitizeMalformedInput) {
		t.Fatalf("skipEntropyCodedScan: %v", err)
	}

	in := filepath.Join(t.TempDir(), "in.jpg")
	if err := os.WriteFile(in, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = sanitizeImage(context.Background(), engineExec{}, in, filepath.Join(t.TempDir(), "out.jpg"))
	if !errors.Is(err, ErrSanitizeMalformedInput) {
		t.Fatalf("sanitizeImage: %v", err)
	}
}
