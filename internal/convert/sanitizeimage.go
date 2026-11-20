package convert

// This file (sanitizeimage.go): metadata removal from images (SANI-02).
//
// TOOL CHOICE, AND WHY IT IS NEITHER OF THE TWO THE PLAN OFFERED
//
// Plan 60-03 named two routes: shell out to exiftool (a new binary in the
// image), or re-encode through the stdlib discarding metadata. A third is
// available and strictly better than both, so it is what this does:
//
//	STRUCTURAL STRIP -- walk the container's segment/chunk structure and copy
//	forward everything except the segments that carry metadata, leaving the
//	compressed image data byte-identical.
//
// Against exiftool: no new binary, no new supply-chain surface, and the
// guarantee is by construction rather than by trusting a tool's option
// surface to mean what its documentation says.
//
// Against re-encoding: re-encoding a JPEG decodes and recompresses it, which
// LOSES QUALITY every time, silently and irreversibly. Plan 60-03 was explicit
// that quietly degrading the image is not acceptable and that unavoidable loss
// would have to be reported. Structural stripping makes the question moot --
// the entropy-coded scan data is copied verbatim, so the pixels that come out
// are bit-for-bit the pixels that went in. There is no loss to report because
// there is no loss.
//
// The cost of this route is that it is format-specific: each container needs
// its own walker. That is a real limit and it is why the supported set below
// is closed and small, rather than a claim about images in general.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
)

// imageThreatClasses is what the image path removes. Metadata only: an image
// container carries no actions, no macros and no attachments, and claiming
// otherwise would be the same false statement pdfThreatClasses exists to
// avoid.
var imageThreatClasses = []ThreatClass{ThreatDocumentMetadata}

// COLOR MANAGEMENT IS KEPT; METADATA IS NOT. THE RULE IS ABOUT WHAT A
// SEGMENT DOES, NOT ABOUT WHICH MARKER CARRIES IT.
//
// The first version of this dropped every APP0-APP15 segment, on the argument
// that an allowlist of "segments we know are safe" would let the next vendor
// extension through. That argument is right about METADATA carriers and wrong
// about two segments that are not metadata at all:
//
//	APP2 with an "ICC_PROFILE\0" payload -- the colour profile. Without it a
//	    wide-gamut image is rendered as if it were sRGB. The pixels are
//	    unchanged; what they MEAN is not.
//	APP14 with an "Adobe" payload -- the colour-transform flag. Without it a
//	    CMYK or YCCK JPEG decodes with inverted or wrong channels, and some
//	    decoders refuse it outright.
//
// Dropping those made this file's own losslessness claim false in the only
// sense a client cares about: the bytes of the scan survived and the picture
// changed. Caught in review (PR #12).
//
// Both are kept by CONTENT, never by marker number: APP2 is also used by
// FlashPix (FPXR), and APP14 by other producers, so a marker-only allowlist
// would readmit exactly the vendor extensions the original argument was
// guarding against. Everything else in APP0-APP15, and every COM segment,
// still goes -- APP1 is EXIF/GPS/XMP, APP13 is IPTC, APP0 is JFIF.
//
// WHAT THIS LEAVES ON THE TABLE, STATED RATHER THAN ELIDED: an ICC profile is
// a structured container with vendor-defined tags, so a preserved profile can
// carry bytes this service did not enumerate. That is a boundary of the
// guarantee, and docs/SANITIZE.md's scope section says so; it is not a claim
// this code quietly makes.
//
// The scan data after SOS is copied verbatim to the end. That is what makes
// this lossless: the compressed image is never decoded.
func stripJPEGMetadata(src []byte) ([]byte, error) {
	if len(src) < 2 || src[0] != 0xFF || src[1] != 0xD8 {
		return nil, fmt.Errorf("%w: not a JPEG (no SOI)", ErrSanitizeMalformedInput)
	}

	// TWO PASSES OVER ONE WALKER, not two walkers.
	//
	// The APP2/ICC decision cannot be made segment by segment (see
	// iccChunkSetIsValid), so the file has to be read once before anything is
	// written. Doing that with a second, simpler scanner is the shape this
	// package has already been burned by three times -- a rule implemented in
	// two places drifts, and here the two places would be "which segments are
	// ICC chunks" for the decision and for the emission. So the walk itself is
	// factored out and run twice.
	keepICC, err := iccChunkSetIsValid(src)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.Write(src[:2]) // SOI

	err = walkJPEGSegments(src, func(seg jpegMarkerSegment) {
		isAPP := seg.marker >= 0xE0 && seg.marker <= 0xEF
		isCOM := seg.marker == 0xFE
		switch {
		case !isAPP && !isCOM:
			out.Write(seg.raw)
		case isJPEGICCChunk(seg.marker, seg.payload):
			// Kept or dropped as a SET. A partially-preserved profile is
			// worse than none: the file still decodes, the report still says
			// the colour profile was preserved, and the colours are wrong.
			if keepICC {
				out.Write(seg.raw)
			}
		case isKeptJPEGAppSegment(seg.marker, seg.payload):
			out.Write(seg.raw)
		}
		out.Write(seg.scan)
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// jpegMarkerSegment is one marker segment as the walker sees it.
//
// raw is the whole segment including its marker and length, so a caller that
// keeps a segment writes exactly the bytes that were there. scan is the
// entropy-coded data that follows an SOS and is empty for every other marker;
// it is carried on the segment rather than visited separately so a caller
// cannot keep a scan while dropping its SOS, or the reverse.
type jpegMarkerSegment struct {
	marker  byte
	payload []byte
	raw     []byte
	scan    []byte
}

// walkJPEGSegments visits every segment from SOI to EOI, resolving segment
// lengths, marker fill bytes and entropy-coded scan data.
//
// This is the ONE place any of that is decided. It was inlined in
// stripJPEGMetadata until Plan 63-01 needed to read the file before writing
// it; extracting it was the alternative to writing a second scanner that would
// have had to agree with this one about every rule below.
func walkJPEGSegments(src []byte, visit func(jpegMarkerSegment)) error {
	i := 2
	for i+1 < len(src) {
		if src[i] != 0xFF {
			return fmt.Errorf("%w: malformed JPEG: expected a marker at offset %d", ErrSanitizeMalformedInput, i)
		}
		// A marker may be preceded by any number of FF fill bytes (ISO/IEC
		// 10918-1 B.1.1.2), and real encoders emit them. Skipping the run is
		// the SAME rule endOfEntropyCodedData below already applied to the
		// scan -- and it was applied there and not here, so a legal
		// FF D8 FF FF DB ... file passed the API's dimension decode and then
		// failed asynchronously as malformed input. A rule implemented in one
		// of two places that need it is the shape review has now named three
		// times. Caught in review (PR #12, round 6).
		for i+2 < len(src) && src[i+1] == 0xFF {
			i++
		}
		marker := src[i+1]

		// Standalone markers carry no length field.
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			visit(jpegMarkerSegment{marker: marker, raw: src[i : i+2]})
			i += 2
			continue
		}
		if marker == 0xD9 { // EOI
			visit(jpegMarkerSegment{marker: marker, raw: src[i : i+2]})
			return nil
		}
		if i+4 > len(src) {
			return fmt.Errorf("%w: truncated JPEG segment header at offset %d", ErrSanitizeMalformedInput, i)
		}
		segLen := int(binary.BigEndian.Uint16(src[i+2 : i+4]))
		if segLen < 2 || i+2+segLen > len(src) {
			return fmt.Errorf("%w: invalid JPEG segment length %d at offset %d", ErrSanitizeMalformedInput, segLen, i)
		}
		segEnd := i + 2 + segLen

		seg := jpegMarkerSegment{marker: marker, payload: src[i+4 : segEnd], raw: src[i:segEnd]}

		if marker == 0xDA {
			// SOS: entropy-coded data follows. It is copied VERBATIM -- that
			// is what makes this lossless -- but it does NOT run to the end of
			// the file, and treating it that way was a defect.
			//
			// A JPEG may carry several scans (progressive encoding is the
			// common case) and may legally carry APP or COM segments AFTER a
			// scan. Returning here copied all of that through untouched, so
			// EXIF placed after the first scan survived sanitization while the
			// verifier -- which had the same early return -- reported
			// document_metadata as VERIFIED. A false statement in the report,
			// which is the one outcome this phase exists to prevent. Caught in
			// review (PR #12, round 3), and reproduced before it was fixed.
			// The SOS header is not an APP or COM segment, so every caller
			// keeps it, and its scan travels with it.
			end, err := endOfEntropyCodedData(src, segEnd)
			if err != nil {
				return err
			}
			seg.scan = src[segEnd:end]
			visit(seg)
			i = end
			continue
		}
		visit(seg)
		i = segEnd
	}
	return nil
}

// The two APP segments this sanitizer preserves, recognised by their payload
// and -- for APP14 -- by its exact SHAPE.
//
// A PREFIX IS NOT A STRUCTURE. Matching APP14 on the five bytes "Adobe" alone
// preserved any segment that happened to start that way, so a payload of
// "Adobe" followed by appended EXIF or XMP survived intact while the report
// claimed document_metadata verified. The segment still decoded, the job
// reached done, and the metadata was still in the file. Caught in review
// (PR #12, round 7).
//
// The Adobe marker has a fixed shape and therefore a checkable one: the
// five-byte tag, a two-byte version, two two-byte flag words and a one-byte
// transform -- twelve bytes, no more. Anything longer carries something the
// marker does not define.
//
// APP2/ICC cannot be pinned the same way: a colour profile is legitimately
// variable-length, and that is exactly why docs/SANITIZE.md's scope section
// says a preserved profile can carry vendor-defined bytes. What CAN be
// required is that the chunk does not exceed the profile's own declared size.
const (
	jpegAdobeTag        = "Adobe"
	jpegAdobePayloadLen = 12
	jpegICCTag          = "ICC_PROFILE\x00"
	jpegICCHeaderLen    = 14 // tag + sequence number + total count

	// iccMaxChunks is 255 because the chunk count is ONE BYTE. This is not a
	// policy number -- a larger count is unrepresentable in the format.
	iccMaxChunks = 255

	// iccMaxProfileBytes bounds the ASSEMBLED profile. ICC.1:2010 §7.1.2 caps
	// a profile's own size field at 2^32-1, which is not a useful bound for a
	// sanitizer, so this is the project's own ceiling: 16 MiB is far above any
	// real profile (a large CMYK output profile is single-digit MiB) and far
	// below anything that could be used to make this function allocate.
	iccMaxProfileBytes = 16 << 20
)

// isKeptJPEGAppSegment reports whether an APPn segment is one of the two
// colour-management segments this sanitizer preserves.
func isKeptJPEGAppSegment(marker byte, payload []byte) bool {
	switch marker {
	case 0xEE: // APP14, Adobe colour transform
		return len(payload) == jpegAdobePayloadLen &&
			bytes.HasPrefix(payload, []byte(jpegAdobeTag))
	default:
		// APP2/ICC is deliberately NOT handled here. It cannot be: the
		// decision is about the chunk SET, not the chunk. See
		// iccChunkSetIsValid, and isJPEGICCChunk for the recognizer this
		// function's caller uses to route APP2 segments there instead.
		return false
	}
}

// isJPEGICCChunk reports whether a segment is an APP2 ICC profile chunk, by
// its tag alone. Whether it is KEPT is a question about the whole set.
func isJPEGICCChunk(marker byte, payload []byte) bool {
	return marker == 0xE2 && bytes.HasPrefix(payload, []byte(jpegICCTag))
}

// iccChunkSetIsValid reports whether the file's ICC chunks form one complete,
// consistent profile.
//
// WHY THIS IS NOT A PER-CHUNK CHECK, WHICH IS THE WHOLE FINDING.
//
// The previous version read payload[14:18] as the profile's declared size and
// kept a chunk when its own length fit inside that number. Those four bytes ARE
// the size field -- in CHUNK 1, where what follows the 14-byte header is the
// start of the ICC profile header (ICC.1:2010 §7.2.2). In every continuation
// chunk they are ordinary profile data, so the comparison was against a number
// that means nothing, and a chunk whose data happened to begin with a small
// big-endian integer was dropped out of the middle of a valid profile.
//
// That failure is quiet in the worst way: the file still decodes, the report
// still says the colour profile was preserved, and the image renders with the
// wrong colours. Observed on icc_multichunk.jpg before this fix -- three chunks
// in, two out.
//
// So the unit of the decision is the SET. It is valid when the chunks agree
// with each other and with the profile they claim to carry:
//
//   - at least one chunk, and every chunk carries the tag;
//   - every chunk declares the same total count, which is >= 1;
//   - every sequence number is in 1..count, and none repeats;
//   - every sequence in 1..count is present, so there are no gaps;
//   - the assembled profile fits iccMaxProfileBytes;
//   - the assembled profile's own size field agrees with what was assembled.
//
// Anything else drops the whole set. Half a profile is not a smaller profile.
func iccChunkSetIsValid(src []byte) (bool, error) {
	type chunk struct {
		seq, count int
		dataLen    int
	}
	var chunks []chunk
	total := 0
	var firstChunkHead []byte

	err := walkJPEGSegments(src, func(seg jpegMarkerSegment) {
		if !isJPEGICCChunk(seg.marker, seg.payload) {
			return
		}
		if len(seg.payload) < jpegICCHeaderLen {
			// Tagged but too short to carry its own sequence/count. Recorded
			// as a chunk with an impossible sequence so the set fails rather
			// than being silently skipped -- skipping it here would let a
			// malformed chunk sit inside an otherwise "complete" set.
			chunks = append(chunks, chunk{seq: 0})
			return
		}
		c := chunk{
			seq:     int(seg.payload[jpegICCHeaderLen-2]),
			count:   int(seg.payload[jpegICCHeaderLen-1]),
			dataLen: len(seg.payload) - jpegICCHeaderLen,
		}
		if c.seq == 1 {
			firstChunkHead = seg.payload[jpegICCHeaderLen:]
		}
		chunks = append(chunks, c)
		total += c.dataLen
	})
	if err != nil {
		return false, err
	}
	if len(chunks) == 0 {
		return false, nil
	}
	if total > iccMaxProfileBytes {
		return false, nil
	}

	want := chunks[0].count
	if want < 1 || want > iccMaxChunks || len(chunks) != want {
		return false, nil
	}
	seen := make([]bool, want+1)
	for _, c := range chunks {
		if c.count != want || c.seq < 1 || c.seq > want || seen[c.seq] {
			return false, nil
		}
		seen[c.seq] = true
	}

	// The size check the old per-chunk version was REACHING for, applied where
	// it is actually meaningful. The first four bytes of chunk 1's data are the
	// profile's own size field (ICC.1:2010 §7.2.2), and that field is the exact
	// size of the profile -- so the assembled data must equal it.
	//
	// Equality, not "<=": the old comparison allowed an assembled profile
	// SHORTER than declared, which is a truncated profile, and it is the
	// direction that matters least. What it did catch, and this keeps, is a
	// chunk carrying far more than the profile describes -- 200 bytes behind a
	// declared size of 8 is 192 bytes the profile says nothing about.
	//
	// Stated as a risk rather than hidden: an encoder that pads the final chunk
	// beyond the profile would fail this and lose its colour profile. No such
	// file is in the corpus and none is known; if one appears, the fix is a
	// measured allowance, not a loosening to "<=".
	if len(firstChunkHead) < 4 {
		return false, nil
	}
	if int(binary.BigEndian.Uint32(firstChunkHead[:4])) != total {
		return false, nil
	}
	return true, nil
}

// endOfEntropyCodedData returns the offset of the next real marker at or after
// from, skipping a JPEG scan's compressed bytes.
//
// Two things inside a scan look like markers and are not (ISO/IEC 10918-1):
//
//	FF 00      -- byte stuffing. A literal 0xFF in the compressed data is
//	              written as FF 00 so it cannot be mistaken for a marker.
//	FF D0..D7  -- restart markers, which punctuate the scan itself.
//
// Anything else after an 0xFF ends the scan. A run of padding 0xFF bytes
// before a marker is legal and is handled by looking past it.
func endOfEntropyCodedData(b []byte, from int) (int, error) {
	for i := from; i+1 < len(b); i++ {
		if b[i] != 0xFF {
			continue
		}
		// Skip fill bytes: FF FF ... FF <marker>.
		j := i
		for j+1 < len(b) && b[j+1] == 0xFF {
			j++
		}
		if j+1 >= len(b) {
			return 0, fmt.Errorf("%w: JPEG scan ended on a fill byte", ErrSanitizeMalformedInput)
		}
		next := b[j+1]
		if next == 0x00 || (next >= 0xD0 && next <= 0xD7) {
			i = j
			continue
		}
		return j, nil
	}
	return len(b), nil
}

// pngMetadataChunks is the closed set of PNG chunk types that carry metadata.
// eXIf is the PNG container for the same EXIF block JPEG puts in APP1; the
// text chunks carry everything from authorship to embedded XMP.
// iCCP, sRGB, gAMA and cHRM are deliberately ABSENT: they are PNG's colour
// management, the same role APP2/APP14 play in JPEG, and dropping them here
// while keeping them there would make the two paths disagree about what
// "metadata" means.
var pngMetadataChunks = map[string]bool{
	"tEXt": true, "iTXt": true, "zTXt": true,
	"eXIf": true, "tIME": true,
}

// stripPNGMetadata drops metadata chunks from a PNG, copying every other chunk
// through byte-for-byte -- IDAT (the compressed image) is never touched.
func stripPNGMetadata(src []byte) ([]byte, error) {
	sig := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}
	if len(src) < len(sig) || !bytes.Equal(src[:len(sig)], sig) {
		return nil, fmt.Errorf("%w: not a PNG (bad signature)", ErrSanitizeMalformedInput)
	}

	var out bytes.Buffer
	out.Write(sig)

	i := len(sig)
	for i+8 <= len(src) {
		length := int(binary.BigEndian.Uint32(src[i : i+4]))
		if length < 0 || i+12+length > len(src) {
			return nil, fmt.Errorf("%w: invalid PNG chunk length %d at offset %d", ErrSanitizeMalformedInput, length, i)
		}
		ctype := string(src[i+4 : i+8])
		end := i + 12 + length // length + type + data + CRC

		if !pngMetadataChunks[ctype] {
			out.Write(src[i:end])
		}
		i = end
		if ctype == "IEND" {
			break
		}
	}
	return out.Bytes(), nil
}

// sanitizeImage strips metadata from inPath into outPath.
//
// The format is decided from the file's own magic bytes, not from the caller's
// claimed format: a client that uploads a PNG named .jpg would otherwise get
// the JPEG walker, which would fail on the signature check and turn a
// mislabelled file into an error instead of a sanitized one.
//
// x is unused: metadata stripping walks the file's own byte structure in
// pure Go and execs nothing. It carries the parameter only because
// sanitizeFormats' value type is shared across all six format handlers.
func sanitizeImage(ctx context.Context, _ engineExec, inPath, outPath string) (SanitizeResult, error) {
	src, err := os.ReadFile(inPath)
	if err != nil {
		return SanitizeResult{}, fmt.Errorf("sanitize image: read: %w", err)
	}

	var out []byte
	switch {
	case len(src) >= 2 && src[0] == 0xFF && src[1] == 0xD8:
		out, err = stripJPEGMetadata(src)
	case len(src) >= 8 && bytes.Equal(src[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}):
		out, err = stripPNGMetadata(src)
	default:
		return SanitizeResult{}, fmt.Errorf("%w: unrecognized image container", ErrSanitizeMalformedInput)
	}
	if err != nil {
		// Already carries ErrSanitizeMalformedInput where it applies -- every
		// walker failure above is a statement about the INPUT, deterministic
		// on it, and the worker must classify all of them terminal rather
		// than only the ghostscript ones. Applying the sentinel to some
		// input-parse paths and not others is the same
		// stopped-at-the-first-instance shape review found twice already
		// (PR #12, rounds 4 and 5).
		return SanitizeResult{}, fmt.Errorf("sanitize image: %w", err)
	}

	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		return SanitizeResult{}, fmt.Errorf("sanitize image: write output: %w", err)
	}

	_ = ctx // pure Go; no external process to cancel

	return SanitizeResult{
		Removed: append([]ThreatClass(nil), imageThreatClasses...),
		// Nothing is lost: the compressed image data is copied verbatim, so
		// there is no quality cost to report. An empty list here is a claim,
		// and TestSanitizeImageIsLossless is what backs it.
		LostCapabilities: nil,
	}, nil
}
