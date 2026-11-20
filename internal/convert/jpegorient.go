package convert

// EXIF orientation is baked into the raster before APP1 is removed.
//
// Orientations 2-4 mirror quantized DCT coefficients: a horizontal mirror
// negates odd columns, a vertical mirror negates odd rows. Orientations 5-8
// also transpose the coefficients, and the quantization tables with them,
// because dequantization is a per-index multiply and the value that was at
// (u,v) has to be dequantized by the table entry that moves with it.
//
// A frame whose width or height is not a multiple of its MCU is not moved
// this way. The edge block holds both the last visible samples and the
// encoder's padding, so a block permutation pulls that padding into the new
// frame. Those files are decoded and encoded again. image/jpeg.Encode writes
// YCbCr and does not emit APP2, so a complete ICC profile is placed back
// after the new SOI. An APP14 segment is placed back only when its transform
// byte is already YCbCr. Transform 0 means RGB, and copying it onto the new
// file makes a decoder read the YCbCr components as RGB.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
)

var errJPEGOrientFallback = errors.New("jpeg orientation coefficient path does not apply")

// jpegOrientMaxPixels bounds a frame whose orientation is applied here.
// SOF width and height are not limited by the file size, and the coefficient
// path stores 256 bytes per block, so an unchecked frame allocates far more
// than the input length predicts.
const jpegOrientMaxPixels = 48_000_000

// jpegAdobeTransformYCbCr is the APP14 colour transform value for YCbCr.
// 0 means RGB and 2 means YCCK. image/jpeg.Encode writes YCbCr.
const jpegAdobeTransformYCbCr = 1

// jpegUnzig maps a zig-zag index to a natural-order index. ITU-T T.81.
var jpegUnzig = [64]int{
	0, 1, 8, 16, 9, 2, 3, 10,
	17, 24, 32, 25, 18, 11, 4, 5,
	12, 19, 26, 33, 40, 48, 41, 34,
	27, 20, 13, 6, 7, 14, 21, 28,
	35, 42, 49, 56, 57, 50, 43, 36,
	29, 22, 15, 23, 30, 37, 44, 51,
	58, 59, 52, 45, 38, 31, 39, 46,
	53, 60, 61, 54, 47, 55, 62, 63,
}

type jpegBlock [64]int32

type jpegOrientComp struct {
	id, h, v int
	blocksX  int
	blocksY  int
	blocks   []jpegBlock
}

type jpegOrientSeg struct {
	marker  byte
	payload []byte
	raw     []byte
	scan    []byte
}

type jpegHuff struct {
	nbits [256]uint8
	code  [256]uint16
	min   [17]int
	max   [17]int
	idx   [17]int
	vals  []byte
}

func jpegEXIFOrientation(src []byte) (int, error) {
	orient := 0
	var bad error
	err := walkJPEGSegments(src, func(seg jpegMarkerSegment) {
		if bad != nil || seg.marker != 0xE1 || !bytes.HasPrefix(seg.payload, []byte("Exif\x00\x00")) {
			return
		}
		o, err := tiffOrientation(seg.payload[6:])
		if err != nil {
			bad = err
			return
		}
		if o == 0 {
			return
		}
		if orient != 0 && orient != o {
			bad = fmt.Errorf("%w: conflicting JPEG EXIF orientation", ErrSanitizeMalformedInput)
			return
		}
		orient = o
	})
	if err != nil {
		return 0, err
	}
	if bad != nil {
		return 0, bad
	}
	return orient, nil
}

func tiffOrientation(tiff []byte) (int, error) {
	if len(tiff) < 8 {
		return 0, nil
	}
	var bo binary.ByteOrder
	switch string(tiff[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return 0, nil
	}
	if bo.Uint16(tiff[2:4]) != 42 {
		return 0, nil
	}
	off := int(bo.Uint32(tiff[4:8]))
	if off < 8 || off+2 > len(tiff) {
		return 0, nil
	}
	n := int(bo.Uint16(tiff[off : off+2]))
	if n > 256 {
		return 0, fmt.Errorf("%w: JPEG EXIF IFD", ErrSanitizeMalformedInput)
	}
	if off+2+n*12 > len(tiff) {
		return 0, fmt.Errorf("%w: JPEG EXIF IFD truncated", ErrSanitizeMalformedInput)
	}
	found := 0
	for i := 0; i < n; i++ {
		e := off + 2 + i*12
		if bo.Uint16(tiff[e:e+2]) != 0x0112 {
			continue
		}
		typ := bo.Uint16(tiff[e+2 : e+4])
		cnt := bo.Uint32(tiff[e+4 : e+8])
		if cnt != 1 || (typ != 3 && typ != 4) {
			return 0, fmt.Errorf("%w: JPEG EXIF orientation type", ErrSanitizeMalformedInput)
		}
		var v uint32
		if typ == 3 {
			v = uint32(bo.Uint16(tiff[e+8 : e+10]))
		} else {
			v = bo.Uint32(tiff[e+8 : e+12])
		}
		if v < 1 || v > 8 {
			return 0, fmt.Errorf("%w: JPEG EXIF orientation %d", ErrSanitizeMalformedInput, v)
		}
		found = int(v)
	}
	return found, nil
}

func orientJPEG(src []byte, orient int) ([]byte, error) {
	if orient < 2 || orient > 8 {
		return nil, fmt.Errorf("%w: JPEG EXIF orientation %d", ErrSanitizeMalformedInput, orient)
	}
	if cfg, err := jpeg.DecodeConfig(bytes.NewReader(src)); err == nil && cfg.Width > 0 && cfg.Height > jpegOrientMaxPixels/cfg.Width {
		return nil, fmt.Errorf("%w: JPEG orientation frame is too large", ErrSanitizeMalformedInput)
	}
	if out, err := orientJPEGLossless(src, orient); err == nil {
		return out, nil
	}
	return orientJPEGPixels(src, orient)
}

func orientJPEGPixels(src []byte, orient int) ([]byte, error) {
	kept, err := keptJPEGColourSegments(src)
	if err != nil {
		return nil, err
	}
	img, err := jpeg.Decode(bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("%w: JPEG orientation: %v", ErrSanitizeMalformedInput, err)
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, orientRaster(img, orient), &jpeg.Options{Quality: 100}); err != nil {
		return nil, fmt.Errorf("%w: JPEG orientation: %v", ErrSanitizeMalformedInput, err)
	}
	out, err := stripJPEGSegments(buf.Bytes())
	if err != nil || len(kept) == 0 {
		return out, err
	}
	return insertJPEGSegmentsAfterSOI(out, kept)
}

func keptJPEGColourSegments(src []byte) ([][]byte, error) {
	keepICC, err := iccChunkSetIsValid(src)
	if err != nil {
		return nil, err
	}
	var kept [][]byte
	err = walkJPEGSegments(src, func(seg jpegMarkerSegment) {
		switch {
		case keepICC && isJPEGICCChunk(seg.marker, seg.payload):
			kept = append(kept, bytes.Clone(seg.raw))
		case isKeptJPEGAppSegment(seg.marker, seg.payload) && seg.payload[jpegAdobePayloadLen-1] == jpegAdobeTransformYCbCr:
			kept = append(kept, bytes.Clone(seg.raw))
		}
	})
	return kept, err
}

func insertJPEGSegmentsAfterSOI(src []byte, segs [][]byte) ([]byte, error) {
	if len(src) < 2 || src[0] != 0xFF || src[1] != 0xD8 {
		return nil, fmt.Errorf("%w: not a JPEG (no SOI)", ErrSanitizeMalformedInput)
	}
	var out bytes.Buffer
	out.Write(src[:2])
	for _, seg := range segs {
		out.Write(seg)
	}
	out.Write(src[2:])
	return out.Bytes(), nil
}

func orientRaster(src image.Image, orient int) *image.RGBA {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	nw, nh := w, h
	if orient >= 5 {
		nw, nh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dx, dy := mapJPEGPixel(x, y, w, h, orient)
			dst.Set(dx, dy, src.At(b.Min.X+x, b.Min.Y+y))
		}
	}
	return dst
}

func mapJPEGPixel(x, y, w, h, orient int) (int, int) {
	switch orient {
	case 2:
		return w - 1 - x, y
	case 3:
		return w - 1 - x, h - 1 - y
	case 4:
		return x, h - 1 - y
	case 5:
		return y, x
	case 6:
		return h - 1 - y, x
	case 7:
		return h - 1 - y, w - 1 - x
	case 8:
		return y, w - 1 - x
	default:
		return x, y
	}
}

func orientJPEGLossless(src []byte, orient int) ([]byte, error) {
	if len(src) < 2 || src[0] != 0xFF || src[1] != 0xD8 {
		return nil, errJPEGOrientFallback
	}
	var segs []jpegOrientSeg
	err := walkJPEGSegments(src, func(seg jpegMarkerSegment) {
		segs = append(segs, jpegOrientSeg{
			marker: seg.marker, payload: seg.payload, raw: seg.raw, scan: seg.scan,
		})
	})
	if err != nil {
		return nil, errJPEGOrientFallback
	}

	var (
		comps      []jpegOrientComp
		width      int
		height     int
		sofPayload []byte
		tables     [2][4]*jpegHuff
		seenSOF    bool
		seenSOS    bool
		scanComps  []jpegScanComp
		decoded    bool
	)
	for i := range segs {
		seg := &segs[i]
		switch seg.marker {
		case 0xC0:
			if seenSOF {
				return nil, errJPEGOrientFallback
			}
			seenSOF = true
			sofPayload = seg.payload
			comps, width, height, err = parseSOF0(seg.payload)
			if err != nil {
				return nil, err
			}
		case 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF:
			return nil, errJPEGOrientFallback
		case 0xDD:
			return nil, errJPEGOrientFallback
		case 0xC4:
			if seenSOS {
				continue
			}
			if err := parseDHT(seg.payload, &tables); err != nil {
				return nil, err
			}
		case 0xDA:
			if seenSOS || !seenSOF {
				return nil, errJPEGOrientFallback
			}
			seenSOS = true
			scanComps, err = parseSOS(seg.payload, comps)
			if err != nil {
				return nil, err
			}
			if err := decodeJPEGScan(seg.scan, comps, scanComps, tables, width, height); err != nil {
				return nil, err
			}
			decoded = true
		}
	}
	if !decoded {
		return nil, errJPEGOrientFallback
	}

	transpose := orient >= 5
	for i := range comps {
		nb, nx, ny, err := transformJPEGBlocks(comps[i].blocks, comps[i].blocksX, comps[i].blocksY, orient)
		if err != nil {
			return nil, err
		}
		comps[i].blocks = nb
		comps[i].blocksX = nx
		comps[i].blocksY = ny
		if transpose {
			comps[i].h, comps[i].v = comps[i].v, comps[i].h
		}
	}
	if transpose {
		width, height = height, width
	}
	maxH, maxV := 1, 1
	for _, c := range comps {
		if c.h > maxH {
			maxH = c.h
		}
		if c.v > maxV {
			maxV = c.v
		}
	}
	if maxH == 0 || maxV == 0 || width%(8*maxH) != 0 || height%(8*maxV) != 0 {
		return nil, errJPEGOrientFallback
	}
	mxx := width / (8 * maxH)
	myy := height / (8 * maxV)
	for _, c := range comps {
		if c.blocksX != mxx*c.h || c.blocksY != myy*c.v {
			return nil, errJPEGOrientFallback
		}
	}

	scan, err := encodeJPEGScan(comps, scanComps, tables, mxx, myy)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.Write(src[:2])
	for _, seg := range segs {
		switch seg.marker {
		case 0xC0:
			writeJPEGMarker(&out, 0xC0, rewriteSOF0(sofPayload, width, height, comps))
		case 0xDB:
			if !transpose {
				out.Write(seg.raw)
				continue
			}
			payload, err := transposeDQTPayload(seg.payload)
			if err != nil {
				return nil, err
			}
			writeJPEGMarker(&out, 0xDB, payload)
		case 0xDA:
			writeJPEGMarker(&out, 0xDA, seg.payload)
			out.Write(scan)
		default:
			out.Write(seg.raw)
			out.Write(seg.scan)
		}
	}
	return out.Bytes(), nil
}

func parseSOF0(p []byte) ([]jpegOrientComp, int, int, error) {
	if len(p) < 6 || p[0] != 8 {
		return nil, 0, 0, errJPEGOrientFallback
	}
	height := int(binary.BigEndian.Uint16(p[1:3]))
	width := int(binary.BigEndian.Uint16(p[3:5]))
	n := int(p[5])
	if width <= 0 || height <= 0 || n < 1 || n > 4 || len(p) < 6+3*n {
		return nil, 0, 0, errJPEGOrientFallback
	}
	maxH, maxV := 1, 1
	comps := make([]jpegOrientComp, n)
	seen := map[int]bool{}
	for i := 0; i < n; i++ {
		id := int(p[6+3*i])
		hv := p[6+3*i+1]
		h, v := int(hv>>4), int(hv&0x0f)
		if seen[id] || h < 1 || h > 4 || v < 1 || v > 4 {
			return nil, 0, 0, errJPEGOrientFallback
		}
		seen[id] = true
		comps[i] = jpegOrientComp{id: id, h: h, v: v}
		if h > maxH {
			maxH = h
		}
		if v > maxV {
			maxV = v
		}
	}
	if width%(8*maxH) != 0 || height%(8*maxV) != 0 {
		return nil, 0, 0, errJPEGOrientFallback
	}
	mxx := width / (8 * maxH)
	myy := height / (8 * maxV)
	for i := range comps {
		comps[i].blocksX = mxx * comps[i].h
		comps[i].blocksY = myy * comps[i].v
		nblk := comps[i].blocksX * comps[i].blocksY
		if comps[i].blocksX <= 0 || nblk/comps[i].blocksX != comps[i].blocksY {
			return nil, 0, 0, errJPEGOrientFallback
		}
		comps[i].blocks = make([]jpegBlock, nblk)
	}
	return comps, width, height, nil
}

type jpegScanComp struct {
	index int
	td    int
	ta    int
}

func parseSOS(p []byte, comps []jpegOrientComp) ([]jpegScanComp, error) {
	if len(p) < 1 {
		return nil, errJPEGOrientFallback
	}
	n := int(p[0])
	if n < 1 || n > len(comps) || len(p) < 1+2*n+3 {
		return nil, errJPEGOrientFallback
	}
	ss, se, ahAl := int(p[1+2*n]), int(p[2+2*n]), int(p[3+2*n])
	if ss != 0 || se != 63 || ahAl != 0 {
		return nil, errJPEGOrientFallback
	}
	out := make([]jpegScanComp, n)
	used := map[int]bool{}
	for i := 0; i < n; i++ {
		id := int(p[1+2*i])
		td := int(p[2+2*i] >> 4)
		ta := int(p[2+2*i] & 0x0f)
		if td > 3 || ta > 3 {
			return nil, errJPEGOrientFallback
		}
		index := -1
		for ci := range comps {
			if comps[ci].id == id {
				index = ci
				break
			}
		}
		if index < 0 || used[index] {
			return nil, errJPEGOrientFallback
		}
		used[index] = true
		out[i] = jpegScanComp{index: index, td: td, ta: ta}
	}
	return out, nil
}

func parseDHT(p []byte, tables *[2][4]*jpegHuff) error {
	i := 0
	for i < len(p) {
		if i+17 > len(p) {
			return errJPEGOrientFallback
		}
		tc := int(p[i] >> 4)
		th := int(p[i] & 0x0f)
		i++
		if tc > 1 || th > 3 {
			return errJPEGOrientFallback
		}
		var counts [16]byte
		copy(counts[:], p[i:i+16])
		i += 16
		n := 0
		for _, c := range counts {
			n += int(c)
		}
		if n > 256 || i+n > len(p) {
			return errJPEGOrientFallback
		}
		h, err := newJPEGHuff(counts, append([]byte(nil), p[i:i+n]...))
		if err != nil {
			return err
		}
		tables[tc][th] = h
		i += n
	}
	return nil
}

func newJPEGHuff(counts [16]byte, vals []byte) (*jpegHuff, error) {
	h := &jpegHuff{vals: vals}
	for i := range h.max {
		h.max[i] = -1
	}
	code := 0
	k := 0
	for length := 1; length <= 16; length++ {
		n := int(counts[length-1])
		if n == 0 {
			code <<= 1
			continue
		}
		if k+n > len(vals) {
			return nil, errJPEGOrientFallback
		}
		h.min[length] = code
		h.max[length] = code + n - 1
		h.idx[length] = k
		for j := 0; j < n; j++ {
			if code >= 1<<length {
				return nil, errJPEGOrientFallback
			}
			sym := vals[k]
			h.nbits[sym] = uint8(length)
			h.code[sym] = uint16(code)
			code++
			k++
		}
		code <<= 1
	}
	if k != len(vals) {
		return nil, errJPEGOrientFallback
	}
	return h, nil
}

func (h *jpegHuff) decode(r *jpegBitReader) (byte, error) {
	code := 0
	for n := 1; n <= 16; n++ {
		bit, err := r.bit()
		if err != nil {
			return 0, err
		}
		code = (code << 1) | int(bit)
		if h.max[n] >= 0 && code >= h.min[n] && code <= h.max[n] {
			return h.vals[h.idx[n]+code-h.min[n]], nil
		}
	}
	return 0, errJPEGOrientFallback
}

func (h *jpegHuff) write(w *jpegBitWriter, sym int) error {
	if h == nil || sym < 0 || sym > 255 || h.nbits[sym] == 0 {
		return errJPEGOrientFallback
	}
	w.bits(uint32(h.code[sym]), int(h.nbits[sym]))
	return nil
}

type jpegBitReader struct {
	b   []byte
	i   int
	cur byte
	n   int
}

func (r *jpegBitReader) bit() (uint32, error) {
	if r.n == 0 {
		if r.i >= len(r.b) {
			return 0, errJPEGOrientFallback
		}
		c := r.b[r.i]
		r.i++
		if c == 0xFF {
			if r.i >= len(r.b) || r.b[r.i] != 0x00 {
				return 0, errJPEGOrientFallback
			}
			r.i++
		}
		r.cur = c
		r.n = 8
	}
	r.n--
	return uint32((r.cur >> r.n) & 1), nil
}

func (r *jpegBitReader) extend(t int) (int32, error) {
	if t == 0 {
		return 0, nil
	}
	if t > 16 {
		return 0, errJPEGOrientFallback
	}
	v := 0
	for i := 0; i < t; i++ {
		bit, err := r.bit()
		if err != nil {
			return 0, err
		}
		v = (v << 1) | int(bit)
	}
	if v < 1<<(t-1) {
		v += (-1 << t) + 1
	}
	return int32(v), nil
}

type jpegBitWriter struct {
	buf bytes.Buffer
	cur byte
	n   int
}

func (w *jpegBitWriter) bits(val uint32, n int) {
	for n > 0 {
		n--
		w.cur = (w.cur << 1) | byte((val>>n)&1)
		w.n++
		if w.n == 8 {
			w.buf.WriteByte(w.cur)
			if w.cur == 0xFF {
				w.buf.WriteByte(0x00)
			}
			w.cur = 0
			w.n = 0
		}
	}
}

func (w *jpegBitWriter) finish() {
	if w.n == 0 {
		return
	}
	for w.n < 8 {
		w.cur = (w.cur << 1) | 1
		w.n++
	}
	w.buf.WriteByte(w.cur)
	if w.cur == 0xFF {
		w.buf.WriteByte(0x00)
	}
}

func decodeJPEGScan(scan []byte, comps []jpegOrientComp, scanComps []jpegScanComp, tables [2][4]*jpegHuff, width, height int) error {
	maxH, maxV := 1, 1
	for _, c := range comps {
		if c.h > maxH {
			maxH = c.h
		}
		if c.v > maxV {
			maxV = c.v
		}
	}
	mxx := width / (8 * maxH)
	myy := height / (8 * maxV)
	br := jpegBitReader{b: scan}
	pred := make([]int32, len(comps))
	blockCount := 0
	for my := 0; my < myy; my++ {
		for mx := 0; mx < mxx; mx++ {
			for _, sc := range scanComps {
				comp := &comps[sc.index]
				dc, ac := tables[0][sc.td], tables[1][sc.ta]
				if dc == nil || ac == nil {
					return errJPEGOrientFallback
				}
				for j := 0; j < comp.h*comp.v; j++ {
					var bx, by int
					if len(scanComps) != 1 {
						bx = comp.h*mx + j%comp.h
						by = comp.v*my + j/comp.h
					} else {
						q := mxx * comp.h
						bx = blockCount % q
						by = blockCount / q
						blockCount++
					}
					b, err := decodeJPEGBlock(&br, dc, ac, &pred[sc.index])
					if err != nil {
						return err
					}
					comp.blocks[by*comp.blocksX+bx] = b
				}
			}
		}
	}
	return nil
}

func decodeJPEGBlock(r *jpegBitReader, dc, ac *jpegHuff, pred *int32) (jpegBlock, error) {
	var b jpegBlock
	sym, err := dc.decode(r)
	if err != nil {
		return b, err
	}
	if sym > 16 {
		return b, errJPEGOrientFallback
	}
	delta, err := r.extend(int(sym))
	if err != nil {
		return b, err
	}
	*pred += delta
	b[0] = *pred
	for zig := 1; zig < 64; {
		sym, err = ac.decode(r)
		if err != nil {
			return b, err
		}
		run := int(sym >> 4)
		size := int(sym & 0x0f)
		if size != 0 {
			zig += run
			if zig >= 64 {
				return b, errJPEGOrientFallback
			}
			acv, err := r.extend(size)
			if err != nil {
				return b, err
			}
			b[jpegUnzig[zig]] = acv
			zig++
			continue
		}
		if run == 0x0f {
			zig += 16
			continue
		}
		if run == 0 {
			break
		}
		return b, errJPEGOrientFallback
	}
	return b, nil
}

func encodeJPEGScan(comps []jpegOrientComp, scanComps []jpegScanComp, tables [2][4]*jpegHuff, mxx, myy int) ([]byte, error) {
	var w jpegBitWriter
	pred := make([]int32, len(comps))
	blockCount := 0
	for my := 0; my < myy; my++ {
		for mx := 0; mx < mxx; mx++ {
			for _, sc := range scanComps {
				comp := &comps[sc.index]
				dc, ac := tables[0][sc.td], tables[1][sc.ta]
				for j := 0; j < comp.h*comp.v; j++ {
					var bx, by int
					if len(scanComps) != 1 {
						bx = comp.h*mx + j%comp.h
						by = comp.v*my + j/comp.h
					} else {
						q := mxx * comp.h
						bx = blockCount % q
						by = blockCount / q
						blockCount++
					}
					if err := encodeJPEGBlock(&w, comp.blocks[by*comp.blocksX+bx], dc, ac, &pred[sc.index]); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	w.finish()
	return w.buf.Bytes(), nil
}

func encodeJPEGBlock(w *jpegBitWriter, b jpegBlock, dc, ac *jpegHuff, pred *int32) error {
	delta := b[0] - *pred
	*pred = b[0]
	if err := writeJPEGCoef(w, dc, 0, delta); err != nil {
		return err
	}
	run := 0
	for zig := 1; zig < 64; zig++ {
		v := b[jpegUnzig[zig]]
		if v == 0 {
			run++
			continue
		}
		for run > 15 {
			if err := ac.write(w, 0xF0); err != nil {
				return err
			}
			run -= 16
		}
		if err := writeJPEGCoef(w, ac, run, v); err != nil {
			return err
		}
		run = 0
	}
	if run > 0 {
		if err := ac.write(w, 0x00); err != nil {
			return err
		}
	}
	return nil
}

func writeJPEGCoef(w *jpegBitWriter, h *jpegHuff, run int, v int32) error {
	mag := v
	if mag < 0 {
		mag = -mag
	}
	n := 0
	for x := mag; x > 0; x >>= 1 {
		n++
	}
	if n > 16 {
		return errJPEGOrientFallback
	}
	if err := h.write(w, run<<4|n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	bits := uint32(v)
	if v < 0 {
		bits = uint32(v - 1)
	}
	w.bits(bits, n)
	return nil
}

func transformJPEGBlocks(src []jpegBlock, bx, by, orient int) ([]jpegBlock, int, int, error) {
	switch orient {
	case 2:
		return flipHJPEG(src, bx, by), bx, by, nil
	case 3:
		return flipVJPEG(flipHJPEG(src, bx, by), bx, by), bx, by, nil
	case 4:
		return flipVJPEG(src, bx, by), bx, by, nil
	case 5:
		b, nx, ny := transposeJPEG(src, bx, by)
		return b, nx, ny, nil
	case 6:
		b, nx, ny := transposeJPEG(src, bx, by)
		return flipHJPEG(b, nx, ny), nx, ny, nil
	case 7:
		b, nx, ny := transposeJPEG(src, bx, by)
		return flipVJPEG(flipHJPEG(b, nx, ny), nx, ny), nx, ny, nil
	case 8:
		b := flipHJPEG(src, bx, by)
		nb, nx, ny := transposeJPEG(b, bx, by)
		return nb, nx, ny, nil
	default:
		return nil, 0, 0, errJPEGOrientFallback
	}
}

func flipHJPEG(src []jpegBlock, bx, by int) []jpegBlock {
	dst := make([]jpegBlock, len(src))
	for y := 0; y < by; y++ {
		for x := 0; x < bx; x++ {
			dst[y*bx+x] = flipHJPEGBlock(src[y*bx+(bx-1-x)])
		}
	}
	return dst
}

func flipVJPEG(src []jpegBlock, bx, by int) []jpegBlock {
	dst := make([]jpegBlock, len(src))
	for y := 0; y < by; y++ {
		for x := 0; x < bx; x++ {
			dst[y*bx+x] = flipVJPEGBlock(src[(by-1-y)*bx+x])
		}
	}
	return dst
}

func transposeJPEG(src []jpegBlock, bx, by int) ([]jpegBlock, int, int) {
	dst := make([]jpegBlock, len(src))
	for y := 0; y < by; y++ {
		for x := 0; x < bx; x++ {
			dst[x*by+y] = transposeJPEGBlock(src[y*bx+x])
		}
	}
	return dst, by, bx
}

func flipHJPEGBlock(s jpegBlock) jpegBlock {
	var d jpegBlock
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			v := s[y*8+x]
			if x&1 == 1 {
				v = -v
			}
			d[y*8+x] = v
		}
	}
	return d
}

func flipVJPEGBlock(s jpegBlock) jpegBlock {
	var d jpegBlock
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			v := s[y*8+x]
			if y&1 == 1 {
				v = -v
			}
			d[y*8+x] = v
		}
	}
	return d
}

func transposeJPEGBlock(s jpegBlock) jpegBlock {
	var d jpegBlock
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			d[x*8+y] = s[y*8+x]
		}
	}
	return d
}

func transposeJPEGQuant(z [64]byte) [64]byte {
	var natural [64]byte
	for i := 0; i < 64; i++ {
		natural[jpegUnzig[i]] = z[i]
	}
	var t [64]byte
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			t[x*8+y] = natural[y*8+x]
		}
	}
	var out [64]byte
	for i := 0; i < 64; i++ {
		out[i] = t[jpegUnzig[i]]
	}
	return out
}

func transposeDQTPayload(p []byte) ([]byte, error) {
	out := append([]byte(nil), p...)
	i := 0
	for i < len(p) {
		if i >= len(p) {
			return nil, errJPEGOrientFallback
		}
		pq := p[i] >> 4
		i++
		if pq != 0 || i+64 > len(p) {
			return nil, errJPEGOrientFallback
		}
		var z [64]byte
		copy(z[:], p[i:i+64])
		t := transposeJPEGQuant(z)
		copy(out[i:], t[:])
		i += 64
	}
	return out, nil
}

func rewriteSOF0(payload []byte, width, height int, comps []jpegOrientComp) []byte {
	p := append([]byte(nil), payload...)
	binary.BigEndian.PutUint16(p[1:3], uint16(height))
	binary.BigEndian.PutUint16(p[3:5], uint16(width))
	n := int(p[5])
	for i := 0; i < n && 6+3*i+1 < len(p); i++ {
		id := int(p[6+3*i])
		for _, c := range comps {
			if c.id == id {
				p[6+3*i+1] = byte((c.h << 4) | c.v)
				break
			}
		}
	}
	return p
}

func writeJPEGMarker(out *bytes.Buffer, marker byte, payload []byte) {
	var hdr [4]byte
	hdr[0] = 0xFF
	hdr[1] = marker
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(payload)+2))
	out.Write(hdr[:])
	out.Write(payload)
}
