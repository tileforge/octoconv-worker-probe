package pdfref805d49da

import "bytes"

type pdfScan struct {
	objects map[int]int

	streams [][2]int

	unresolved int

	objectsCapped bool
}

type pdfLexInt struct {
	value int
	at    int
}

func scanPDF(b []byte) pdfScan { return scanPDFSeeded(b, nil) }

func scanPDFSeeded(b []byte, seed map[int]int) pdfScan { return scanPDFImpl(b, seed, 0) }

func scanPDFLimited(b []byte, seed map[int]int, maxObjects int) pdfScan {
	return scanPDFImpl(b, seed, maxObjects)
}

func scanPDFImpl(b []byte, seed map[int]int, maxObjects int) pdfScan {
	res := pdfScan{objects: map[int]int{}}
	for k, v := range seed {
		res.objects[k] = v
	}

	ints := make([]pdfLexInt, 0, 2)
	depth := 0

	arrayDepth := 0

	dictClosed := false
	lengthValue, lengthRef, haveLength := 0, false, false

	awaitLength := false
	pendingValue, pendingRef, pendingOK := 0, false, false

	i := 0
	for i < len(b) {
		c := b[i]

		if isPDFSpace(c) {
			i++
			continue
		}
		if c == '%' {
			for i < len(b) && b[i] != '\n' && b[i] != '\r' {
				i++
			}
			continue
		}
		if c == '(' {
			i = pdfSkipLiteralString(b, i)
			ints = ints[:0]
			dictClosed = false
			continue
		}

		if c == '<' {
			if i+1 < len(b) && b[i+1] == '<' {
				depth++
				i += 2
				ints = ints[:0]
				dictClosed = false
				continue
			}
			i = pdfSkipHexString(b, i)
			ints = ints[:0]
			dictClosed = false
			continue
		}
		if c == '>' && i+1 < len(b) && b[i+1] == '>' {
			depth--
			i += 2
			if depth <= 0 {
				depth = 0
				dictClosed = true
				lengthValue, lengthRef, haveLength = pendingValue, pendingRef, pendingOK
				pendingValue, pendingRef, pendingOK = 0, false, false
			}
			ints = ints[:0]
			continue
		}

		if c == '[' {
			arrayDepth++
			i++
			ints = ints[:0]
			dictClosed = false
			continue
		}
		if c == ']' {
			if arrayDepth > 0 {
				arrayDepth--
			}
			i++
			ints = ints[:0]
			dictClosed = false
			continue
		}

		if c == '/' {
			if depth == 0 {

				i = pdfSkipName(b, i)
				awaitLength = false
				ints = ints[:0]
				dictClosed = false
				continue
			}
			name, next := pdfReadName(b, i)
			i = next

			awaitLength = depth == 1 && arrayDepth == 0 && name == "Length"
			ints = ints[:0]
			dictClosed = false
			continue
		}

		if c >= '0' && c <= '9' || ((c == '+' || c == '-') && i+1 < len(b) && b[i+1] >= '0' && b[i+1] <= '9') {

			v, next := pdfReadSignedInt(b, i)
			if awaitLength {
				pendingValue, pendingOK = v, true
				pendingRef = pdfLooksLikeRef(b, next)
				awaitLength = false
			}
			if len(ints) == 2 {
				ints[0] = ints[1]
				ints = ints[:1]
			}
			ints = append(ints, pdfLexInt{value: v, at: i})
			i = next
			dictClosed = false
			continue
		}

		word, next := pdfReadKeyword(b, i)
		switch {
		case word == "obj" && depth == 0 && len(ints) == 2:
			if maxObjects > 0 && len(res.objects) >= maxObjects {

				res.objectsCapped = true
				return res
			}
			res.objects[ints[0].value] = next
			i = next
			ints = ints[:0]
			dictClosed = false

		case word == "stream" && dictClosed:
			payload := next
			if payload < len(b) && b[payload] == '\r' {
				payload++
			}
			if payload < len(b) && b[payload] == '\n' {
				payload++
			}

			n, ok := 0, false
			if haveLength {
				if lengthRef {
					if off, found := res.objects[lengthValue]; found {
						n, _, ok = pdfReadIntAt(b, off)
					}
				} else {
					n, ok = lengthValue, true
				}
			}
			if !ok || n < 0 || payload+n > len(b) || !pdfEndstreamFollows(b, payload+n) {

				res.unresolved++
				if e := bytes.Index(b[payload:], []byte("endstream")); e >= 0 {
					i = payload + e + len("endstream")
				} else {
					i = next
				}
				dictClosed = false
				ints = ints[:0]
				haveLength = false
				continue
			}
			res.streams = append(res.streams, [2]int{payload, payload + n})
			i = payload + n
			dictClosed = false
			ints = ints[:0]
			haveLength = false

		default:
			i = next
			dictClosed = false
			ints = ints[:0]
		}
	}
	return res
}

func pdfSkipLiteralString(b []byte, i int) int {
	i++
	nest := 1
	for i < len(b) {
		switch b[i] {
		case '\\':
			i += 2
			continue
		case '(':
			nest++
		case ')':
			nest--
			if nest == 0 {
				return i + 1
			}
		}
		i++
	}
	return len(b)
}

func pdfSkipHexString(b []byte, i int) int {
	i++
	for i < len(b) && b[i] != '>' {
		i++
	}
	if i < len(b) {
		i++
	}
	return i
}

func pdfReadName(b []byte, i int) (string, int) {
	i++
	var out []byte
	for i < len(b) && !isPDFSpace(b[i]) && !isPDFDelimiter(b[i]) {
		if b[i] == '#' && i+2 < len(b) {
			hi, ok1 := pdfHexDigit(b[i+1])
			lo, ok2 := pdfHexDigit(b[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 3
				continue
			}
		}
		out = append(out, b[i])
		i++
	}
	return string(out), i
}

func pdfSkipName(b []byte, i int) int {
	i++
	for i < len(b) && !isPDFSpace(b[i]) && !isPDFDelimiter(b[i]) {
		if b[i] == '#' && i+2 < len(b) {
			if _, ok1 := pdfHexDigit(b[i+1]); ok1 {
				if _, ok2 := pdfHexDigit(b[i+2]); ok2 {
					i += 3
					continue
				}
			}
		}
		i++
	}
	return i
}

func pdfHexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func pdfReadKeyword(b []byte, i int) (string, int) {
	if isPDFDelimiter(b[i]) {
		return "", i + 1
	}
	start := i
	for i < len(b) && !isPDFSpace(b[i]) && !isPDFDelimiter(b[i]) {
		i++
	}
	return string(b[start:i]), i
}

func pdfReadSignedInt(b []byte, i int) (int, int) {
	neg := false
	if i < len(b) && (b[i] == '+' || b[i] == '-') {
		neg = b[i] == '-'
		i++
	}
	v, next := pdfReadUint(b, i)
	if neg {
		return -v, next
	}
	return v, next
}

func pdfReadUint(b []byte, i int) (int, int) {
	v := 0
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		v = v*10 + int(b[i]-'0')
		if v > 1<<30 {
			v = 1 << 30
		}
		i++
	}
	return v, i
}

func pdfReadIntAt(b []byte, off int) (int, int, bool) {
	i := pdfSkipTrivia(b, off)
	if i >= len(b) {
		return 0, i, false
	}
	if !(b[i] >= '0' && b[i] <= '9') && !((b[i] == '+' || b[i] == '-') && i+1 < len(b) && b[i+1] >= '0' && b[i+1] <= '9') {
		return 0, i, false
	}
	v, next := pdfReadSignedInt(b, i)
	return v, next, true
}

func pdfLooksLikeRef(b []byte, i int) bool {
	i = pdfSkipTrivia(b, i)
	if i >= len(b) || b[i] < '0' || b[i] > '9' {
		return false
	}
	_, i = pdfReadUint(b, i)
	i = pdfSkipTrivia(b, i)
	return i < len(b) && b[i] == 'R'
}

func pdfSkipTrivia(b []byte, i int) int {
	for i < len(b) {
		if isPDFSpace(b[i]) {
			i++
			continue
		}
		if b[i] == '%' {
			for i < len(b) && b[i] != '\n' && b[i] != '\r' {
				i++
			}
			continue
		}
		return i
	}
	return i
}

func isPDFDelimiter(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func pdfEndstreamFollows(b []byte, end int) bool {
	i := end
	for i < len(b) && isPDFSpace(b[i]) {
		i++
	}
	return bytes.HasPrefix(b[i:], []byte("endstream"))
}

func isPDFSpace(c byte) bool {
	return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\f' || c == 0
}

func pdfXrefObjects(b []byte) map[int]int { return pdfXrefObjectsLimited(b, 0) }

func pdfXrefObjectsLimited(b []byte, maxIndexed int) map[int]int {
	out := map[int]int{}

	at := bytes.LastIndex(b, []byte("startxref"))
	if at < 0 {
		return out
	}
	off, _, ok := pdfReadIntAt(b, at+len("startxref"))
	if !ok {
		return out
	}

	seen := map[int]bool{}
	for hops := 0; hops < pdfXrefMaxHops; hops++ {
		if off < 0 || off >= len(b) || seen[off] {
			return out
		}
		seen[off] = true

		i := pdfSkipTrivia(b, off)
		if !bytes.HasPrefix(b[i:], []byte("xref")) {

			return out
		}
		i += len("xref")

		for {
			i = pdfSkipTrivia(b, i)
			if bytes.HasPrefix(b[i:], []byte("trailer")) {
				i += len("trailer")
				break
			}
			startNum, next, ok := pdfReadIntAt(b, i)
			if !ok {
				return out
			}
			count, next2, ok := pdfReadIntAt(b, next)
			if !ok || count < 0 || count > pdfXrefMaxEntries {
				return out
			}
			i = next2
			for n := 0; n < count; n++ {
				entOff, e1, ok1 := pdfReadIntAt(b, i)
				_, e2, ok2 := pdfReadIntAt(b, e1)
				if !ok1 || !ok2 {
					return out
				}
				j := pdfSkipTrivia(b, e2)
				if j >= len(b) {
					return out
				}
				kind := b[j]
				i = j + 1
				if kind != 'n' {
					continue
				}
				num := startNum + n
				if maxIndexed > 0 && len(out) >= maxIndexed {

					return out
				}
				if hdr, ok := pdfObjectHeaderAt(b, entOff, num); ok {

					if _, already := out[num]; !already {
						out[num] = hdr
					}
				}
			}
		}

		prev, ok := pdfTrailerPrev(b, i)
		if !ok {
			return out
		}
		off = prev
	}
	return out
}

const (
	pdfXrefMaxHops = 32

	pdfXrefMaxEntries = 1 << 20

	pdfXrefMaxIndexed = 1 << 16
)

func pdfObjectHeaderAt(b []byte, off, num int) (int, bool) {
	if off < 0 || off >= len(b) {
		return 0, false
	}
	got, next, ok := pdfReadIntAt(b, off)
	if !ok || got != num {
		return 0, false
	}
	if _, next, ok = pdfReadIntAt(b, next); !ok {
		return 0, false
	}
	next = pdfSkipTrivia(b, next)
	if !bytes.HasPrefix(b[next:], []byte("obj")) {
		return 0, false
	}
	return next + len("obj"), true
}

func pdfTrailerPrev(b []byte, i int) (int, bool) {
	i = pdfSkipTrivia(b, i)
	if !bytes.HasPrefix(b[i:], []byte("<<")) {
		return 0, false
	}

	depth, arrayDepth := 0, 0
	await := false
	for i < len(b) {
		c := b[i]
		switch {
		case isPDFSpace(c) || c == '%':
			i = pdfSkipTrivia(b, i)
			continue
		case c == '(':
			i = pdfSkipLiteralString(b, i)
			await = false
			continue
		case c == '<' && i+1 < len(b) && b[i+1] == '<':
			depth++
			i += 2
			await = false
			continue
		case c == '<':
			i = pdfSkipHexString(b, i)
			await = false
			continue
		case c == '>' && i+1 < len(b) && b[i+1] == '>':
			depth--
			i += 2
			await = false
			if depth <= 0 {

				return 0, false
			}
			continue
		case c == '[':
			arrayDepth++
			i++
			await = false
			continue
		case c == ']':
			if arrayDepth > 0 {
				arrayDepth--
			}
			i++
			await = false
			continue
		case c == '/':
			name, next := pdfReadName(b, i)
			i = next

			await = depth == 1 && arrayDepth == 0 && name == "Prev"
			continue
		}

		if await {
			v, next, ok := pdfReadIntAt(b, i)
			if !ok {
				i = next
				await = false
				continue
			}

			if pdfLooksLikeRef(b, next) {
				return 0, false
			}
			return v, true
		}
		i++
	}
	return 0, false
}

const pdfMaxIndexedObjects = 65536

const maxPDFDictDepth = 64

func PDFTypedDictUints(b []byte, typeName, key string, maxDicts int) (values []int, ceilingHit bool) {

	scan := scanPDFLimited(b, nil, pdfMaxIndexedObjects)
	if scan.objectsCapped {
		return nil, true
	}
	objects := scan.objects
	for num, off := range pdfXrefObjectsLimited(b, pdfMaxIndexedObjects) {
		objects[num] = off
	}

	type frame struct {
		isType    bool
		val       int
		haveVal   bool
		expectKey bool
		key       string

		valueArrayDepth int

		valueDictDepth int
	}
	var stack []frame

	endValue := func() {
		if n := len(stack); n > 0 {
			stack[n-1].key = ""
			stack[n-1].expectKey = true
		}
	}

	endValueIfDirect := func(arrayDepth int) {
		if arrayDepth != 0 {
			return
		}
		if n := len(stack); n > 0 && !stack[n-1].expectKey {
			endValue()
		}
	}

	arrayDepth := 0
	matched := 0

	awaitVal := false

	dictClosed := false
	lengthVal, haveLength := 0, false
	awaitLength := false
	pendingLength, pendingRef, pendingHave := 0, false, false

	i := 0
	for i < len(b) {
		c := b[i]

		if isPDFSpace(c) {
			i++
			continue
		}
		if c == '%' {
			for i < len(b) && b[i] != '\n' && b[i] != '\r' {
				i++
			}
			continue
		}
		if c == '(' {
			i = pdfSkipLiteralString(b, i)
			dictClosed, awaitVal = false, false

			endValueIfDirect(arrayDepth)
			continue
		}
		if c == '<' {
			if i+1 < len(b) && b[i+1] == '<' {
				if len(stack) >= maxPDFDictDepth {

					return nil, true
				}
				if n := len(stack); n > 0 && !stack[n-1].expectKey {

					stack[n-1].valueDictDepth = len(stack)
				}
				stack = append(stack, frame{expectKey: true})
				i += 2
				dictClosed, awaitVal = false, false
				continue
			}
			i = pdfSkipHexString(b, i)
			dictClosed, awaitVal = false, false
			endValueIfDirect(arrayDepth)
			continue
		}
		if c == '>' && i+1 < len(b) && b[i+1] == '>' {
			i += 2
			if n := len(stack); n > 0 {
				f := stack[n-1]
				stack = stack[:n-1]
				if f.isType && f.haveVal {
					values = append(values, f.val)
				}
				if m := len(stack); m > 0 && !stack[m-1].expectKey && stack[m-1].valueDictDepth == m {
					stack[m-1].valueDictDepth = 0
					endValue()
				}
				if len(stack) == 0 {
					dictClosed = true
					lengthVal, haveLength = pendingLength, pendingHave
					if pendingHave && pendingRef {
						if off, found := objects[pendingLength]; found {
							lengthVal, _, haveLength = pdfReadIntAt(b, off)
						} else {
							haveLength = false
						}
					}
					pendingLength, pendingRef, pendingHave = 0, false, false
				}
			}
			awaitVal = false
			continue
		}
		if c == '[' {
			if n := len(stack); n > 0 && !stack[n-1].expectKey && stack[n-1].valueArrayDepth == 0 {
				stack[n-1].valueArrayDepth = arrayDepth + 1
			}
			arrayDepth++
			i++
			dictClosed, awaitVal = false, false
			continue
		}
		if c == ']' {
			if arrayDepth > 0 {
				arrayDepth--
			}
			i++
			if n := len(stack); n > 0 && !stack[n-1].expectKey && stack[n-1].valueArrayDepth == arrayDepth+1 {
				stack[n-1].valueArrayDepth = 0
				endValue()
			}
			dictClosed, awaitVal = false, false
			continue
		}

		if c == '/' {

			if len(stack) == 0 || arrayDepth != 0 {
				i = pdfSkipName(b, i)
				dictClosed = false
				continue
			}

			name, next := pdfReadName(b, i)
			i = next
			dictClosed = false
			n := len(stack)
			if n == 0 || arrayDepth != 0 {

				continue
			}
			if stack[n-1].expectKey {
				stack[n-1].key = name
				stack[n-1].expectKey = false
				awaitLength = n == 1 && name == "Length"
				continue
			}

			if stack[n-1].key == "Type" && name == typeName {
				stack[n-1].isType = true

				if matched++; matched > maxDicts {
					return nil, true
				}
			}
			awaitLength = false
			endValue()
			continue
		}

		if c >= '0' && c <= '9' || ((c == '+' || c == '-') && i+1 < len(b) && b[i+1] >= '0' && b[i+1] <= '9') {
			v, next := pdfReadSignedInt(b, i)
			isValue := false
			if n := len(stack); n > 0 && arrayDepth == 0 && !stack[n-1].expectKey {
				isValue = stack[n-1].key == key
			}
			awaitVal = isValue
			if awaitVal {

				if n := len(stack); n > 0 {
					val, have := v, v >= 0
					if pdfLooksLikeRef(b, next) {
						val, have = 0, false
						if off, found := objects[v]; found {
							if resolved, _, ok := pdfReadIntAt(b, off); ok && resolved >= 0 {
								val, have = resolved, true
							}
						}
					}
					if have {
						stack[n-1].val, stack[n-1].haveVal = val, true
					}
				}
				awaitVal = false
			}
			if awaitLength {
				pendingLength, pendingRef, pendingHave = v, pdfLooksLikeRef(b, next), true
				awaitLength = false
			}
			i = next
			dictClosed = false

			if n := len(stack); n > 0 && arrayDepth == 0 && !stack[n-1].expectKey {
				if pdfLooksLikeRef(b, next) {
					i = pdfSkipRefTail(b, next)
				}
				endValue()
			}
			continue
		}

		word, next := pdfReadKeyword(b, i)
		if word == "stream" && dictClosed {
			payload := next
			if payload < len(b) && b[payload] == '\r' {
				payload++
			}
			if payload < len(b) && b[payload] == '\n' {
				payload++
			}
			if !haveLength || lengthVal < 0 || payload+lengthVal > len(b) ||
				!pdfEndstreamFollows(b, payload+lengthVal) {

				return nil, true
			}
			i = payload + lengthVal
			dictClosed, haveLength = false, false
			continue
		}
		i = next
		dictClosed, awaitVal = false, false
		if word != "" && arrayDepth == 0 {
			if n := len(stack); n > 0 && !stack[n-1].expectKey {
				endValue()
			}
		}
	}

	return values, false
}

func pdfSkipRefTail(b []byte, from int) int {
	i := pdfSkipTrivia(b, from)
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	i = pdfSkipTrivia(b, i)
	if i < len(b) && b[i] == 'R' {
		i++
	}
	return i
}

const MaxIndexedObjects = pdfMaxIndexedObjects

type ScanResult struct {
	Objects       map[int]int
	Streams       [][2]int
	Unresolved    int
	ObjectsCapped bool
}

func scanResult(s pdfScan) ScanResult {
	return ScanResult{Objects: s.objects, Streams: s.streams, Unresolved: s.unresolved, ObjectsCapped: s.objectsCapped}
}

func ScanPDF(b []byte) ScanResult { return scanResult(scanPDF(b)) }

func ScanPDFSeeded(b []byte, seed map[int]int) ScanResult { return scanResult(scanPDFSeeded(b, seed)) }

func ScanPDFLimited(b []byte, maxObjects int) ScanResult {
	return scanResult(scanPDFLimited(b, nil, maxObjects))
}

func XrefObjects(b []byte) map[int]int { return pdfXrefObjects(b) }

func XrefObjectsLimited(b []byte, maxIndexed int) map[int]int {
	return pdfXrefObjectsLimited(b, maxIndexed)
}

func ReadName(b []byte, i int) (string, int) { return pdfReadName(b, i) }

func ReadKeyword(b []byte, i int) (string, int) { return pdfReadKeyword(b, i) }

func MergedObjects(b []byte) int {
	scan := scanPDFLimited(b, nil, pdfMaxIndexedObjects)
	if scan.objectsCapped {
		return -1
	}
	merged := len(scan.objects)
	for num := range pdfXrefObjectsLimited(b, pdfMaxIndexedObjects) {
		if _, ok := scan.objects[num]; !ok {
			merged++
		}
	}
	return merged
}
