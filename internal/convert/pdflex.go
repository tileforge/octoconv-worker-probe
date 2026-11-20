package convert

import (
	"bytes"
	"fmt"
)

// A SMALL PDF TOKENIZER, AND WHY THIS FILE EXISTS AT ALL
//
// 63-CONTEXT.md D-02 said, in as many words: "no general PDF object parser. The
// resolver indexes N G obj offsets and reads one integer; anything more is a
// parser, and this phase is not writing one." That decision is reversed here,
// deliberately and on evidence.
//
// Three rounds of review found five defects in the byte-scanning version, and
// every one of them was the same defect: a token recognised by its bytes without
// regard to the lexical context it sits in.
//
//	round 1  "stream" matched inside "endstream"
//	round 1  "/Length" matched inside "/Length1"
//	round 1  object headers read out of stream payloads
//	round 3  object headers read out of COMMENTS
//	round 3  "stream" recognised inside a comment
//	round 3  ">>" inside a literal string counted as a dictionary close
//
// Patching a sixth would have been the fifth clever comparison in a row against
// a bound that keeps getting bypassed -- the pattern this project has already
// recorded in .planning/RETROSPECTIVE.md and resolved once before by replacing
// the comparison rather than refining it. A PDF's bytes have exactly four
// lexical contexts (whitespace, comment, literal string, hex string) plus tokens,
// and code that does not model those four will keep finding new ways to be
// wrong. So this models them. It is a tokenizer, not an object model: it does not
// build a document, resolve references beyond one integer, or decode anything.
//
// ONE TOKENIZER, TWO CONSUMERS -- ALSO A REVERSAL, ALSO ON EVIDENCE.
//
// sanitizepdf.go and sanitizeverify.go previously walked the file separately, so
// that "one subtle byte walker cannot feed both the redaction AND the check that
// is supposed to catch its mistakes". The reasoning was sound and the outcome was
// not: in rounds 1 through 3 the two walkers had IDENTICAL bugs every single
// time -- review said so explicitly, "the verifier repeats the same indexing
// behavior" -- because both were written by one author from one misunderstanding.
// The independence bought nothing on any occasion, and cost a second place to fix
// and a second chance to diverge on trivia (the two disagreed about whether a
// form feed is whitespace, which cost a valid file its output).
//
// What the two must NOT share is the proposition: the sanitizer decides what to
// remove, the verifier independently decides whether it is gone. Agreeing about
// where a stream's bytes are is a prerequisite for both, not a check of either --
// and there is already a test forcing that agreement, which means sharing loses
// no coverage that was real.
type pdfScan struct {
	// objects maps an object number to the offset just past its "N G obj"
	// header. Only headers found at top level, outside comments, strings and
	// stream payloads, are recorded.
	objects map[int]int
	// streams holds the payload range of every stream whose /Length resolved
	// and whose bytes agreed with it.
	streams [][2]int
	// unresolved counts streams whose length could not be established on this
	// pass -- for example one whose /Length object is defined later in the
	// file.
	unresolved int
	// objectsCapped reports that the walk STOPPED because it reached the
	// caller's object cap, so neither the index nor the stream list is
	// complete. Only scanPDFLimited's callers can see this, and they abstain
	// on it.
	objectsCapped bool
	stopped       bool
}

// pdfLexInt is an integer token and where it started, so "N G obj" can be read
// from the two integers preceding the keyword.
type pdfLexInt struct {
	value int
	at    int
}

// scanPDF walks b once, in order, and reports the object headers and stream
// payloads it finds.
//
// ORDER IS LOAD-BEARING, not incidental: a stream's /Length is resolved only
// from objects seen BEFORE it, and a resolved payload is jumped over whole, so
// no byte inside a payload can ever be read as structure. That is what makes a
// decoy planted in a payload unable to poison the lookup that precedes it.
func scanPDF(b []byte) pdfScan { return scanPDFSeeded(b, nil) }

// scanPDFSeeded is scanPDF with an object index from an earlier pass already in
// hand, so a /Length object defined AFTER the stream that refers to it can be
// resolved on the second look. Seeding is the only thing that makes the retry
// different from the first pass; everything else about the walk is identical,
// which is why there is one implementation and not two.
func scanPDFSeeded(b []byte, seed map[int]int) pdfScan { return scanPDFImpl(b, seed, 0, nil, true) }

func scanPDFLimited(b []byte, seed map[int]int, maxObjects int, stop func() bool) pdfScan {
	return scanPDFImpl(b, seed, maxObjects, stop, false)
}

const pdfStopCheckEvery = 1024

func scanPDFImpl(b []byte, seed map[int]int, maxObjects int, stop func() bool, keepStreams bool) pdfScan {
	res := pdfScan{objects: map[int]int{}}
	for k, v := range seed {
		res.objects[k] = v
	}

	// The last two integer tokens at depth 0, and never more than two.
	//
	// This used to be a nil slice trimmed with ints = ints[len(ints)-2:],
	// which keeps the SAME backing array: append then grows that array for the
	// life of the walk, so a long run of integers -- which is exactly what a
	// cross-reference table is -- allocated without bound. Measured before this
	// changed: a 20 971 614-byte file whose table declares the per-subsection
	// maximum cost 48.0 MB in scanPDF alone, ~2.3x the input, and this walk
	// runs in the API process for every /v1/inspect as well as in the sanitize
	// worker.
	//
	// A fixed capacity of two makes the trim a copy into the same array
	// instead, so the walk allocates this once.
	ints := make([]pdfLexInt, 0, 2)
	depth := 0
	// Arrays do not change dictionary depth, so a /Length inside "[ ... ]" was
	// read as another key of the enclosing dictionary and overwrote the real
	// one. "<< /Length N /Foo [/Length 5] >>" is legal and its stream is N
	// bytes long. Found by review on PR #14, round 4.
	arrayDepth := 0

	// State for the dictionary that most recently closed at top level. A
	// "stream" keyword is only a stream keyword when it directly follows one.
	dictClosed := false
	lengthValue, lengthRef, haveLength := 0, false, false

	// State while inside a dictionary: /Length was just read, so the next value
	// token is its value.
	awaitLength := false
	pendingValue, pendingRef, pendingOK := 0, false, false

	i := 0
	for iter := 0; i < len(b); iter++ {
		if stop != nil && iter%pdfStopCheckEvery == 0 && stop() {
			res.stopped = true
			return res
		}
		c := b[i]

		// The four non-token contexts. None of them clears dictClosed:
		// whitespace and comments may legally separate a dictionary from its
		// stream keyword (ISO 32000-1 7.2.4).
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
				// Outside every dictionary a name cannot be a key, and this
				// walk reads names ONLY as keys. Skipping without decoding is
				// what keeps a file of bare names from allocating per token.
				i = pdfSkipName(b, i)
				awaitLength = false
				ints = ints[:0]
				dictClosed = false
				continue
			}
			next := pdfSkipName(b, i)
			// /Length as a KEY of this dictionary: at dictionary depth 1 and
			// outside any array. A /Length in a /DecodeParms sub-dictionary or
			// inside an array value is not the stream's own.
			awaitLength = depth == 1 && arrayDepth == 0 && pdfNameEquals(b, i, "Length")
			i = next
			ints = ints[:0]
			dictClosed = false
			continue
		}

		if c >= '0' && c <= '9' || ((c == '+' || c == '-') && i+1 < len(b) && b[i+1] >= '0' && b[i+1] <= '9') {
			// PDF integers may carry a sign (ISO 32000-1 7.3.3). "/Length +5"
			// is valid and was rejected outright. A NEGATIVE length is not a
			// length, so it is read and then refused by the payload bounds
			// check rather than silently clamped.
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

		// A keyword: a run of regular characters.
		word, next := pdfKeywordAt(b, i)
		switch {
		case pdfKeywordIs(word, "obj") && depth == 0 && len(ints) == 2:
			if maxObjects > 0 && len(res.objects) >= maxObjects {
				// STOP, do not merely stop recording. The caller that passes a
				// cap abstains on objectsCapped, so every byte walked after
				// this point is work done for an answer that will not be given
				// -- and the walk itself allocates per token. Continuing to the
				// end of an 8 MiB body still cost 58 MB with the index capped.
				res.objectsCapped = true
				return res
			}
			res.objects[ints[0].value] = next
			i = next
			ints = ints[:0]
			dictClosed = false

		case pdfKeywordIs(word, "stream") && dictClosed:
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
				// RESYNCHRONISATION, NOT A RANGE.
				//
				// The length is unknown, so where the payload ends is unknown
				// -- but continuing to tokenize from here would read binary
				// payload bytes as PDF syntax, and a single "(" in compressed
				// data swallows the rest of the file as a literal string. That
				// is what happened on Ghostscript's own output, whose streams
				// carry "/Length 6 0 R" with object 6 written AFTER them: the
				// first pass indexed one object out of a whole file and the
				// retry had nothing better to work with.
				//
				// So resume at the next "endstream". This is the lexical guess
				// the rest of this file exists to avoid -- and it is safe HERE
				// and only here, because it decides nothing: no range is
				// recorded, the stream stays counted as unresolved, and if the
				// retry cannot resolve it properly the whole scan fails closed.
				// A guess used to keep reading is not a guess used to answer.
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
			if keepStreams {
				res.streams = append(res.streams, [2]int{payload, payload + n})
			}
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

// pdfSkipLiteralString returns the offset just past a "(...)" string, honouring
// backslash escapes and PDF's balanced-parenthesis nesting (ISO 32000-1 7.3.4.2).
//
// Without this, a dictionary carrying a string such as (>>) unbalanced the
// walker that used to scan backwards for the opening "<<", so the stream was
// silently treated as non-structural and its payload left unprotected.
func pdfSkipLiteralString(b []byte, i int) int {
	i++ // past '('
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

// pdfSkipHexString returns the offset just past a "<...>" hex string.
func pdfSkipHexString(b []byte, i int) int {
	i++ // past '<'
	for i < len(b) && b[i] != '>' {
		i++
	}
	if i < len(b) {
		i++
	}
	return i
}

func pdfNameEquals(b []byte, i int, s string) bool {
	i++
	n := 0
	for i < len(b) && !isPDFSpace(b[i]) && !isPDFDelimiter(b[i]) {
		c := b[i]
		if c == '#' && i+2 < len(b) {
			hi, ok1 := pdfHexDigit(b[i+1])
			lo, ok2 := pdfHexDigit(b[i+2])
			if ok1 && ok2 {
				c = hi<<4 | lo
				i += 2
			}
		}
		if n >= len(s) || s[n] != c {
			return false
		}
		n++
		i++
	}
	return n == len(s)
}

func pdfSkipName(b []byte, i int) int {
	i++ // past '/'
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

func pdfKeywordAt(b []byte, i int) ([]byte, int) {
	if isPDFDelimiter(b[i]) {
		return b[i:i], i + 1
	}
	start := i
	for i < len(b) && !isPDFSpace(b[i]) && !isPDFDelimiter(b[i]) {
		i++
	}
	return b[start:i], i
}

func pdfKeywordIs(word []byte, s string) bool { return string(word) == s }

// pdfReadSignedInt reads an optionally signed integer.
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

// pdfReadIntAt reads the first integer at or after off, skipping whitespace and
// comments. Used to read the value of an indirect /Length object.
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

// pdfLooksLikeRef reports whether the tokens after an integer are "G R", making
// that integer an object number rather than a value.
// pdfLooksLikeRef reports whether the tokens after an integer are "G R", making
// that integer an object number rather than a value.
//
// Comments count as whitespace between all three tokens: "/Length 7 % why\n0 R"
// is valid, and a version of this that skipped only whitespace read the 7 as a
// direct length -- so unless the stream happened to be seven bytes long, both
// passes left it unresolved and verifySanitized refused a valid PDF. Found by
// review on PR #14, round 4. The main loop already treated comments as
// whitespace; this helper is the second place that needed the same rule, which
// is the shape this package keeps paying for.
func pdfLooksLikeRef(b []byte, i int) bool {
	i = pdfSkipTrivia(b, i)
	if i >= len(b) || b[i] < '0' || b[i] > '9' {
		return false
	}
	_, i = pdfReadUint(b, i)
	i = pdfSkipTrivia(b, i)
	return i < len(b) && b[i] == 'R'
}

// pdfSkipTrivia advances over whitespace and comments -- the two things that
// may appear between any two tokens (ISO 32000-1 7.2.4).
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

// pdfEndstreamFollows confirms the dictionary and the bytes agree: "endstream"
// must appear after at most a run of whitespace. Disagreement is malformed
// input, not something to guess at.
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

// pdfStreamPayloads returns the payload range of every stream in b.
//
// A stream whose length cannot be established is an error, never a guess: a
// silent fallback to "scan for endstream" is exactly the defect this file
// replaced, and it would hide behind a passing test.
//
// THE RETRY IS ANCHORED IN THE CROSS-REFERENCE TABLE, NOT IN A GUESS.
//
// A forward pass cannot resolve "/Length 6 0 R" when object 6 is written AFTER
// the stream -- which is exactly what Ghostscript emits. The first version
// retried using the object index the forward pass had built, and review showed
// why that is not good enough: the pass RESYNCHRONISES at the first "endstream"
// it can find, so on a crafted file it resumes inside a payload and records
// whatever object headers it finds there, while an unmatched "(" hides the
// genuine definition. The retry then resolved the length from a decoy.
//
// The file already carries an authoritative answer, and round one of this review
// said so ("build the index from actual object structure/xref data"). The
// cross-reference table maps object numbers to offsets, and every offset is
// checked to actually carry that object's own "N G obj" header before it is
// believed -- so a decoy sitting somewhere else in the file is not reachable
// through it at all.
//
// This is safe to depend on here because sanitizePDF forces
// -dCompatibilityLevel=1.4, which means a classic cross-reference TABLE rather
// than a 1.5+ cross-reference stream. An input without a usable table simply has
// no forward references resolved, and the stream stays unresolved, which fails
// closed.
func pdfStreamPayloads(b []byte) ([][2]int, error) {
	first := scanPDF(b)
	if first.unresolved == 0 {
		return first.streams, nil
	}

	second := scanPDFSeeded(b, pdfXrefObjects(b))
	if second.unresolved > 0 {
		return nil, fmt.Errorf("%w: %d stream(s) declare a /Length this file does not resolve",
			ErrSanitizeMalformedInput, second.unresolved)
	}
	return second.streams, nil
}

// pdfXrefObjects reads the classic cross-reference table(s) and returns object
// number -> offset just past the object's header, for every entry whose offset
// actually carries that object's header.
//
// It follows /Prev so an incrementally-updated file resolves through its whole
// chain, and it bounds that walk: a table chain that loops or is absurdly long
// is malformed, and this returns what it has rather than following it forever.
func pdfXrefObjects(b []byte) map[int]int { return pdfXrefObjectsLimited(b, 0) }

// pdfXrefObjectsLimited is pdfXrefObjects with a cap on how many entries it
// will index. maxIndexed <= 0 means no cap.
//
// The cap is the INSPECT window's, not the worker's, and imposing it on both
// was a defect of its own (PR #18 review): pdfStreamPayloads verifies whole
// sanitizer OUTPUT inside a cgroup under a measured timeout, and a silently
// partial index there can leave a forward /Length unresolved -- so
// verifySanitized would reject a valid job to save memory the worker has.
// cmd/api's inspect path runs on an 8 MiB attacker-supplied window and passes
// a cap; the worker passes none.
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
			// A cross-reference STREAM (PDF 1.5+), which this does not read.
			// Not an error: the caller treats an unresolved stream as
			// unresolved, which fails closed.
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
					// The INDEX is bounded, not just each subsection. Measured
					// before this existed, on a file whose table declares the
					// per-subsection maximum: a 20 971 614-byte input built a
					// map costing 48 MB of allocation in 201ms. That runs in
					// the API process for every /v1/inspect (internal/inspect
					// reads up to its 8 MiB budget), so the cost of a table
					// nobody has to honour was a client's to choose.
					//
					// Stopping is safe in the direction that matters: a stream
					// whose /Length object is not indexed stays unresolved, and
					// unresolved fails closed.
					return out
				}
				if hdr, ok := pdfObjectHeaderAt(b, entOff, num); ok {
					// FIRST definition wins across the /Prev chain, because the
					// chain is walked newest-first and a newer revision's entry
					// is the one in force.
					if _, already := out[num]; !already {
						out[num] = hdr
					}
				}
			}
		}

		// /Prev in the trailer dictionary, if any.
		prev, ok := pdfTrailerPrev(b, i)
		if !ok {
			return out
		}
		off = prev
	}
	return out
}

const (
	// pdfXrefMaxHops bounds the /Prev chain. Incremental updates are rare in
	// this project's own output (Ghostscript writes one revision) and a chain
	// longer than this is describing itself badly.
	pdfXrefMaxHops = 32
	// pdfXrefMaxEntries bounds a single subsection's declared count so a
	// malformed header cannot make this loop for a long time.
	pdfXrefMaxEntries = 1 << 20
	// pdfXrefMaxIndexed bounds the RESULT, which pdfXrefMaxEntries does not:
	// a table may carry many subsections, and each one within its limit.
	// 65 536 objects is far past any document this service converts (the
	// largest PDF in the corpus has three figures' worth) and costs a map of
	// bounded size instead of one the file's author picks.
	pdfXrefMaxIndexed = 1 << 16
)

// pdfObjectHeaderAt reports the offset just past "num G obj" if that is what
// sits at off. This is what makes an xref offset trustworthy: an entry pointing
// somewhere else, or at a different object, is discarded rather than believed.
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

// pdfTrailerPrev reads /Prev out of the trailer dictionary beginning at or after
// i. Deliberately shallow: it reads one key out of one dictionary and does not
// pretend to understand the trailer.
func pdfTrailerPrev(b []byte, i int) (int, bool) {
	i = pdfSkipTrivia(b, i)
	if !bytes.HasPrefix(b[i:], []byte("<<")) {
		return 0, false
	}

	// Walked with the same primitives as the main scan, for the same reason.
	// This function used to take the first ">>" and then the first "/Prev"
	// substring inside it, and every way that is wrong was reproduced by
	// running it:
	//
	//	<< /Note (/Prev 999) /Prev 12345 >>       followed 999
	//	<< /Sub << /Prev 999 >> /Prev 12345 >>    followed 999
	//	<< /PrevPage 999 /Prev 12345 >>           found nothing
	//	<< /Note (>>) /Prev 12345 >>              found nothing
	//	<< /Prev 5 0 R >>                         read the object number as an offset
	//
	// The first two follow a decoy; the next two abandon a real chain. Neither
	// is a security hole -- pdfXrefObjects verifies that every offset carries
	// its own object header, so a wrong chain yields FEWER objects, not wrong
	// ones -- but "fewer" means forward /Length references go unresolved and
	// verifySanitized fails closed on a VALID file. That is this project's
	// most expensive defect class, not its cheapest.
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
				// The trailer dictionary closed without a /Prev of its own.
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
			next := pdfSkipName(b, i)
			await = depth == 1 && arrayDepth == 0 && pdfNameEquals(b, i, "Prev")
			i = next
			continue
		}

		if await {
			v, next, ok := pdfReadIntAt(b, i)
			if !ok {
				i = next
				await = false
				continue
			}
			// "/Prev 5 0 R" is not a byte offset: the spec requires a direct
			// integer, and reading the object NUMBER as an offset is how 5
			// became a position in the file. pdfLooksLikeRef asks whether the
			// tokens AFTER an integer are "G R", so it is called past the one
			// just read -- calling it at the integer itself tests the wrong
			// pair and silently never fires.
			if pdfLooksLikeRef(b, next) {
				return 0, false
			}
			return v, true
		}
		i++
	}
	return 0, false
}
