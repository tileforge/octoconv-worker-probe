package convert

// This file (pdfdictscan.go): read one integer key out of the dictionaries that
// declare a given /Type, using pdflex.go's tokenizer rather than a byte scan.
//
// WHY IT EXISTS, AND WHY IT LIVES HERE RATHER THAN IN internal/inspect
//
// internal/inspect needed a PDF's declared page count for the sanitize
// admission gate (PROBE-01), and derived it by scanning bytes near a
// "/Type /Pages" marker. Review found four ways to be wrong, in three rounds,
// and every one of them is a member of the SAME class:
//
//	round 1  "/Type /Pages /Count 300" read out of a CONTENT STREAM
//	round 2  /Count taken from a following /Outlines dictionary
//	round 3  "/Count300" matched as the key "/Count" by prefix
//	round 3  "/Extra [ /Count 300 ]" read as a direct key of the dictionary
//
// pdflex.go's own header records that exact class, from a different bound, in
// almost the same words -- including "/Length" matched inside "/Length1" and a
// "/Length inside [ ... ]" read as a key of the enclosing dictionary. Both of
// those are the round-3 findings above, one key name over. The lesson was
// already written down in this repository and the byte scanner in
// internal/inspect repeated it anyway, because it had no model of what a token
// is.
//
// .planning/RETROSPECTIVE.md's rule applies: a bound that keeps getting
// bypassed is replaced, not patched. So this does not add a delimiter check and
// an array counter to a byte scan -- it moves the question to the tokenizer
// that already models PDF's four lexical contexts, and the class goes with it.
//
// It lives in internal/convert because pdflex.go does. internal/inspect already
// imports this package (container.go), so there is no new dependency edge and
// no cycle. Phase 58 D-02a refused a PARSER on untrusted bytes in the API
// process, and that decision was about pdfcpu: a large third-party dependency
// that builds a document model. This is a bounded tokenizer of this project's
// own, which builds nothing, resolves no references beyond one integer and
// decodes nothing -- pdflex.go's own header says so. The operator was shown the
// distinction and chose to cross it deliberately rather than have it crossed
// silently.

// pdfMaxIndexedObjects bounds the object index built to resolve indirect
// values, in entries.
//
// 65536, derived rather than picked: an 8 MiB window -- the size the sanitize
// admission gate reads -- holds at most a few hundred thousand minimal "N 0
// obj/endobj" records, and no real document of that size declares anywhere near
// 65536 objects. So the cap abstains on files that are object-dense beyond any
// legitimate shape while leaving every real one answerable, and holds the map
// to a few MB instead of tens.
const pdfMaxIndexedObjects = 65536

// PDFTypedDictUints walks b once and returns, in file order, the value of key
// for every dictionary that BOTH declares /Type /<typeName> and carries key as
// a DIRECT key of its own.
//
// "Direct" is the whole point: not a key of a nested dictionary, not a name
// inside an array value, and not a longer name that merely starts with key.
//
// ceilingHit reports that the walk could not be trusted to completion -- more
// than maxDicts dictionaries DECLARING THE REQUESTED /Type, nesting past
// maxPDFDictDepth, or a stream whose /Length this window does not resolve,
// after which later bytes may be payload read as structure. Callers must treat
// it as "no answer", never as "the answers so far".
//
// maxDicts counts matching dictionaries, not every dictionary in the file:
// counting all of them turned an ordinary annotated document into a work
// ceiling before its page tree was reached.
//
// A window that cuts a file mid-stream is the ordinary case for
// internal/inspect, so an unresolved length is not an error here; it is the
// reason the caller gets nothing.
// maxPDFDictDepth bounds dictionary NESTING. Real PDFs nest a handful of
// levels; Acrobat's own implementation limit is 28. 64 is generous for anything
// a writer produces and refuses what only a generator produces.
const maxPDFDictDepth = 64

func PDFTypedDictUints(b []byte, typeName, key string, maxDicts int, stop func() bool) (values []int, ceilingHit bool) {
	// INDIRECT LENGTHS ARE THE ORDINARY CASE, NOT AN EDGE ONE.
	//
	// Ghostscript writes "/Length 6 0 R" with object 6 defined AFTER the stream
	// it belongs to -- pdflex.go's own comment records that, and this function's
	// first version gave up on it and reported a ceiling for every real PDF in
	// the corpus. So the object index is built first, from a forward pass and
	// from the xref, exactly as pdfStreamPayloads resolves the same problem.
	// XREF WINS. This started as "fill in what the forward pass missed", and
	// the precedence was backwards.
	//
	// scanPDF resynchronises to the next "endstream" when a stream's /Length
	// cannot be resolved on the first pass -- pdflex.go's own comment explains
	// why it must keep reading rather than stop. While resynchronising it can
	// record an object header that is really PAYLOAD BYTES, and a file can put
	// one there on purpose. Refusing to let the xref replace that offset means
	// a decoy planted in a stream outranks the file's own declared structure,
	// which is the opposite of how a reader resolves references.
	//
	// So the speculative index is built first and the xref overwrites it. Found
	// in review (PR #15 round 4), with a valid two-page PDF that this function
	// reported as 300.
	//
	// AND IT IS BOUNDED, BY A LIMIT OF ITS OWN. scanPDF indexes every distinct
	// object number it sees, which on an 8 MiB body of unique "N 0 obj" records
	// allocated 40 MB -- attacker-controlled memory on a route with no
	// concurrency semaphore and a 1 GiB pod (PR #15 round 5).
	//
	// The cap is NOT maxDicts. The first fix used it, on the reasoning that it
	// is "the ceiling this walk already takes" -- which is true and useless:
	// internal/inspect passes maxTokenScanIterations, which is 1<<20, so a
	// million objects were still admitted and the measured allocation did not
	// move. Written without looking at the number.
	//
	// Dictionaries and indexed objects are two resources and get two bounds,
	// the same split pdfDictScanWindow and its budget needed earlier in this
	// PR. Reaching this one abstains rather than answering from a half-built
	// index: an incomplete index resolves some references and silently misses
	// others, which is a wrong answer rather than a missing one.
	scan := scanPDFLimited(b, nil, pdfMaxIndexedObjects, stop)
	if scan.objectsCapped || scan.stopped {
		return nil, true
	}
	objects := scan.objects
	for num, off := range pdfXrefObjectsLimited(b, pdfMaxIndexedObjects) {
		if _, known := objects[num]; !known && len(objects) >= pdfMaxIndexedObjects {
			return nil, true
		}
		objects[num] = off
	}

	// A DICTIONARY IS KEY/VALUE PAIRS, NOT A BAG OF NAMES.
	//
	// The first version treated every name at dictionary depth as a key, and
	// "<< /Foo /Type /Type /Pages ... >>" defeated it: the first /Type is
	// /Foo's VALUE, but it was read as a key, which then swallowed the real
	// /Type key as its value and lost the dictionary entirely (PR #15 round 5).
	//
	// So each open dictionary tracks whether the next token begins a key or is
	// the value of the key just read. Every complete value -- a name, a number,
	// a string, an array, a nested dictionary, a keyword -- returns the frame
	// to expecting a key.
	type frame struct {
		isType    bool
		val       int
		haveVal   bool
		expectKey bool
		keyOff    int
		// valueArrayDepth remembers the array nesting at which this frame's
		// current VALUE began, so the frame returns to expecting a key when
		// that array closes rather than at the first "]" of any depth.
		valueArrayDepth int
		// valueDictDepth is the same for a nested dictionary value.
		valueDictDepth int
	}
	var stack []frame

	// endValue returns the top frame to expecting a key.
	endValue := func() {
		if n := len(stack); n > 0 {
			stack[n-1].keyOff = -1
			stack[n-1].expectKey = true
		}
	}
	keyIs := func(f frame, s string) bool { return f.keyOff >= 0 && pdfNameEquals(b, f.keyOff, s) }
	// endValueIfDirect is endValue for tokens that are only a value when they
	// are a direct member of the dictionary -- inside an array they are array
	// elements and the dictionary is still waiting for the array to close.
	endValueIfDirect := func(arrayDepth int) {
		if arrayDepth != 0 {
			return
		}
		if n := len(stack); n > 0 && !stack[n-1].expectKey {
			endValue()
		}
	}

	arrayDepth := 0
	matched := 0 // dictionaries declaring the requested /Type

	// awaitVal is set for exactly one token: the integer that follows the key
	// this function was asked about. Everything else about key/value position
	// lives on the frame.
	awaitVal := false

	// dictClosed / length carry the same meaning they do in pdflex.go's scan:
	// a "stream" keyword is only a stream keyword directly after a dictionary,
	// and that dictionary's /Length is what bounds its payload.
	dictClosed := false
	lengthVal, haveLength := 0, false
	awaitLength := false
	pendingLength, pendingRef, pendingHave := 0, false, false

	i := 0
	for iter := 0; i < len(b); iter++ {
		if stop != nil && iter%pdfStopCheckEvery == 0 && stop() {
			return nil, true
		}
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
			// A string is a complete value. Without this the frame stayed in
			// "expecting a value" and the NEXT name -- very often the real
			// /Type, since /Title, /Author and /Subject precede it constantly
			// -- was read as that value instead of as a key. Found by probing
			// this state machine rather than by review: "<< /Title (hello)
			// /Type /Pages /Count 2 >>" abstained, which is an ordinary
			// dictionary and not an edge case.
			endValueIfDirect(arrayDepth)
			continue
		}
		if c == '<' {
			if i+1 < len(b) && b[i+1] == '<' {
				if len(stack) >= maxPDFDictDepth {
					// DEPTH, which no other bound covers. maxDicts counts
					// MATCHING dictionaries and nothing bounded how deep any
					// of them NEST, so the frame stack grew with the nesting.
					// Measured before this existed: 2 097 169 bytes of "<<"
					// cost 131.4 MB of allocation, and internal/inspect runs
					// this over up to 8 MiB in the API process.
					//
					// Recorded as a still-open finding when this file was
					// deleted with the gate it was built for; restoring it
					// without the bound would have restored the finding.
					return nil, true
				}
				if n := len(stack); n > 0 && !stack[n-1].expectKey {
					// This dictionary IS the value of the key just read.
					stack[n-1].valueDictDepth = len(stack)
				}
				stack = append(stack, frame{expectKey: true, keyOff: -1})
				i += 2
				dictClosed, awaitVal = false, false
				continue
			}
			i = pdfSkipHexString(b, i)
			dictClosed, awaitVal = false, false
			endValueIfDirect(arrayDepth) // a hex string is a value too
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
			start := i
			i = pdfSkipName(b, i)
			dictClosed = false
			n := len(stack)
			if n == 0 || arrayDepth != 0 {
				// Not a direct token of any dictionary: a name inside an array
				// value is data, whatever it spells.
				continue
			}
			if stack[n-1].expectKey {
				stack[n-1].keyOff = start
				stack[n-1].expectKey = false
				awaitLength = n == 1 && pdfNameEquals(b, start, "Length")
				continue
			}
			// This name is the VALUE of the key just read.
			if keyIs(stack[n-1], "Type") && pdfNameEquals(b, start, typeName) {
				stack[n-1].isType = true
				// MATCHING dictionaries are what maxDicts bounds, not every
				// dictionary in the file. Counting all of them regressed the
				// public page_count characteristic from an integer to null on
				// ordinary documents: 9 000 annotation dictionaries ahead of
				// the page tree -- a form, or any richly annotated PDF --
				// exhausted the cap before /Type /Pages was ever reached, and
				// reported a work ceiling for a file with nothing wrong with
				// it (PR #18 review). Refusing valid work to bound work is the
				// trade this project has paid for most.
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
				isValue = keyIs(stack[n-1], key)
			}
			awaitVal = isValue
			if awaitVal {
				// AN INDIRECT VALUE IS A REFERENCE, NOT THE VALUE.
				//
				// "/Count 5 0 R" is legal and means "the count is in object 5".
				// Taking the first integer would report the OBJECT NUMBER as
				// the page count -- a confidently wrong answer, in either
				// direction, on a valid document. Found by probing this
				// function rather than by review: pdfLooksLikeRef was already
				// applied to /Length here and simply had not been applied to
				// the key's own value.
				//
				// Resolved from the same object index the lengths use, and
				// abstained on when the target is outside this window. The
				// tokenizer resolves exactly one integer through one
				// reference; that is the limit pdflex.go states for itself and
				// this does not widen it.
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
			// "N G R" is one value spanning three tokens; pdfLooksLikeRef has
			// already told us so, and the G and R are skipped by the generic
			// token path below without ending the value early, because the
			// value ends only here.
			if n := len(stack); n > 0 && arrayDepth == 0 && !stack[n-1].expectKey {
				if pdfLooksLikeRef(b, next) {
					i = pdfSkipRefTail(b, next)
				}
				endValue()
			}
			continue
		}

		word, next := pdfKeywordAt(b, i)
		if pdfKeywordIs(word, "stream") && dictClosed {
			payload := next
			if payload < len(b) && b[payload] == '\r' {
				payload++
			}
			if payload < len(b) && b[payload] == '\n' {
				payload++
			}
			if !haveLength || lengthVal < 0 || payload+lengthVal > len(b) ||
				!pdfEndstreamFollows(b, payload+lengthVal) {
				// The payload's end is unknown, so everything after it might be
				// payload read as structure -- which is round 1's finding. Give
				// up rather than resynchronise on a guess: this function only
				// ever answers, it never has to keep reading.
				return nil, true
			}
			i = payload + lengthVal
			dictClosed, haveLength = false, false
			continue
		}
		i = next
		dictClosed, awaitVal = false, false
		if len(word) != 0 && arrayDepth == 0 {
			if n := len(stack); n > 0 && !stack[n-1].expectKey {
				endValue()
			}
		}
	}

	return values, false
}

// pdfSkipRefTail returns the offset just past the "G R" of an indirect
// reference whose object number ended at from. pdfLooksLikeRef has already
// established that the two tokens are there.
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
