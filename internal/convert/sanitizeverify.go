package convert

// This file (sanitizeverify.go): independent verification of sanitizer output
// (SANI-04).
//
// WHY THE VERIFIER MUST NOT SHARE CODE WITH THE SANITIZER
//
// The research measured the failure mode directly. A single `pdfwrite` pass
// regenerates /Info -- and the values it was invoked to remove reappear in an
// XMP packet the pass itself creates. A verifier that read /Info and reported
// "metadata removed" would be right about /Info and wrong about the file. It
// would not be proving cleanliness; it would be proving its own blindness.
//
// So the implementation that checks is never the implementation that removed:
//
//	PDF   -- ghostscript removes, pdfcpu checks (D-03)
//	OOXML -- Go archive/zip removes, unzip + libmagic check (D-04)
//
// THREE OUTCOMES, ALL DISTINGUISHABLE (D-07)
//
//	clean          -> nil; output may proceed to storage
//	residue found  -> ErrSanitizeResidue, naming the class found
//	cannot parse   -> ErrSanitizeUnverifiable, its own separate cause
//
// The third is the one worth defending. Handing back a file marked
// "unverified" loses to a specific failure: a file that went through an
// operation named *sanitize* will be treated as clean by everyone who did not
// read the report, and that is most people. It is the same principle phase 59
// held for `absent`: "could not look" is never "nothing there".
//
// WHY pdfcpu IS ALLOWED HERE AT ALL
//
// It is the project's first parsing dependency pointed at untrusted bytes, and
// phase 58 (D-02a) refused it in the API process for exactly that reason. It
// was agreed on three conditions, all of which hold here and only here: it
// runs in an isolated worker, under a measured timeout, with cgroup limits.
// A future attempt to call pdfcpu from cmd/api should read that decision
// before assuming this file is a precedent -- it is not; it is the exception
// the conditions were written for.
//
// WHAT pdfcpu BUYS THAT PHASE 58'S BYTE SCANNER COULD NOT
//
// It decompresses /ObjStm. An object hidden inside an object stream is
// structurally invisible to a byte scanner (internal/inspect/pdf.go documents
// that limit); it is ordinary to a parser.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	pdftypes "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// pdfcpu writes a config.yml on first use, and PANICS if it cannot.
//
// model.NewDefaultConfiguration calls os.UserConfigDir, which returns
// $HOME/.config WITHOUT an error whenever HOME is merely set -- and this worker
// runs as nobody, whose HOME on debian is /nonexistent. So the fallback to
// TempDir never fires, EnsureDefaultConfigAt fails, and pdfcpu calls
// fault.Fail: a panic, inside api.ReadContextFile, on the verification path of
// EVERY sanitize job.
//
// asynq recovers it, which is what made this invisible: the job is retried
// until the budget is gone and then left ACTIVE, so a client sees a job that
// never finishes rather than a failure. Found by running the e2e tier
// (PR #16), where one test times out waiting for a terminal state.
//
// "disable" is pdfcpu's own switch for exactly this: no config file is read or
// written and the built-in defaults are used. A sandboxed worker with no
// writable home should not be persisting a config anywhere.
func init() { model.ConfigPath = "disable" }

// The two failure modes are separate sentinels because they mean different
// things to an operator: residue means the sanitizer is wrong, unverifiable
// means the verifier could not do its job. Collapsing them into one error
// would make the second look like the first and send the wrong person
// looking.
var (
	// ErrSanitizeResidue means the verifier found, in the OUTPUT bytes, a
	// construct the sanitizer claimed to remove.
	ErrSanitizeResidue = errors.New("sanitize verification: residue found in output")
	// ErrSanitizeUnverifiable means the verifier could not parse or inspect
	// the output at all. Fail closed: this is a job failure, not a caveat.
	ErrSanitizeUnverifiable = errors.New("sanitize verification: output could not be verified")
	// ErrSanitizeMalformedInput means the INPUT could not be processed: the
	// engine refused to parse it, the archive would not open, or a part this
	// path must rewrite is not well-formed XML.
	//
	// It exists so the worker can classify these as TERMINAL. They are
	// deterministic on the input -- a file ghostscript cannot read now is a
	// file ghostscript cannot read in twenty seconds -- and without a sentinel
	// they fell through to the shared isTerminal, which knows nothing about
	// sanitizer or ghostscript errors and returned false. Asynq then exhausted
	// its retries WITHOUT MarkFailed ever running, leaving the job active
	// until the reconciler exhausted it over repeated 15-minute cycles.
	//
	// ProbeDescriptor's own doc comment had claimed this classification since
	// the class was added; the code never implemented it. Caught in review
	// (PR #12, round 4) -- a comment describing behaviour that does not exist
	// is precisely the defect this phase's tests were built against, and it
	// was in this phase's own comment.
	ErrSanitizeMalformedInput = errors.New("sanitize: input could not be processed")
)

// verifiers is the closed set of formats that have an independent verifier.
// A format that sanitizes but has no verifier must not silently skip
// verification -- sanitizeFile turns a missing entry into an error, because
// "nothing checked it" and "it checked out" must never share an outcome.
//
// The signature carries the FORMAT as well as the path because one verifier
// (OOXML) cannot state its own proposition without it: "the main part is still
// there" needs to know which part that is, and inferring it from whichever main
// part happens to be present is the same "the check only runs when the thing is
// there" defect SANI-09 exists to close.
//
// x is the SanitizeConverter's own engineExec, threaded through so verifyOOXML
// and verifyImage run unzip/file(1) under the SAME ruleset the sanitizer used
// to produce the file they are checking. verifyPDF carries x unused -- pdfcpu
// parses in-process and execs nothing.
var verifiers = map[string]func(ctx context.Context, x engineExec, format, path string) ([]ThreatClass, error){}

// verifySanitized inspects the sanitized OUTPUT at path and reports which
// threat classes an independent implementation confirmed absent.
//
// It never reports a class it did not actually look for: the returned slice is
// what feeds SanitizeResult.Verified, and that field exists precisely so that
// "removed" and "confirmed absent" stay separate claims.
//
// It is package-private for the same reason as sanitizeFile: its x parameter
// is the package-private engineExec.
func verifySanitized(ctx context.Context, x engineExec, format, path string) ([]ThreatClass, error) {
	fn, ok := verifiers[NormalizeFormat(format)]
	if !ok {
		return nil, fmt.Errorf("%w: no verifier registered for format %q",
			ErrSanitizeUnverifiable, format)
	}
	return fn(ctx, x, NormalizeFormat(format), path)
}

// unverifiableEngineFailure classifies an engine failure encountered WHILE
// VERIFYING a sanitized output. When err carries ErrEngineSandboxUnavailable
// it is a NODE fault -- this node could not confine unzip/file(1), which says
// nothing about the file -- and the sentinel is preserved unwrapped so
// isProbeTerminal sees it before any terminal classification runs. Otherwise
// this returns exactly the ErrSanitizeUnverifiable wrap every call site used
// before x existed, byte-identical: "%w: "+format+": %v" with err last.
func unverifiableEngineFailure(err error, format string, args ...any) error {
	if errors.Is(err, ErrEngineSandboxUnavailable) {
		wrapArgs := append(append([]any{}, args...), err)
		return fmt.Errorf("sanitize verify: "+format+": %w", wrapArgs...)
	}
	wrapArgs := append([]any{ErrSanitizeUnverifiable}, args...)
	wrapArgs = append(wrapArgs, err)
	return fmt.Errorf("%w: "+format+": %v", wrapArgs...)
}

// ---------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------

func init() { verifiers["pdf"] = verifyPDF }

// pdfActionResidue maps a dictionary key or /S action name to the threat class
// its presence in the output would disprove. Keys are checked as they appear
// in a parsed dictionary, so an object reachable only through /ObjStm is
// covered the same as one at top level.
var pdfActionResidue = map[string]ThreatClass{
	"JavaScript":    ThreatJavaScript,
	"JS":            ThreatJavaScript,
	"OpenAction":    ThreatActionDict,
	"AA":            ThreatActionDict,
	"Launch":        ThreatLaunchAction,
	"EmbeddedFiles": ThreatEmbeddedFile,
	"EmbeddedFile":  ThreatEmbeddedFile,
	"URI":           ThreatExternalReference,
	"GoToR":         ThreatExternalReference,
	"SubmitForm":    ThreatExternalReference,
	"ImportData":    ThreatExternalReference,
}

// pdfByteResidue is the second view: markers greppable in the raw output,
// OUTSIDE its compressed streams.
//
// This is not redundancy with the parse. A parser can miss what a grep finds
// (an object the parser drops as unreachable is still bytes on disk) and a
// grep can miss what a parser finds (a name split across an /ObjStm boundary).
// Two kinds of blindness, not two copies of one check.
//
// SCOPED TO THE NON-STREAM BYTES, and that scoping is a correction. Scanning
// the whole file treated Flate-compressed content-stream bytes as structure:
// a page's compressed data can contain "/AA" or "/URI" by chance, and on a
// document with enough content eventually does. Because verification failure
// DELETES the output (D-07), a false positive here did not mislabel a job --
// it destroyed a correct result and failed it. Caught in review (PR #12),
// the same class as the image verifier's whole-file scan.
//
// Object DICTIONARIES are never compressed in this build's output: the
// sanitizer targets PDF 1.4, which has no object streams, so every dictionary
// -- the only place these names can carry meaning -- lies in the plain bytes
// this still scans. Skipping stream payloads costs no reach.
var pdfByteResidue = map[string]ThreatClass{
	"/JavaScript":    ThreatJavaScript,
	"/OpenAction":    ThreatActionDict,
	"/AA":            ThreatActionDict,
	"/Launch":        ThreatLaunchAction,
	"/EmbeddedFile":  ThreatEmbeddedFile,
	"/EmbeddedFiles": ThreatEmbeddedFile,
	"/URI":           ThreatExternalReference,
	// D-09 removes the XMP packet whole, so the metadata check is binary:
	// the packet is not there. Checking field-by-field would fail on an
	// honest file that legitimately has none of those fields, and checking
	// for a known secret value ("jane.doe") does not scale past the fixture.
	// "No packet" is the only form of this check that is both correct and
	// general -- which is a second reason D-09 chose whole removal, beyond
	// not leaking the producer version.
	"xpacket": ThreatDocumentMetadata,
	// The engine's own signature is metadata too, and D-09 named "does not
	// leak the producer version" as a reason for removing XMP whole. Leaving
	// Ghostscript's name in /Info while stripping it from XMP would be
	// incoherent, so both are checked.
	"Ghostscript":   ThreatDocumentMetadata,
	"%%Invocation:": ThreatDocumentMetadata,
	// PDF 1.4 output has no object streams by construction. If one appears,
	// something changed the compatibility level, and every byte-level check
	// in this project silently lost half its reach.
	"/ObjStm": ThreatDocumentMetadata,
}

func verifyPDF(ctx context.Context, _ engineExec, _, path string) ([]ThreatClass, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read output: %v", ErrSanitizeUnverifiable, err)
	}

	// --- view 0: the one neither of the other two can see ---
	//
	// SC3: a construct removed from the current revision is still recoverable
	// if the file keeps a previous one. pdfcpu reads by the last xref, exactly
	// as a reader does, so a superseded object never enters the parse at all;
	// the byte grep WOULD find it but could not tell "still in the current
	// revision" from "sitting in a superseded one", and only one of those is a
	// bug in the sanitizer.
	//
	// It runs FIRST, before the parse, and that ordering is not cosmetic. It
	// is a pure byte count that needs no parser, and putting it behind a
	// successful parse made a two-revision file report "could not be
	// verified" -- true, but useless, and it hid the actual defect behind a
	// parser complaint about the older revision's page tree.
	if err := verifySingleRevision(raw); err != nil {
		return nil, err
	}

	// --- view 1: an independent parser ---
	pctx, err := api.ReadContextFile(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("%w: pdfcpu could not read the output: %v",
			ErrSanitizeUnverifiable, err)
	}
	if found := scanPDFObjects(pctx.XRefTable.Table); len(found) > 0 {
		return nil, fmt.Errorf("%w: pdfcpu found %s in the parsed output",
			ErrSanitizeResidue, joinClasses(found))
	}
	// /Info is checked by VALUE, not by key. Ghostscript always writes
	// /Producer and /Creator and cannot be told not to (sanitizepdf.go's
	// redactEngineIdentity records the three attempts that were measured), so
	// the keys survive by construction and the redaction empties them. A key
	// with a non-empty value is residue no matter which key it is -- that
	// covers the client's /Title and /Author and the engine's own signature
	// under one rule, rather than an allow-list that would have to be revised
	// every time an engine invents a field.
	if pctx.XRefTable.Info != nil {
		if d, err := pctx.XRefTable.DereferenceDict(*pctx.XRefTable.Info); err == nil {
			for k, v := range d {
				if s, ok := v.(pdftypes.StringLiteral); ok && strings.TrimSpace(s.Value()) != "" {
					return nil, fmt.Errorf("%w: /Info carries a non-empty %s value",
						ErrSanitizeResidue, k)
				}
				if s, ok := v.(pdftypes.HexLiteral); ok && strings.TrimSpace(s.Value()) != "" {
					return nil, fmt.Errorf("%w: /Info carries a non-empty %s value",
						ErrSanitizeResidue, k)
				}
			}
		}
	}

	// --- view 2: the raw bytes ---
	found, err := scanPDFBytes(raw)
	if err != nil {
		return nil, err
	}
	if len(found) > 0 {
		return nil, fmt.Errorf("%w: %s greppable in the output bytes",
			ErrSanitizeResidue, joinClasses(found))
	}

	return append([]ThreatClass(nil), pdfThreatClasses...), nil
}

// verifySingleRevision requires exactly one startxref and one %%EOF.
func verifySingleRevision(raw []byte) error {
	// Counted OUTSIDE stream payloads, for the reason scanPDFBytes already
	// counted its markers there: compressed and image data can contain
	// "%%EOF" or "startxref" by chance, and a false multi-revision verdict
	// DELETES a valid output. The scoping existed one function away and was
	// not applied here -- the same rule in one of two places that need it,
	// which is the fourth time this review has named that shape. Caught in
	// review (PR #12, round 7).
	outside, err := pdfNonStreamBytes(raw)
	if err != nil {
		return err
	}
	starts := bytes.Count(outside, []byte("startxref"))
	eofs := bytes.Count(outside, []byte("%%EOF"))

	// Zero of either is not "too many revisions" -- it is "this does not have
	// the structure of a PDF", which is the unverifiable outcome, not the
	// residue one. Collapsing the two would report a file of garbage as a
	// sanitizer defect and send the wrong person looking. Found by the
	// outcome-separation test after this check moved ahead of the parse.
	if starts == 0 || eofs == 0 {
		return fmt.Errorf("%w: output has %d startxref and %d %%%%EOF markers; "+
			"it does not have the trailer structure of a PDF",
			ErrSanitizeUnverifiable, starts, eofs)
	}
	if starts > 1 || eofs > 1 {
		return fmt.Errorf("%w: output has %d startxref and %d %%%%EOF markers; "+
			"more than one revision means removed objects stay recoverable in a prior one",
			ErrSanitizeResidue, starts, eofs)
	}
	return nil
}

// scanPDFObjects walks every object the parser resolved -- including those
// unpacked out of /ObjStm -- and reports the classes it finds.
//
// Both a key check and a VALUE check run here, and the value check is the one
// that matters: /S is an ordinary key on every action dictionary, so its
// presence proves nothing, while /S with the name Launch is a launch action
// and nothing else.
func scanPDFObjects(table map[int]*model.XRefTableEntry) []ThreatClass {
	seen := map[ThreatClass]bool{}
	var found []ThreatClass
	add := func(c ThreatClass) {
		if !seen[c] {
			seen[c] = true
			found = append(found, c)
		}
	}

	var walk func(pdftypes.Object, int)
	walk = func(obj pdftypes.Object, depth int) {
		if depth > 64 { // a malformed file can nest without an indirect ref
			return
		}
		switch o := obj.(type) {
		case pdftypes.Dict:
			for k, v := range o {
				if c, ok := pdfActionResidue[k]; ok {
					add(c)
				}
				if k == "S" || k == "Type" {
					if n, ok := v.(pdftypes.Name); ok {
						if c, ok := pdfActionResidue[n.Value()]; ok {
							add(c)
						}
					}
				}
				walk(v, depth+1)
			}
		case pdftypes.StreamDict:
			walk(o.Dict, depth+1)
		case pdftypes.Array:
			for _, v := range o {
				walk(v, depth+1)
			}
		}
	}

	for _, e := range table {
		if e == nil || e.Free || e.Object == nil {
			continue
		}
		walk(e.Object, 0)
	}
	return sortClasses(found)
}

// sortClasses orders findings by the canonical vocabulary order, so the same
// set of findings always renders as the same string. An error message that
// reorders itself between runs is one nobody can grep for.
func sortClasses(cs []ThreatClass) []ThreatClass {
	if len(cs) < 2 {
		return cs
	}
	in := map[ThreatClass]bool{}
	for _, c := range cs {
		in[c] = true
	}
	var out []ThreatClass
	for _, c := range allThreatClasses {
		if in[c] {
			out = append(out, c)
		}
	}
	return out
}

func scanPDFBytes(raw []byte) ([]ThreatClass, error) {
	outside, err := pdfNonStreamBytes(raw)
	if err != nil {
		return nil, err
	}
	seen := map[ThreatClass]bool{}
	var found []ThreatClass
	add := func(class ThreatClass) {
		if !seen[class] {
			seen[class] = true
			found = append(found, class)
		}
	}
	// A PDF name runs from '/' to the next delimiter. "/AA" is a prefix of
	// the subset-font name "/AABCDE+Test", so a substring search reports an
	// additional-actions dictionary that is not there.
	for i := 0; i < len(outside); i++ {
		if outside[i] != '/' {
			continue
		}
		name, ok := pdfNameAt(outside, i)
		if !ok {
			continue
		}
		if class, ok := pdfByteResidue["/"+name]; ok {
			add(class)
		}
	}
	for marker, class := range pdfByteResidue {
		if strings.HasPrefix(marker, "/") {
			continue
		}
		if bytes.Contains(outside, []byte(marker)) {
			add(class)
		}
	}
	return sortClasses(found), nil
}

// pdfNameAt returns the PDF name that starts at b[i], which must be '/'.
// A '#' and two hex digits are one character of the name. The name ends at a
// delimiter, so "/AA" does not match the leading bytes of "/AABCDE+Test".
func pdfNameAt(b []byte, i int) (string, bool) {
	if i >= len(b) || b[i] != '/' {
		return "", false
	}
	var name []byte
	for j := i + 1; j < len(b); {
		c := b[j]
		if pdfNameDelim(c) {
			break
		}
		if c == '#' && j+2 < len(b) && pdfHex(b[j+1]) && pdfHex(b[j+2]) {
			name = append(name, pdfHexValue(b[j+1])<<4|pdfHexValue(b[j+2]))
			j += 3
			continue
		}
		name = append(name, c)
		j++
	}
	if len(name) == 0 {
		return "", false
	}
	return string(name), true
}

func pdfNameDelim(c byte) bool {
	switch c {
	case 0, '\t', '\n', '\f', '\r', ' ',
		'(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	default:
		return false
	}
}

func pdfHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f'
}

func pdfHexValue(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

// pdfNonStreamBytes returns the file with every stream payload blanked out,
// so a scan sees dictionaries, names and trailers but not compressed content.
//
// Blanking rather than deleting keeps every offset where it was, which makes a
// reported offset in a failure message still mean something.
//
// The stream boundaries come from pdflex.go's tokenizer, the same one the
// sanitizer uses. That file's header records why: this verifier and the
// sanitizer must AGREE about where a stream's bytes are -- it is a prerequisite
// for both propositions, not a check of either -- and three review rounds
// showed that two hand-written walkers produced identical bugs every time while
// costing a second place to fix and a second chance to disagree about trivia.
//
// What stays independent is what this file looks FOR: the sanitizer decides
// what to remove, this decides whether it is gone.
//
// An unresolvable /Length is an error, not a guess. This function used to fail
// closed by blanking the rest of the file, which is a defensible answer for a
// grep and a strictly worse one than saying so, in a verifier whose job is to
// refuse what it cannot confirm.
func pdfNonStreamBytes(raw []byte) ([]byte, error) {
	ranges, err := pdfStreamPayloads(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSanitizeUnverifiable, err)
	}
	out := append([]byte(nil), raw...)
	for _, r := range ranges {
		for x := r[0]; x < r[1]; x++ {
			out[x] = ' '
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// OOXML
// ---------------------------------------------------------------------------

func init() {
	for _, f := range []string{"docm", "docx", "xlsm", "xlsx", "pptm", "pptx", "dotm", "potm", "ppsm"} {
		verifiers[f] = verifyOOXML
	}
}

// ooxmlMainPart is the closed map from a sanitize-supported OOXML format to the
// part without which the package is not that format.
//
// The same three names docsniff.go's ooxmlRootParts uses to IDENTIFY a package,
// restated here for the opposite question -- "this format requires this part"
// rather than "this part means this format" -- and extended to the
// macro-enabled and template extensions the sanitize path also accepts. An
// unlisted format returns "", which the caller turns into unverifiable rather
// than into a pass: a verifier that does not know what to require must not
// report success.
func ooxmlMainPart(format string) string {
	switch NormalizeFormat(format) {
	case "docx", "docm", "dotm":
		return "word/document.xml"
	case "xlsx", "xlsm":
		return "xl/workbook.xml"
	case "pptx", "pptm", "potm", "ppsm":
		return "ppt/presentation.xml"
	default:
		return ""
	}
}

// opcContentTypesNS is the namespace a package's content-type declarations live
// in (ECMA-376 Part 2 §10.1.2). An Override or Default outside it is some other
// vocabulary's element that happens to share a local name.
const opcContentTypesNS = "http://schemas.openxmlformats.org/package/2006/content-types"

// xmlWholeDocumentRoot returns the root element name of a document that parses
// COMPLETELY, and reports false for one that does not.
//
// The distinction from xmlRootElement is the whole point: that one answers "what
// does this start as", which is the right question for classifying a part, and
// the wrong one for "is this a usable document".
func xmlWholeDocumentRoot(blob []byte) (xml.Name, bool) {
	dec := xml.NewDecoder(bytes.NewReader(blob))
	var root xml.Name
	seen := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return root, seen
		}
		if err != nil {
			return xml.Name{}, false
		}
		if el, ok := tok.(xml.StartElement); ok && !seen {
			root, seen = el.Name, true
		}
	}
}

// ooxmlMainRoot is the root element the main part must carry, per format. The
// closed companion to ooxmlMainPart: knowing which part to require says nothing
// about whether what is in it is a document.
func ooxmlMainRoot(format string) string {
	switch NormalizeFormat(format) {
	case "docx", "docm", "dotm":
		return "document"
	case "xlsx", "xlsm":
		return "workbook"
	case "pptx", "pptm", "potm", "ppsm":
		return "presentation"
	default:
		return ""
	}
}

// contentTypeDeclares reports whether [Content_Types].xml gives the part a
// content type, by an Override naming it or a Default covering its extension.
//
// Both are legal (ECMA-376 Part 2 §10.1.2); real packages use an Override for
// the main part because its content type is format-specific, but a Default is
// not wrong and refusing it would fail a valid package.
func contentTypeDeclares(contentTypes []byte, part string) bool {
	if len(contentTypes) == 0 {
		return false
	}

	// The WHOLE document must parse, not just enough of it to find a match.
	// Returning true on the matching element let a truncated file through --
	// "<Types ...><Override .../>"" with no closing tag was accepted, because
	// the decoder had not yet reached the error. verifyOOXML's own root check
	// looks at the first start element only, so nothing else caught it either.
	// Found by review on PR #14, round 3.
	// DEPTH AND NAMESPACE, not element name alone. A cleanly parsing document
	// can nest an Override inside something else --
	// <Types><Wrapper><Override .../></Wrapper></Types> -- and that nested
	// element is not a package content-type declaration. Only a DIRECT child of
	// Types, in the OPC content-types namespace, declares anything. Found by
	// review on PR #14, round 4.
	dec := xml.NewDecoder(bytes.NewReader(contentTypes))
	depth := 0
	rootIsTypes := false
	found := false
	ext := ""
	if i := strings.LastIndexByte(part, '.'); i >= 0 {
		ext = strings.ToLower(part[i+1:])
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return found
		}
		if err != nil {
			return false
		}
		if _, ok := tok.(xml.EndElement); ok {
			depth--
			continue
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		here := depth
		depth++
		if here == 0 {
			// THE ROOT'S OWN NAMESPACE, not just its local name. A document can
			// put a foreign <x:Types> at the root while declaring the OPC
			// namespace as the default for its children, so the children look
			// right and their parent is not the OPC Types element at all.
			// Found by review on PR #14, round 5, after the depth check was
			// added -- a check on the child said nothing about the parent.
			rootIsTypes = el.Name.Space == opcContentTypesNS && el.Name.Local == "Types"
			continue
		}
		// depth 0 is <Types> itself; its declarations are at depth 1.
		if !rootIsTypes || here != 1 || el.Name.Space != opcContentTypesNS {
			continue
		}

		var partName, extension, contentType string
		for _, a := range el.Attr {
			switch a.Name.Local {
			case "PartName":
				partName = a.Value
			case "Extension":
				extension = a.Value
			case "ContentType":
				contentType = a.Value
			}
		}
		// An EMPTY ContentType is not a declaration. rewriteContentTypes
		// preserves whatever the input had, so `ContentType=""` -- or the
		// attribute missing entirely -- survived into the output, and a
		// substring match on PartName read it as declared. The package then
		// passed verification and was delivered with a main part nothing
		// describes, which Office will not open: exactly the invalid output
		// this check exists to reject. Found by review on PR #14.
		if strings.TrimSpace(contentType) == "" {
			continue
		}

		switch el.Name.Local {
		case "Override":
			if partName == "/"+part {
				found = true
			}
		case "Default":
			// ASCII-case-insensitive, because OPC extension matching is
			// (ECMA-376 Part 2 §9.1.2.3) and rewriteContentTypes preserves
			// the input's capitalization. A lowercase-only search rejected a
			// valid package that wrote Extension="XML" -- and a rejection here
			// DELETES the output, so being too strict costs a client a file
			// exactly as surely as being too loose lets one through.
			if ext != "" && strings.EqualFold(extension, ext) {
				found = true
			}
		}
	}
}

// TOOL CHOICE FOR OOXML, AND THE MEASUREMENT THAT DECIDED IT
//
// The research recommended oletools/olevba and said plainly that it had not
// run it. Running it is what changed the answer.
//
// olevba 0.60.2 on the corpus fixture -- a package that contains
// word/vbaProject.bin whose first eight bytes are the OLE CFB signature --
// reports `"macros": []` and exits 0. So does `oleid`, printing
// "VBA Macros: No". The reason is in olevba.py: it scans every zip member by
// magic (so it is not fooled by a rename), but then requires a well-formed VBA
// project -- a storage named VBA, plus PROJECT, VBA/_VBA_PROJECT and VBA/dir
// streams -- before it reports anything at all. Anything short of that is
// "no macros".
//
// That makes olevba a fine macro ANALYSER and the wrong VERIFIER. Its "clean"
// verdict means "I found no VBA project I could parse", and a residual OLE
// container that it cannot parse is precisely what a verifier must not wave
// through. Reporting clean because parsing failed is the D-07 failure mode
// wearing a tool's clothes.
//
// So: unzip (Info-ZIP, C) enumerates and extracts the parts, and file/libmagic
// (a third codebase, also C) classifies each extracted part by content. The
// OLE container is identified as application/CDFV2 by its bytes, under
// whatever name it carries. Measured on the same fixture:
//
//	word/vbaProject.bin  ->  application/CDFV2
//	word/document.xml    ->  text/xml
//
// A rename does not move that line, because no part of this path reads names.

// oleMIMETypes is what libmagic calls an OLE/CFB compound document. Compared
// case-insensitively: libmagic's spelling has changed across releases.
var oleMIMETypes = []string{
	"application/cdfv2",
	"application/vnd.ms-office",
	"application/x-ole-storage",
	"application/msword",
}

// WHY THIS VERIFIER PARSES RELATIONSHIPS AT ALL
//
// It did not, and that was the sharpest gap review found. The sanitizer drops
// parts named by an embedded-content, properties or external relationship;
// this verifier checked part MIME types, the OLE signature and the
// macroEnabled content type, and then returned embedded_file,
// external_reference AND document_metadata as CONFIRMED ABSENT. An archive
// still carrying metadata/core.xml plus a core-properties relationship passed
// -- the verifier could not catch the one thing on the sanitizer side it
// exists to catch. Caught in review (PR #12, round 5), after round 4 had
// expanded the removal and left the check where it was: the third time in this
// review the remover moved and the checker did not.
//
// The tables and the parse below are written separately from
// sanitizeooxml.go's, deliberately. They share encoding/xml, as pdfcpu and
// ghostscript share Go, and that is unavoidable; what they do not share is the
// struct, the type table or the traversal, so a mistake in the sanitizer's
// relationship handling cannot travel into its own verification.

// macroContentTypeMarkers are the substrings that identify a macro-carrying
// declaration in [Content_Types].xml.
//
// "macroEnabled" alone was not enough, and I found this one rather than review
// did -- by sweeping for the shape review had already named four times: a rule
// the remover applies more broadly than the checker. All seven main content
// types in macroEnabledContentTypes contain "macroEnabled", so those were
// covered; the vbaProject type does NOT, and the sanitizer removes its
// Default declaration when no .bin part survives. A package keeping that
// declaration would have passed verification while the sanitizer had failed
// to finish its own job.
//
// TestVerifierCatchesEveryMacroContentType holds this to the sanitizer's
// table, so a type added there and not here fails loudly.
var macroContentTypeMarkers = []string{
	"macroEnabled",
	"vbaProject",
}

// ooxmlPropertyRoots are the root elements of the OOXML properties parts,
// matched on CONTENT so a properties part under any name is recognised --
// and matched on NAMESPACE as well as local name.
//
// The local name alone was too broad. An OPC package may carry
// application-defined XML parts, and <Properties xmlns="urn:example"> is an
// ordinary one; the sanitizer keeps it, having neither a properties
// relationship nor a docProps/ path to go on, and then this check called it
// residue and DELETED THE OUTPUT. A false positive here does not mislabel a
// job, it destroys a correct result -- the same consequence the whole-file
// byte scans had, arrived at from the opposite direction: too narrow a view
// misses residue, too broad a predicate invents it. Caught in review
// (PR #12, round 6).
var ooxmlPropertyRoots = map[xml.Name]bool{
	{Space: "http://schemas.openxmlformats.org/package/2006/metadata/core-properties", Local: "coreProperties"}: true,
	{Space: "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties", Local: "Properties"}:   true,
	{Space: "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties", Local: "Properties"}:     true,
	// Dublin Core is what core.xml's own elements live in; some producers
	// write the root in it.
	{Space: "http://purl.org/dc/elements/1.1/", Local: "coreProperties"}: true,
}

// verifyResidualRelTypes are relationship type leaves that must not appear in
// a sanitized package. Kept as its own table rather than imported: two lists
// that must agree and are checked against each other by a test are worth more
// than one list checked against nothing.
var verifyResidualRelTypes = map[string]ThreatClass{
	"package":             ThreatEmbeddedFile,
	"oleObject":           ThreatEmbeddedFile,
	"aFChunk":             ThreatEmbeddedFile,
	"attachment":          ThreatEmbeddedFile,
	"core-properties":     ThreatDocumentMetadata,
	"extended-properties": ThreatDocumentMetadata,
	"custom-properties":   ThreatDocumentMetadata,
	"thumbnail":           ThreatDocumentMetadata,
}

// xmlRootElement returns the namespace-qualified name of an XML document's
// first element.
func xmlRootElement(raw []byte) (xml.Name, bool) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.Name{}, false
		}
		if start, ok := tok.(xml.StartElement); ok {
			return start.Name, true
		}
	}
}

// residualRelationship reports the first relationship in a .rels part that a
// sanitized package must not contain.
func residualRelationship(raw []byte) (string, bool) {
	var doc struct {
		Rel []struct {
			Type       string `xml:"Type,attr"`
			Target     string `xml:"Target,attr"`
			TargetMode string `xml:"TargetMode,attr"`
		} `xml:"Relationship"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		// Unreadable wiring is not a clean package. The caller turns this
		// into residue rather than into "could not verify", because the
		// sanitizer WROTE this file: if it is not parseable, the sanitizer
		// produced something malformed.
		return "an unparseable relationship file", true
	}
	for _, r := range doc.Rel {
		if strings.EqualFold(r.TargetMode, "External") {
			return fmt.Sprintf("an external relationship to %q (%s)", r.Target, ThreatExternalReference), true
		}
		leaf := r.Type
		if i := strings.LastIndex(leaf, "/"); i >= 0 {
			leaf = leaf[i+1:]
		}
		if class, bad := verifyResidualRelTypes[leaf]; bad {
			return fmt.Sprintf("a %s relationship to %q (%s)", leaf, r.Target, class), true
		}
	}
	return "", false
}

func verifyOOXML(ctx context.Context, x engineExec, format, path string) ([]ThreatClass, error) {
	listing, err := x.run(ctx, "unzip", "-Z1", path)
	if err != nil {
		return nil, unverifiableEngineFailure(err, "unzip could not list the output")
	}
	parts := unzipMemberNames(listing)
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: unzip listed no parts in the output",
			ErrSanitizeUnverifiable)
	}

	// Counted rather than assumed. An upload whose zip carries
	// word/document.xml and no [Content_Types].xml is admitted as docx by
	// SniffContainer, the sanitizer copies the root part through, and the
	// macro-enabled check below was simply never entered -- so every OOXML
	// class came back verified and the job reached done with a package Office
	// cannot open. A check that only runs when a part is present says nothing
	// about a package that omits it. Caught in review (PR #12, round 6).
	sawContentTypes := 0

	// SANI-09: the package must still contain the document.
	//
	// relationshipDrivenDrops resolves a relationship's Target and drops that
	// part. A .rels whose Target is the package's OWN main part therefore
	// produces an output that unzips, carries a well-formed
	// [Content_Types].xml, and contains no document at all -- and this
	// verifier was satisfied by it, because it counted [Content_Types].xml and
	// never asked whether anything else survived. Observed before the fix:
	// sanitizeFile succeeded, reported five removed classes, and delivered a
	// package that opens as nothing.
	//
	// "I removed every threat" is not the claim this service makes. It says it
	// sanitized a document, and a package with no document in it cannot be
	// called sanitized -- it can only be called empty.
	mainPart := ooxmlMainPart(format)
	sawMainPart := false
	var contentTypesBlob []byte

	// D-05 precondition: this scratch directory lives INSIDE the job
	// directory (filepath.Dir(path)), never under the system temp dir --
	// probe's ruleset grants no /tmp at all, and a call here that landed
	// under os.TempDir() would fail closed on every single sanitize job the
	// moment that grant leaves probeReadWrite.
	dir, err := os.MkdirTemp(filepath.Dir(path), ".verify-")
	if err != nil {
		return nil, fmt.Errorf("%w: temp dir: %v", ErrSanitizeUnverifiable, err)
	}
	defer os.RemoveAll(dir)

	for i, part := range parts {
		// unzip treats [, ] and * in the member name as wildcard syntax, so
		// [Content_Types].xml -- a part every OOXML package has -- matches
		// nothing unless escaped. Left unhandled this reads as "the part is
		// empty", which is a clean verdict produced by a quoting bug.
		extracted := filepath.Join(dir, fmt.Sprintf("part-%03d", i))
		blob, err := x.run(ctx, "unzip", "-p", path, escapeZipGlob(part))
		if err != nil {
			return nil, unverifiableEngineFailure(err, "unzip could not extract %q", part)
		}
		if err := writeNewFile(extracted, blob, 0o600); err != nil {
			return nil, fmt.Errorf("%w: write %q: %v", ErrSanitizeUnverifiable, part, err)
		}

		out, err := x.run(ctx, "file", "--mime-type", "-b", extracted)
		if err != nil {
			return nil, unverifiableEngineFailure(err, "file(1) could not classify %q", part)
		}
		mime := strings.ToLower(strings.TrimSpace(string(out)))
		for _, ole := range oleMIMETypes {
			if strings.Contains(mime, ole) {
				return nil, fmt.Errorf("%w: part %q is an OLE container (%s)",
					ErrSanitizeResidue, part, mime)
			}
		}

		// libmagic has a blind spot here, found by test rather than reasoning:
		// it needs enough of a well-formed compound file before it will say
		// CDFV2, so a part carrying the OLE signature and little else is
		// classified as something harmless. The sanitizer drops a part on the
		// signature alone, so such a part surviving means the sanitizer
		// failed -- and the check that catches it must therefore be at least
		// as broad as the one that drops it.
		//
		// This is the one place the verifier deliberately shares a PREDICATE
		// with the sanitizer. It does not share an implementation, and it is
		// not the only check: libmagic covers well-formed containers under any
		// name, this covers degenerate ones. Dropping either leaves a range
		// uncovered, and a range uncovered by a verifier reads as clean.
		if IsOLECFBFromPrefix(blob) {
			return nil, fmt.Errorf("%w: part %q begins with the OLE compound-file signature "+
				"(libmagic called it %s)", ErrSanitizeResidue, part, mime)
		}

		if mainPart != "" && strings.EqualFold(part, mainPart) {
			// PRESENT IS NOT ENOUGH. A zero-byte or malformed word/document.xml
			// satisfied a filename comparison while carrying no document at
			// all: the loop's root-element check is only consulted for the
			// property-part test, and libmagic only rules out OLE content. So
			// a valid [Content_Types].xml was letting an empty or corrupt
			// package through -- the very outcome SANI-09 exists to reject,
			// one step further in. Found by review on PR #14, round 4.
			// PARSED TO A CLEAN EOF, not just far enough to see the root.
			// xmlRootElement returns on the first start token, so
			// "<document><broken>" satisfied it while carrying a document that
			// cannot be opened. Found by review on PR #14, round 5 -- the
			// round-4 fix had moved the check to the right place and stopped
			// one token short of making it mean anything.
			root, ok := xmlWholeDocumentRoot(blob)
			if !ok {
				return nil, fmt.Errorf("%w: %s does not parse as XML to the end, so the "+
					"package has no usable document in it", ErrSanitizeUnverifiable, part)
			}
			// LOCAL NAME, NOT THE FULL NAMESPACE, and that is a deliberate
			// limit rather than an oversight. OOXML has two conformance
			// classes with different namespaces for the same element --
			// Transitional (schemas.openxmlformats.org/...) and Strict
			// (purl.oclc.org/ooxml/...) -- so pinning one would refuse valid
			// Strict packages. Rejection here DELETES the output, and this
			// check exists to catch an empty or corrupt main part, not to
			// referee conformance classes.
			if want := ooxmlMainRoot(format); want != "" && root.Local != want {
				return nil, fmt.Errorf("%w: %s has root <%s>, want <%s> -- this is not the "+
					"document this format requires", ErrSanitizeUnverifiable, part,
					root.Local, want)
			}
			sawMainPart = true
		}

		if strings.EqualFold(part, "[Content_Types].xml") {
			sawContentTypes++
			contentTypesBlob = append([]byte(nil), blob...)
			for _, marker := range macroContentTypeMarkers {
				if bytes.Contains(blob, []byte(marker)) {
					return nil, fmt.Errorf("%w: [Content_Types].xml still declares %q",
						ErrSanitizeResidue, marker)
				}
			}
			if root, ok := xmlRootElement(blob); !ok || root.Local != "Types" {
				return nil, fmt.Errorf("%w: [Content_Types].xml does not parse as a Types document",
					ErrSanitizeUnverifiable)
			}
		}

		// A properties part identified by its ROOT ELEMENT, not by its path.
		// The sanitizer drops these; this is the independent confirmation,
		// and it looks at content for the same reason the OLE check does.
		if root, ok := xmlRootElement(blob); ok && ooxmlPropertyRoots[root] {
			return nil, fmt.Errorf("%w: part %q is a document-properties part (<%s> in %s)",
				ErrSanitizeResidue, part, root.Local, root.Space)
		}

		if strings.HasSuffix(strings.ToLower(part), ".rels") {
			if found, ok := residualRelationship(blob); ok {
				return nil, fmt.Errorf("%w: %s declares %s", ErrSanitizeResidue, part, found)
			}
		}
	}

	if sawContentTypes != 1 {
		return nil, fmt.Errorf("%w: the package has %d [Content_Types].xml parts, want exactly 1; "+
			"without it this is not an OOXML package and nothing here describes it",
			ErrSanitizeUnverifiable, sawContentTypes)
	}

	if mainPart == "" {
		return nil, fmt.Errorf("%w: no main part is declared for format %q, so this verifier "+
			"cannot say whether the document survived", ErrSanitizeUnverifiable, format)
	}
	if !sawMainPart {
		return nil, fmt.Errorf("%w: the sanitized package has no %s -- the document itself is "+
			"gone, so there is nothing here to call sanitized", ErrSanitizeUnverifiable, mainPart)
	}
	if !contentTypeDeclares(contentTypesBlob, mainPart) {
		return nil, fmt.Errorf("%w: [Content_Types].xml does not declare a content type for %s; "+
			"the part is present but nothing says what it is, and Office will not open it",
			ErrSanitizeUnverifiable, mainPart)
	}

	return append([]ThreatClass(nil), ooxmlThreatClasses...), nil
}

// unzip -Z1 prints one member name per line. A name may contain spaces, so
// splitting the listing on whitespace turns one member into two paths.
func unzipMemberNames(listing []byte) []string {
	text := strings.TrimSuffix(string(listing), "\n")
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		parts = append(parts, line)
	}
	return parts
}

// escapeZipGlob backslash-escapes the characters Info-ZIP reads as wildcards.
func escapeZipGlob(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch r {
		case '[', ']', '*', '?', '\\':
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// shared
// ---------------------------------------------------------------------------

func joinClasses(cs []ThreatClass) string {
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = string(c)
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// images
// ---------------------------------------------------------------------------

// Plan 60-04 specified verifiers for PDF and OOXML only, because it was
// written expecting the image path to shell out to exiftool. Plan 60-03 chose
// a structural strip instead, so an image verifier is needed and this is it.
//
// The rule that verification cannot be skipped (see sanitizeFile) is what
// forced the issue rather than letting it slide: with no verifier registered,
// every image sanitize failed closed. That is the correct failure, and it is
// louder than a TODO.
//
// Independence: the sanitizer walks segments and never decodes. This verifier
// does the two things the sanitizer does not -- it DECODES the output with the
// standard library, proving the strip left a real image behind, and it asks
// libmagic what the file is. Neither shares a line with the walker.

func init() {
	verifiers["jpg"] = verifyImage
	verifiers["png"] = verifyImage
}

// WHY THIS WALKS THE CONTAINER INSTEAD OF GREPPING IT
//
// The first version scanned the whole output for "tEXt", "Exif\0\0" and
// friends. Compressed image data is arbitrary bytes: a PNG's IDAT stream or a
// JPEG's entropy-coded scan can contain any four-byte sequence, and on a large
// enough image it eventually does. The verifier would then report residue on a
// perfectly clean output, and because verification failure DELETES the output
// (D-07), a false positive here does not merely mislabel a job -- it destroys
// a correct result and fails the job. Caught in review (PR #12).
//
// Structure is not optional here for a second reason: a byte scan cannot tell
// a kept APP2 colour profile from a dropped APP1 EXIF block, so once the
// sanitizer started preserving colour management the grep had no way to
// express the actual rule.
//
// The walk below is written independently of the sanitizer's, and it checks a
// different proposition: the sanitizer asks "should I copy this segment", this
// asks "is any segment of a forbidden class present in what was copied". Two
// implementations of one rule, which is what SANI-04 requires; sharing a
// walker would make this check prove only that the walker agrees with itself.

// jpegSegmentAllowed mirrors sanitizeimage.go's colour-management allowance,
// restated here rather than imported so the two can disagree loudly.
//
// Restated INCLUDING THE SHAPE CHECK, which the prefix-only version lacked: a
// verifier that allows any APP14 starting with "Adobe" confirms as clean the
// exact segment the sanitizer was fixed to stop preserving. The two halves of
// this fix are useless apart.
func jpegSegmentAllowed(marker byte, payload []byte, iccSetComplete bool) bool {
	switch marker {
	case 0xEE:
		return len(payload) == 12 && bytes.HasPrefix(payload, []byte("Adobe"))
	case 0xE2:
		// An ICC chunk is allowed only as part of a COMPLETE set, decided by
		// the caller's own pass (verifierICCSetComplete). The version this
		// replaced read four bytes at a fixed offset as the profile's declared
		// size, which is true of chunk 1 and meaningless in every continuation
		// chunk -- so it called a legitimate chunk residue, and would have
		// failed every multi-chunk profile the sanitizer now correctly keeps.
		//
		// Note the direction this errs in. Broad here means "allowed", so the
		// bar for allowing is a complete set and nothing less; a chunk from an
		// incomplete or inconsistent set is residue, which is the verdict that
		// stops delivery.
		return iccSetComplete && bytes.HasPrefix(payload, []byte("ICC_PROFILE\x00"))
	default:
		return false
	}
}

// verifierICCSetComplete decides, from the OUTPUT alone, whether its ICC chunks
// form one complete profile.
//
// Written against the file rather than shared with the sanitizer's
// iccChunkSetIsValid, for the reason this file's header gives: two
// implementations of one rule are the point, and a shared one would prove only
// that the walker agrees with itself. The propositions are also genuinely
// different -- the sanitizer asks "may I keep these", this asks "is what
// arrived a whole profile".
func verifierICCSetComplete(raw []byte) bool {
	const iccHeader = 14
	tag := []byte("ICC_PROFILE\x00")

	var seqs []int
	count := -1
	assembled := 0
	declared := -1

	i := 2
	for i+1 < len(raw) {
		if raw[i] != 0xFF {
			return false
		}
		for i+2 < len(raw) && raw[i+1] == 0xFF {
			i++
		}
		marker := raw[i+1]
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			i += 2
			continue
		}
		if marker == 0xD9 {
			break
		}
		if i+4 > len(raw) {
			return false
		}
		segLen := int(binary.BigEndian.Uint16(raw[i+2 : i+4]))
		if segLen < 2 || i+2+segLen > len(raw) {
			return false
		}
		end := i + 2 + segLen
		if marker == 0xDA {
			next, err := skipEntropyCodedScan(raw, end)
			if err != nil {
				return false
			}
			i = next
			continue
		}
		if payload := raw[i+4 : end]; marker == 0xE2 && bytes.HasPrefix(payload, tag) {
			if len(payload) < iccHeader {
				return false
			}
			seq, c := int(payload[iccHeader-2]), int(payload[iccHeader-1])
			if count == -1 {
				count = c
			}
			if c != count {
				return false
			}
			seqs = append(seqs, seq)
			data := payload[iccHeader:]
			assembled += len(data)
			if seq == 1 {
				if len(data) < 4 {
					return false
				}
				declared = int(binary.BigEndian.Uint32(data[:4]))
			}
		}
		i = end
	}

	// No chunks at all is a complete set in the only sense that matters here:
	// there is no ICC residue to report. The caller never reaches
	// jpegSegmentAllowed for a segment that does not exist.
	if count == -1 {
		return true
	}
	if count < 1 || len(seqs) != count {
		return false
	}
	seen := make([]bool, count+1)
	for _, s := range seqs {
		if s < 1 || s > count || seen[s] {
			return false
		}
		seen[s] = true
	}
	// The profile's own size field, from chunk 1, against what actually
	// arrived. See iccChunkSetIsValid for why this is equality and what it
	// costs; the two are written apart on purpose and this is one of the
	// places they must nonetheless agree.
	return declared == assembled
}

// jpegMetadataResidue walks a JPEG's segment chain and reports any APPn or COM
// segment that is not one of the allowed colour-management segments.
func jpegMetadataResidue(raw []byte) (string, bool, error) {
	iccSetComplete := verifierICCSetComplete(raw)

	i := 2 // past SOI
	for i+1 < len(raw) {
		if raw[i] != 0xFF {
			return "", false, nil // malformed; the decode check above already ruled
		}
		// Fill bytes before a marker, same rule as the sanitizer's walker and
		// as skipEntropyCodedScan below. Without it this walker stopped early
		// on a legal file and reported CLEAN on segments it never reached.
		for i+2 < len(raw) && raw[i+1] == 0xFF {
			i++
		}
		marker := raw[i+1]
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			i += 2
			continue
		}
		if marker == 0xD9 { // EOI
			return "", false, nil
		}
		if marker == 0xDA {
			// SOS. The scan's compressed bytes carry no segments, but the
			// FILE does not end here: a JPEG may hold several scans and may
			// legally carry APP or COM segments after one. Returning here
			// made this verifier blind in exactly the same place the
			// sanitizer was, so a post-scan EXIF block survived AND was
			// reported as verified -- two independent implementations sharing
			// one wrong assumption prove nothing at all. Caught in review
			// (PR #12, round 3).
			if i+4 > len(raw) {
				return "", false, nil
			}
			segLen := int(binary.BigEndian.Uint16(raw[i+2 : i+4]))
			if segLen < 2 || i+2+segLen > len(raw) {
				return "", false, nil
			}
			next, err := skipEntropyCodedScan(raw, i+2+segLen)
			if err != nil {
				return "", false, err
			}
			i = next
			continue
		}
		if i+4 > len(raw) {
			return "", false, nil
		}
		segLen := int(binary.BigEndian.Uint16(raw[i+2 : i+4]))
		if segLen < 2 || i+2+segLen > len(raw) {
			return "", false, nil
		}
		end := i + 2 + segLen

		isAPP := marker >= 0xE0 && marker <= 0xEF
		if isAPP || marker == 0xFE {
			if !jpegSegmentAllowed(marker, raw[i+4:end], iccSetComplete) {
				return fmt.Sprintf("APP%d/COM segment 0x%02X at offset %d", marker-0xE0, marker, i), true, nil
			}
		}
		i = end
	}
	return "", false, nil
}

// skipEntropyCodedScan returns the offset of the next real marker after a
// scan's compressed data.
//
// Written separately from sanitizeimage.go's endOfEntropyCodedData on purpose,
// even though the rule is the same one: SANI-04 requires the implementation
// that checks to differ from the one that removed, and calling the sanitizer's
// helper here would make this check prove that the helper agrees with itself.
// The rule itself -- FF 00 is stuffing, FF D0..D7 are restart markers, a run
// of FF is padding -- comes from ISO/IEC 10918-1, not from the other function.
func skipEntropyCodedScan(b []byte, from int) (int, error) {
	i := from
	for i+1 < len(b) {
		if b[i] != 0xFF {
			i++
			continue
		}
		j := i
		for j+1 < len(b) && b[j+1] == 0xFF {
			j++
		}
		if j+1 >= len(b) {
			return 0, fmt.Errorf("%w: JPEG scan ended on a fill byte", ErrSanitizeMalformedInput)
		}
		next := b[j+1]
		if next == 0x00 || (next >= 0xD0 && next <= 0xD7) {
			i = j + 2
			continue
		}
		return j, nil
	}
	return len(b), nil
}

// pngMetadataResidue walks a PNG's chunk chain and reports any chunk whose
// TYPE is a metadata type. A four-byte sequence inside IDAT is data, not a
// chunk header, and this is what tells them apart.
func pngMetadataResidue(raw []byte) (string, bool) {
	const sigLen = 8
	i := sigLen
	for i+8 <= len(raw) {
		length := int(binary.BigEndian.Uint32(raw[i : i+4]))
		if length < 0 || i+12+length > len(raw) {
			return "", false
		}
		ctype := string(raw[i+4 : i+8])
		if pngMetadataChunks[ctype] {
			return fmt.Sprintf("%s chunk at offset %d", ctype, i), true
		}
		i += 12 + length
		if ctype == "IEND" {
			break
		}
	}
	return "", false
}

// verifyMaxDecodePixels bounds the full decode above. 100 megapixels is the
// project's own documented image ceiling (MaxImagePixels, .env.example), so
// this refuses exactly the images the API would already have refused at upload
// and no others -- picking a smaller number here would turn a legitimate
// upload the API accepted into a failed job at the last step.
const verifyMaxDecodePixels = 100_000_000

func verifyImage(ctx context.Context, x engineExec, _, path string) ([]ThreatClass, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read output: %v", ErrSanitizeUnverifiable, err)
	}

	// --- view 1: it still decodes as an image, ALL of it ---
	//
	// DecodeConfig alone was not enough, and the gap it left was a false
	// "verified": it reads only enough structure to report dimensions, so a
	// file with an intact header and a truncated or corrupted compressed
	// stream passed. The sanitizer copies that damaged payload through
	// unchanged and libmagic still recognises the header, so the job finished
	// successfully with an output no decoder can open, and the report claimed
	// document_metadata verified. Caught in review (PR #12, round 3) and
	// reproduced before it was fixed: removing one scan byte from the corpus
	// fixture passes DecodeConfig and fails image.Decode with
	// "missing 0xff00 sequence".
	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: the stripped image no longer decodes: %v",
			ErrSanitizeUnverifiable, err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, fmt.Errorf("%w: decoded %s has no dimensions", ErrSanitizeUnverifiable, format)
	}
	// The full decode is bounded BEFORE it is attempted. Go's image decoders
	// materialise the whole raster, so an image admitted at the API's pixel
	// ceiling would allocate hundreds of megabytes inside a 1 GiB worker.
	// Above the bound the answer is "could not verify" -- which deletes the
	// output and fails the job -- rather than a decode that takes the worker
	// with it. Refusing to claim is the fail-closed outcome; claiming without
	// checking is the one D-07 rules out.
	if px := int64(cfg.Width) * int64(cfg.Height); px > verifyMaxDecodePixels {
		return nil, fmt.Errorf("%w: %s is %dx%d (%d pixels), above the %d-pixel bound this "+
			"verifier will decode within the worker's memory",
			ErrSanitizeUnverifiable, format, cfg.Width, cfg.Height, px, verifyMaxDecodePixels)
	}
	if _, _, err := image.Decode(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("%w: the stripped image does not fully decode: %v",
			ErrSanitizeUnverifiable, err)
	}

	// --- view 2: libmagic, a different codebase, agrees what this is ---
	out, err := x.run(ctx, "file", "--mime-type", "-b", path)
	if err != nil {
		return nil, unverifiableEngineFailure(err, "file(1) could not classify the output")
	}
	mime := strings.ToLower(strings.TrimSpace(string(out)))
	if !strings.HasPrefix(mime, "image/") {
		return nil, fmt.Errorf("%w: libmagic calls the output %q, not an image",
			ErrSanitizeUnverifiable, mime)
	}

	// --- view 3: no metadata-carrying segment or chunk survives ---
	var found string
	var isResidue bool
	switch format {
	case "jpeg":
		found, isResidue, err = jpegMetadataResidue(raw)
		if err != nil {
			return nil, err
		}
	case "png":
		found, isResidue = pngMetadataResidue(raw)
	default:
		return nil, fmt.Errorf("%w: no structural check for decoded format %q",
			ErrSanitizeUnverifiable, format)
	}
	if isResidue {
		return nil, fmt.Errorf("%w: %s survives in the output", ErrSanitizeResidue, found)
	}

	return append([]ThreatClass(nil), imageThreatClasses...), nil
}
