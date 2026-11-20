# Sanitize corpus — provenance

These files are **inputs** to tests, never their output. Each one carries threat
constructs on purpose, and each exists to make one claim about the sanitizer
observable rather than argued. Replacing a file means replacing the section
below with it; a fixture nobody can regenerate is a fixture nobody can dispute.

Committed by Plan 60-01, **before** the sanitizer they judge
(`internal/convert/sanitize*.go`, Plans 60-02/60-03). A fixture added alongside
a sanitizer proves what the sanitizer already does. A fixture committed first
proves what it must do. Phase 59 paid for that distinction twice — its corpus
caught a 19× overcount that every pre-existing fixture was blind to.

Regenerate all six with:

```
python3 scripts/sanitize-corpus.py
```

The generator is deterministic (fixed ZIP timestamps, no randomness, no host
paths in the output) and **self-checking**: it greps every fixture for the
markers that fixture exists to carry, *and* walks each one as the format it
claims to be, exiting non-zero if either check fails. Both halves earned their
place by failing:

* the grep half, on its first run, on a marker its own author had asserted
  against the raw bytes of a deflate archive;
* the structural half, on the JPEG this file originally described — see the
  correction recorded under `exif_gps.jpg` below.

## The payloads are inert

`app.alert('benign fixture payload')` and a shell script whose body is `echo`.
The point is that the *constructs* are structurally live — a real action object,
a real filespec, a real OLE container — not that they do anything.

---

## `threat_all_classes.pdf` — 1904 bytes

A one-page PDF carrying every SANI-01 threat class plus `/Info` metadata:
`/OpenAction`, `/AA`, `/Names /JavaScript` with a live action object,
`/Names /EmbeddedFiles` with an attached file, a `/URI` annotation pointing at
an external host, `/Launch`, and `/Info` with a title and an author email.

**Proves (60-RESEARCH.md R1, the empirical half of D-01):** a single
`gs -sDEVICE=pdfwrite` pass does **not** remove everything, and the round trip
through PostScript does. Without this file that is a claim in a planning
document; with it, it is a property under test.

### The R1 table, re-measured on this file

Measured commands (`gs` 10.07.1):

```
gs -q -dNOPAUSE -dBATCH -dSAFER -sDEVICE=pdfwrite -o direct.pdf   threat_all_classes.pdf
gs -q -dNOPAUSE -dBATCH -dSAFER -sDEVICE=ps2write -o mid.ps       threat_all_classes.pdf
gs -q -dNOPAUSE -dBATCH -dSAFER -sDEVICE=pdfwrite -dOmitXMP -o twostep.pdf mid.ps
```

Counts via `grep -ac <marker> <file>`:

| Marker | input | after `pdfwrite` | after `ps2write → pdfwrite` |
|---|---|---|---|
| `/OpenAction` | 1 | 0 | 0 |
| `/AA` | 1 | 0 | 0 |
| `/Launch` | 1 | 0 | 0 |
| `/URI` | 1 | 0 | 0 |
| `evil.example` | 1 | 0 | 0 |
| `JavaScript` | 3 | **1** | 0 |
| `EmbeddedFile` | 2 | **2** | 0 |
| `Secret Internal Title` | 1 | **1** | 0 |
| `jane.doe@corp.example` | 1 | **1** | 0 |
| `xpacket` | **0** | **2** | 0 |

Two rows differ from the research measurement, and both make this fixture a
harder target than the one the research used:

* **`EmbeddedFile` 2 → 2, not 1 → 1.** Object 6 here carries a real
  `/Type /EmbeddedFile` stream, which the research fixture did not. Direct
  `pdfwrite` preserves *both* occurrences, including the one on a genuine
  stream object.
* **`xpacket` 0 → 2.** The input has no XMP packet at all; direct `pdfwrite`
  **creates one**. This is R2 (metadata migrates rather than disappearing) made
  visible in the sharpest possible form: the sanitizer would be *introducing*
  the metadata carrier it was invoked to remove. It is also why D-09 strips XMP
  wholesale with `-dOmitXMP` rather than emptying fields — with the flag, the
  count is 0.

### Content survives exactly

```
pdftotext threat_all_classes.pdf - | tr -d '[:space:]' | wc -c
```

prints **42** for both the input and the two-step output. Same unit as Phase
59's corpus and as `countNonWhitespace` in `internal/convert/ocrguards.go`.

### One revision

The two-step output contains exactly one `startxref` and one `%%EOF`. SC3 asks
for the removed object to be *unrecoverable*, not merely absent: a PDF written
as an incremental update keeps its previous revision in the file, so every
byte-absence count above could read 0 while the document still carries the
construct in a superseded revision. `ps2write` destroys PDF structure entirely,
so there is nothing to append to — but "by construction" is exactly the kind of
promise Phase 59 found untrue in a comment, so 60-02 and 60-04 test it.

### Cost of the round trip

| stage | bytes |
|---|---|
| input | 1,904 |
| intermediate PostScript | 166,369 |
| output | 3,329 |

The PostScript intermediate is a roughly constant ~170 KB overhead, not a
multiplier (60-RESEARCH.md R4) — measured on 1.9–36 KB inputs only. A
production-scale corpus is still required before the Plan 60-06 timeout is set.

**If replaced:** the two-step pipeline loses the only file that shows why it has
two steps, and the argument "it is the same thing, why two passes" becomes
unanswerable without re-running the measurement from scratch.

---

## `macro_enabled.docm` — 1512 bytes

A minimal macro-enabled Word document with the **complete wiring** a real one
has (60-RESEARCH.md Q2):

| Part | Carries |
|---|---|
| `word/vbaProject.bin` | OLE CFB signature `D0 CF 11 E0 A1 B1 1A E1`, module source, and a `_VBA_PROJECT` p-code marker |
| `[Content_Types].xml` | `<Default Extension="bin">`, `<Override PartName="/word/vbaProject.bin">`, and `<Override PartName="/word/document.xml">` with the **macroEnabled** content type |
| `word/_rels/document.xml.rels` | `<Relationship … Type=".../vbaProject" Target="vbaProject.bin"/>` |
| `word/document.xml` | body text that must survive |

**Proves (D-05 and D-06, which are one piece of code):** removing the macro is
three coordinated edits, not one deletion. Skipping any of them yields a file
Word refuses to open — a failure disguised as success, which is worse than no
sanitization at all because the job finishes green.

**Proves the p-code half of SANI-01:** the part carries both benign-looking
module source *and* a p-code marker. That is the shape of VBA stomping, and it
is why D-05 deletes the whole part instead of reading module source: a
sanitizer that inspects the source and declares the document clean is defeated
by construction.

**Proves the OOXML verifier requirement (D-04, Q3):** the OLE signature is
inside the part, so a checker that only lists part names cannot distinguish
this file from one where the macro was renamed. Plan 60-04 tests exactly that
with a renamed part.

Checks:

```
unzip -l macro_enabled.docm | grep -c 'word/vbaProject.bin'          # 1
unzip -p macro_enabled.docm '[Content_Types].xml' | grep -c macroEnabled   # >= 1
```

(The literal `macroEnabled` is **not** greppable in the file's raw bytes — the
part is deflate-compressed. The generator's self-check learned this the hard
way; see the note at the top.)

**If replaced:** the three-edit wiring loses its subject and a sanitizer that
deletes the part while leaving `[Content_Types].xml` dangling passes.

---

## `exif_gps.jpg` — 331 bytes

A 1×1 greyscale baseline JPEG whose APP1/Exif segment carries a hand-assembled
TIFF IFD: `Make = OctoConvCam`, `Model = FixtureModel X1`, and a GPS IFD with
latitude and longitude as rationals.

**Proves (SANI-02):** metadata removal has a subject. The image data is
irrelevant here — one grey pixel — because the requirement is about the
metadata, not the picture.

Built byte by byte rather than through an imaging library: the corpus carries a
zero-new-dependency constraint, and hand-assembling the IFD is what makes every
offset checkable.

Independent confirmation (`file`, which parses the IFD itself rather than
grepping it):

```
$ file exif_gps.jpg
JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=3,
manufacturer=OctoConvCam, model=FixtureModel X1, GPS-Data], baseline,
precision 8, 1x1, components 1
```

**Correction (during Plan 60-03).** The first version of this fixture, pinned by
Plan 60-01 at 330 bytes, was structurally malformed: its SOF0 segment declared
length 11 but carried only 8 payload bytes, because the component-count byte was
missing. Go's `image/jpeg` could not decode it at all (`bad Tq value`), and any
segment-walking sanitizer stopped at offset 274. It nonetheless passed both
independent checks quoted above — the generator's grep, because the markers it
greps for were all present, and `file`, which is lenient enough to report the
image as valid. A grep cannot see a segment whose declared length is a lie.

The generator now derives the SOF0 length from its payload rather than typing
it, and the self-check walks the marker chain from SOI to SOS asserting that
every declared length lands exactly on the next marker, plus that each SOF's
payload matches `6 + 3 × components`. Run against the 330-byte fixture that
check fails with exactly the two lines above; against the 331-byte replacement
it passes, and Go decodes the file to a 1×1 image.

**If replaced:** SANI-02 for images loses its only positive fixture, and a
metadata stripper that silently does nothing passes.

---

## `icc_multichunk.jpg` — 411 bytes

Added by Plan 63-01 for **SANI-07**.

A JPEG whose ICC profile is split across **three** APP2 chunks (192 profile
bytes, 64 per chunk), plus one APP1/Exif segment that must still be dropped.

The trap is four bytes. After the 12-byte `ICC_PROFILE\0` tag each chunk carries
a one-byte sequence number and a one-byte total count, and then raw profile
bytes. Those bytes are the profile *header* only in chunk 1, where the first
four of them are the profile's own size field. In continuation chunks they are
ordinary profile data — so chunk 2 here begins `00 00 00 04`, a perfectly
plausible tiny size that has nothing to do with anything.

Observed on the tree before the fix: **3 chunks in, 2 out.** The sanitizer
dropped a chunk out of the middle of a valid profile, leaving a file that still
decodes, still reports its colour profile as preserved, and renders with the
wrong colours.

The APP1 is not decoration: a fixture where nothing is dropped would pass an ICC
test for the wrong reason.

The generator walks the chunk set it just built and refuses to emit one whose
sequence numbers are not exactly `1..count`, whose chunks disagree about
`count`, whose assembled profile does not begin with its own size, or whose
chunk 2 does not carry the trap bytes. A fixture that is malformed in some other
way would make the sanitizer drop the set for a reason unrelated to the finding,
and the test would still be green.

---

## `endstream_in_stream.pdf` — 656 bytes

Added by Plan 63-01 for **SANI-08**.

One content stream whose payload contains, as ordinary bytes, all three tokens
the two byte walkers look for: `endstream`, `startxref` and `%%EOF`. The
dictionary's `/Length` is correct and the file is valid — the substring scan and
the dictionary simply disagree about where the stream ends.

Observed on the tree before the fix, and **worse than the review finding
predicted**:

* `pdfStreamRanges` returns `[274 337]` for a payload that actually runs to
  offset 400, so the redactor's protected range excludes the last 63 bytes — it
  may rewrite bytes inside the stream.
* `pdfNonStreamBytes` gets it exactly **inverted**. The payload's `startxref`
  (offset 362) and `%%EOF` (376) *survive* blanking, and the file's real trailer
  — xref table, `startxref 473`, `%%EOF` — is blanked to spaces. The revision
  count then reads 1 and 1 and passes, arrived at by reading the payload as
  structure *and* the structure as payload: two errors whose totals happen to
  agree with the right answer.

The second half of that has a second cause worth naming: `bytes.Index(…,
"stream")` matches inside `endstream`, so after the first blanking the walker
re-enters on the tail of the keyword it just consumed.

---

## `ooxml_rel_targets_main.docx` — 1239 bytes

Added by Plan 63-01 for **SANI-09**.

A docx whose `word/_rels/document.xml.rels` declares an `oleObject`
relationship whose `Target` is `document.xml` — the package's own main part.
`relationshipDrivenDrops` resolves that target and drops it.

Observed on the tree before the fix: `sanitizeFile` **succeeds**, reports
`removed=[vba_macro ole_object embedded_file external_reference
document_metadata]`, and delivers a package with **no `word/document.xml` at
all**. It unzips, it carries a well-formed `[Content_Types].xml`, and it opens
as nothing. The verifier counts `[Content_Types].xml` and never asks whether the
document survived.

---

## What this corpus does NOT cover

Listing what is covered without listing what is not reads as completeness.

* **Production scale.** The largest fixture is 1.9 KB. R4's "constant PostScript
  overhead, not a multiplier" is measured on 1.9–36 KB only, and Plan 60-06's
  timeout must be measured on a real corpus — not extrapolated from these.
* **Encrypted PDFs.** No fixture is encrypted. ISO 32000 §7.5.7 keeps the
  encryption dictionary out of object streams, but nothing here exercises what
  the sanitizer does when it cannot decrypt at all.
* **OOXML OLE objects other than VBA.** An embedded OLE object inside
  `word/embeddings/` is a distinct class from `vbaProject.bin` and has no
  fixture here.
* **Image metadata other than EXIF.** No IPTC segment, no XMP packet in a JPEG,
  no PNG `tEXt`/`iTXt` chunk. SANI-02 names all of them; this corpus proves one.
* **Multi-revision PDF input.** The single-revision property is measured on the
  *output* above; an input that already carries two revisions is built by Plan
  60-02's own test, not committed here.
* **Visual fidelity.** Text is measured exactly (42). Fonts, colour profiles and
  rendered appearance after the PostScript round trip are **not** checked by
  anything in this phase (60-RESEARCH.md A1, confidence MEDIUM-HIGH).
