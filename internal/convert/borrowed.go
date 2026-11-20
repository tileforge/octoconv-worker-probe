package convert

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrOCRTooManyPages stays a distinct sentinel from ErrProbeTooManyPages.
var ErrOCRTooManyPages = errors.New("ocr: pdf page count exceeds bound")

func enforceMaxPages(count, max int) error {
	if max > 0 && count > max {
		return fmt.Errorf("%w: declared page count %d exceeds bound %d", ErrOCRTooManyPages, count, max)
	}
	return nil
}

// ooxmlMacroParts is the closed set of literal OOXML macro-storage paths.
var ooxmlMacroParts = map[string]bool{
	"word/vbaProject.bin": true,
	"xl/vbaProject.bin":   true,
	"ppt/vbaProject.bin":  true,
}

func ocrPageCountArgs(pdfPath string) []string {
	return []string{pdfPath}
}

func parsePdfinfoPages(out []byte) (int, error) {
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(line, "Pages:")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil {
			return 0, fmt.Errorf("ocr: unparseable pdfinfo Pages line %q: %w", line, err)
		}
		return n, nil
	}
	return 0, errors.New("ocr: pdfinfo output has no Pages line")
}

func ocrPreflightPDF(text string) []byte {
	const width, height = 1000, 200
	content := []byte(fmt.Sprintf("BT\n/F1 40 Tf\n20 100 Td\n(%s) Tj\nET\n", text))
	contentObj := append(
		[]byte(fmt.Sprintf("<< /Length %d >>\nstream\n", len(content))),
		append(content, []byte("\nendstream")...)...,
	)
	objects := [][]byte{
		[]byte("<< /Type /Catalog /Pages 2 0 R >>"),
		[]byte("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
		[]byte(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] "+
			"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>", width, height)),
		contentObj,
		[]byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
	}
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for i, body := range objects {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n", i+1)
		buf.Write(body)
		buf.WriteString("\nendobj\n")
	}
	xrefAt := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xrefAt)
	return buf.Bytes()
}
