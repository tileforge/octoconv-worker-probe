// Package convert sanitizes PDF, OOXML, and image files.
package convert

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	EngineProbe                = "probe"
	OperationSanitize          = "sanitize"
	DefaultEngineTimeout       = 600 * time.Second
	MaxInputBytes        int64 = 50 << 20
	MaxFileBytes               = 100 << 20
)

// ErrOutputTooLarge is the read-limit sentinel for a job file.
var ErrOutputTooLarge = fmt.Errorf("output exceeds the byte ceiling")

// Pair is one source format and one target format.
type Pair struct {
	From string
	To   string
}

// Converter sanitizes the file at inPath into outPath.
type Converter interface {
	Pairs() []Pair
	Convert(ctx context.Context, inPath, outPath string, opts map[string]any) error
}

// OperationalConverter reports a job operation other than convert.
type OperationalConverter interface {
	Operation() string
}

var formatAliases = map[string]string{
	"jpeg": "jpg",
	"tif":  "tiff",
}

// MIMEType is the content type stored for format.
func MIMEType(format string) string {
	switch NormalizeFormat(format) {
	case "png":
		return "image/png"
	case "jpg":
		return "image/jpeg"
	case "pdf":
		return "application/pdf"
	case "docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case "xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case "pptx":
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case "dotx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.template"
	case "xltx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.template"
	case "potx":
		return "application/vnd.openxmlformats-officedocument.presentationml.template"
	case "ppsx":
		return "application/vnd.openxmlformats-officedocument.presentationml.slideshow"
	case "json":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

// NormalizeFormat lowercases a format or extension, strips one leading dot, and folds jpeg to jpg.
func NormalizeFormat(f string) string {
	f = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(f), "."))
	if canonical, ok := formatAliases[f]; ok {
		return canonical
	}
	return f
}

func operationOf(c Converter) string {
	if oc, ok := c.(OperationalConverter); ok {
		return oc.Operation()
	}
	return "convert"
}

type opKey struct {
	Operation string
	From      string
	To        string
}

// Registry maps an operation and a format pair to a converter.
type Registry struct {
	m map[opKey]Converter
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{m: make(map[opKey]Converter)}
}

// Register indexes each pair c reports.
func (r *Registry) Register(c Converter) {
	op := operationOf(c)
	for _, pair := range c.Pairs() {
		key := opKey{Operation: op, From: NormalizeFormat(pair.From), To: NormalizeFormat(pair.To)}
		if existing, ok := r.m[key]; ok {
			panic(fmt.Sprintf("convert: Register: triple (%s, %s, %s) already registered to %T", key.Operation, key.From, key.To, existing))
		}
		r.m[key] = c
	}
}

// Replace indexes each pair c reports, overwriting a previous converter for that pair.
func (r *Registry) Replace(c Converter) {
	op := operationOf(c)
	for _, pair := range c.Pairs() {
		r.m[opKey{
			Operation: op,
			From:      NormalizeFormat(pair.From),
			To:        NormalizeFormat(pair.To),
		}] = c
	}
}

// LookupOp reports the converter for op, from, and to.
func (r *Registry) LookupOp(op, from, to string) (Converter, bool) {
	c, ok := r.m[opKey{
		Operation: op,
		From:      NormalizeFormat(from),
		To:        NormalizeFormat(to),
	}]
	return c, ok
}

// EngineForOp reports the engine that serves op from source to target.
func (r *Registry) EngineForOp(op, from, to string) (string, bool) {
	c, ok := r.LookupOp(op, from, to)
	if !ok {
		return "", false
	}
	if e, ok := c.(interface{ Engine() string }); ok {
		return e.Engine(), true
	}
	return "", false
}

// Default is the process registry.
var Default = NewRegistry()
