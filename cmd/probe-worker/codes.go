package main

import (
	"context"
	"errors"
	"strings"

	"github.com/tileforge/octoconv-worker-probe/internal/convert"
)

func transportCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "engine_error"
}

func probeEngineCode(err error) (string, string) {
	if err == nil {
		return "engine_error", "sanitization failed"
	}
	if errors.Is(err, convert.ErrEngineSandboxUnavailable) || errors.Is(err, context.DeadlineExceeded) {
		return "timeout", safeMessage(err)
	}
	if errors.Is(err, convert.ErrOutputTooLarge) {
		return "output_too_large", "the sanitized output is larger than this deployment accepts"
	}
	if errors.Is(err, convert.ErrSanitizeResidue) {
		return "engine_error", "sanitized output still contained a construct that had to be removed"
	}
	if errors.Is(err, convert.ErrSanitizeUnverifiable) {
		return "engine_error", "sanitized output could not be independently verified and was discarded"
	}
	if errors.Is(err, convert.ErrSanitizeMalformedInput) {
		return "engine_error", "the uploaded document could not be parsed for sanitization"
	}
	if errors.Is(err, convert.ErrProbeTooManyPages) {
		return "too_many_pages", "the document has more pages than this service will sanitize"
	}
	if strings.Contains(strings.ToLower(err.Error()), "takes no options") {
		return "invalid_options", "stored conversion options are invalid"
	}
	return "engine_error", "unsupported or corrupted input format"
}
