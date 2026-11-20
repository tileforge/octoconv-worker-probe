package main

import (
	"errors"
	"testing"
)

func TestClassifyInputs(t *testing.T) {
	source := fileLinkJSON{Role: "source", Ordinal: 0, Format: "pdf", Href: "https://files.example/objects/in"}
	got, extras, err := classifyInputs([]fileLinkJSON{source})
	if err != nil || got.Href != source.Href || len(extras) != 0 {
		t.Fatalf("single input %+v %+v %v", got, extras, err)
	}
	second := source
	second.Ordinal = 1
	if _, _, err := classifyInputs([]fileLinkJSON{source, second}); !errors.Is(err, errAssignmentInputs) {
		t.Fatalf("second input err %v", err)
	}
	if _, _, err := classifyInputs(nil); !errors.Is(err, errAssignmentInputs) {
		t.Fatalf("empty err %v", err)
	}
	bad := source
	bad.Role = "attachment"
	if _, _, err := classifyInputs([]fileLinkJSON{bad}); !errors.Is(err, errAssignmentInputs) {
		t.Fatalf("role err %v", err)
	}
}
