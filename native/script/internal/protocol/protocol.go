// Package protocol defines and validates the script evidence wire format.
package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

// Schema is the wire format version.
const Schema = 1

// MaxOutput bounds encoded JSON.
const MaxOutput = 32 << 20

// Document is evidence for one original input.
type Document struct {
	ExtractorVersion     string       `json:"extractor_version"`
	GrammarVersion       string       `json:"grammar_version"`
	NormalizationVersion int          `json:"normalization_version"`
	Schema               int          `json:"schema"`
	Language             string       `json:"language"`
	SHA256               string       `json:"sha256"`
	ByteLength           uint32       `json:"byte_length"`
	Functions            []Function   `json:"functions"`
	Diagnostics          []Diagnostic `json:"diagnostics"`
}

// Function is a function or the executable top-level region.
type Function struct {
	StartByte  uint32      `json:"start_byte"`
	EndByte    uint32      `json:"end_byte"`
	Name       string      `json:"name"`
	TopLevel   bool        `json:"top_level"`
	Statements []Statement `json:"statements"`
}

// Statement is one source-local matching scope.
type Statement struct {
	StartByte uint32    `json:"start_byte"`
	EndByte   uint32    `json:"end_byte"`
	Ordinal   uint32    `json:"ordinal"`
	Features  []Feature `json:"features"`
}

// Feature retains exact source provenance for a concrete observation.
type Feature struct {
	Kind         string `json:"kind"`
	Value        any    `json:"value"`
	DisplayValue string `json:"display_value,omitempty"`
	Access       string `json:"access,omitempty"`
	Basis        string `json:"basis"`
	SourceNode   string `json:"source_node"`
	StartByte    uint32 `json:"start_byte"`
	EndByte      uint32 `json:"end_byte"`
}

// Diagnostic records uncertainty without inventing evidence.
type Diagnostic struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	StartByte uint32 `json:"start_byte"`
	EndByte   uint32 `json:"end_byte"`
}

// New constructs an empty document hashed over the original bytes.
func New(language string, raw []byte) Document {
	h := sha256.Sum256(raw)
	return Document{ExtractorVersion: "0.1.0", GrammarVersion: map[string]string{"powershell": "0.38.1", "python": "0.25.0", "bash": "0.25.1", "javascript": "0.23.1", "typescript": "0.23.2", "c": "0.23.4", "cpp": "0.23.4"}[language], NormalizationVersion: 1, Schema: Schema, Language: language, SHA256: hex.EncodeToString(h[:]), ByteLength: uint32(len(raw)), Functions: []Function{}, Diagnostics: []Diagnostic{}}
}
func span(start, end, lo, hi uint32) bool { return start >= lo && end <= hi && start < end }

// Validate checks all identities, values, provenance, and nested intervals.
func (d Document) Validate() error {
	if d.Schema != Schema {
		return errors.New("unsupported schema")
	}
	if d.Language != "powershell" && d.Language != "python" && d.Language != "bash" && d.Language != "javascript" && d.Language != "typescript" && d.Language != "c" && d.Language != "cpp" {
		return errors.New("unsupported language")
	}
	h, e := hex.DecodeString(d.SHA256)
	if e != nil || len(h) != 32 || hex.EncodeToString(h) != d.SHA256 {
		return errors.New("invalid SHA-256")
	}
	if d.ByteLength > 16<<20 {
		return errors.New("input exceeds limit")
	}
	ids := map[[2]uint32]bool{}
	functions := map[uint32]bool{}
	top := false
	for _, f := range d.Functions {
		if !span(f.StartByte, f.EndByte, 0, d.ByteLength) || functions[f.StartByte] {
			return errors.New("invalid or duplicate function span")
		}
		functions[f.StartByte] = true
		if f.TopLevel {
			if top || len(f.Statements) == 0 || f.StartByte != f.Statements[0].StartByte {
				return errors.New("invalid top-level region")
			}
			top = true
		}
		for _, s := range f.Statements {
			key := [2]uint32{s.StartByte, s.Ordinal}
			if ids[key] || !span(s.StartByte, s.EndByte, f.StartByte, f.EndByte) {
				return errors.New("invalid or duplicate statement span")
			}
			ids[key] = true
			for _, v := range s.Features {
				if !span(v.StartByte, v.EndByte, s.StartByte, s.EndByte) || v.SourceNode == "" || (v.Basis != "direct" && v.Basis != "static-alias") {
					return errors.New("invalid feature provenance")
				}
				switch v.Kind {
				case "script-call", "script-variable", "script-structure", "string":
					if _, ok := v.Value.(string); !ok {
						return errors.New("feature value must be string")
					}
				case "number":
					switch n := v.Value.(type) {
					case float64:
						if math.IsNaN(n) || math.IsInf(n, 0) {
							return errors.New("invalid number")
						}
					case int, int64, uint64:
					default:
						return errors.New("invalid number")
					}
				default:
					return fmt.Errorf("unknown feature kind: %s", v.Kind)
				}
				if v.Kind == "script-variable" {
					if v.Access != "read" && v.Access != "write" {
						return errors.New("invalid variable access")
					}
				} else if v.Access != "" {
					return errors.New("unexpected access")
				}
				if v.Kind == "script-structure" {
					allowed := map[string]bool{"assignment": true, "pipeline": true, "branch": true, "loop": true, "try": true, "redirection": true, "command-substitution": true, "function-definition": true}
					if !allowed[v.Value.(string)] {
						return errors.New("unknown structure")
					}
				}
			}
		}
	}
	for _, v := range d.Diagnostics {
		if v.StartByte > v.EndByte || v.EndByte > d.ByteLength || v.Code == "" || v.Message == "" {
			return errors.New("invalid diagnostic")
		}
	}
	return nil
}

// ValidateSource additionally verifies the input digest and byte length.
func (d Document) ValidateSource(raw []byte) error {
	if e := d.Validate(); e != nil {
		return e
	}
	expected := New(d.Language, raw)
	if d.SHA256 != expected.SHA256 || d.ByteLength != expected.ByteLength {
		return errors.New("source hash or length mismatch")
	}
	return nil
}
