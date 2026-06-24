package evidence

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Mordaax/capathy/agent/internal/request"
	"io"
	"sort"
	"strings"
)

// ImportFull imports observations independently of rule matches, retaining their scope and address spaces.
func ImportFull(data []byte) (Bundle, error) {
	var out Bundle
	if len(data) > 32<<20 {
		return out, errors.New("feature export exceeds 32 MiB")
	}
	var doc struct {
		Schema int    `json:"schema"`
		Kind   string `json:"kind"`
		Sample struct {
			SHA256     string `json:"sha256"`
			ByteLength uint64 `json:"byte_length"`
		} `json:"sample"`
		Analysis struct {
			Format          string `json:"format"`
			CapaVersion     string `json:"capa_version"`
			Extractor       string `json:"extractor"`
			RuntimeRevision string `json:"runtime_revision"`
			Complete        bool   `json:"complete"`
		} `json:"analysis"`
		Functions []struct {
			Address request.Location `json:"address"`
		} `json:"functions"`
		Features []struct {
			Kind       string            `json:"kind"`
			Value      json.RawMessage   `json:"value"`
			Scope      string            `json:"scope"`
			Address    request.Location  `json:"address"`
			Function   *request.Location `json:"function"`
			BasicBlock *request.Location `json:"basic_block"`
			Statement  json.RawMessage   `json:"statement"`
			Feature    json.RawMessage   `json:"feature"`
		} `json:"features"`
		Script      json.RawMessage `json:"script,omitempty"`
		Diagnostics json.RawMessage `json:"diagnostics"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return out, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return out, errors.New("trailing JSON")
	}
	if doc.Schema != 1 || doc.Kind != "capathy.features" || !doc.Analysis.Complete || !request.ValidHash(doc.Sample.SHA256) || doc.Sample.ByteLength > request.MaxInput || doc.Analysis.CapaVersion == "" || doc.Analysis.Extractor == "" || len(doc.Features) > 100000 {
		return out, errors.New("invalid full feature export")
	}
	revision, err := hex.DecodeString(doc.Analysis.RuntimeRevision)
	if err != nil || len(revision) != 20 || doc.Analysis.RuntimeRevision != strings.ToLower(doc.Analysis.RuntimeRevision) {
		return out, errors.New("verified runtime revision required")
	}
	switch doc.Analysis.Format {
	case "pe", "elf", "dotnet", "sc32", "sc64", "powershell", "python", "bash", "javascript", "typescript", "c", "cpp":
	default:
		return out, errors.New("unsupported feature format")
	}
	validLocation := func(loc request.Location) bool {
		switch loc.Type {
		case "no address":
			return string(loc.Value) == "null"
		case "absolute", "relative", "file", "dn token":
			var n uint64
			return json.Unmarshal(loc.Value, &n) == nil && (loc.Type != "file" || n < doc.Sample.ByteLength)
		case "dn token offset":
			var pair []uint64
			return json.Unmarshal(loc.Value, &pair) == nil && len(pair) == 2
		}
		return false
	}
	functions := map[string]bool{}
	for _, f := range doc.Functions {
		if !validLocation(f.Address) {
			return out, errors.New("invalid function location")
		}
		b, _ := json.Marshal(f.Address)
		functions[string(b)] = true
	}
	out = Bundle{SampleSHA256: doc.Sample.SHA256, Format: doc.Analysis.Format, CapaVersion: doc.Analysis.CapaVersion}

	if len(doc.Script) > 0 {
		script, err := ImportScript(doc.Script)
		if err != nil {
			return out, err
		}
		if script.SampleSHA256 != out.SampleSHA256 || script.Format != out.Format {
			return out, errors.New("script identity mismatch")
		}
		out.Features = script.Features
		for i := range out.Features {
			out.Features[i].CapaVersion = out.CapaVersion
			out.Features[i].RuntimeRevision = doc.Analysis.RuntimeRevision
		}
		return out, nil
	}
	seen := map[string]bool{}
	for _, f := range doc.Features {
		if !validLocation(f.Address) || f.Kind == "" || len(f.Kind) > 128 || len(f.Value) > 65536 || f.Kind == "match" {
			return out, errors.New("invalid observation")
		}
		switch f.Scope {
		case "global", "file":
			if f.Function != nil {
				return out, errors.New("invalid global parent")
			}
		case "function", "basic block", "instruction", "statement":
			if f.Function == nil {
				return out, errors.New("missing observation parent")
			}
		default:
			return out, errors.New("unknown observation scope")
		}
		if f.Function != nil {
			b, _ := json.Marshal(f.Function)
			if !functions[string(b)] {
				return out, errors.New("unknown parent function")
			}
		}
		if f.BasicBlock != nil && !validLocation(*f.BasicBlock) {
			return out, errors.New("invalid block location")
		}
		var value string
		if err := json.Unmarshal(f.Value, &value); err != nil {
			var number json.Number
			if json.Unmarshal(f.Value, &number) != nil || string(f.Value) == "null" {
				return out, errors.New("invalid observation value")
			}
			value = string(f.Value)
		}
		e := request.EvidenceRef{RuntimeRevision: doc.Analysis.RuntimeRevision, SampleSHA256: out.SampleSHA256, Kind: f.Kind, Value: value, CapaVersion: out.CapaVersion, ExtractorVersion: doc.Analysis.Extractor, Scope: f.Scope, Location: &f.Address, Function: f.Function, BasicBlock: f.BasicBlock}
		b, _ := json.Marshal(e)
		e.ID = "e-" + request.Hash(b)[:24]
		if !seen[e.ID] {
			out.Features = append(out.Features, e)
			seen[e.ID] = true
		}
	}
	sort.Slice(out.Features, func(i, j int) bool { return out.Features[i].ID < out.Features[j].ID })
	return out, nil
}
