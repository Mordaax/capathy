package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"capathy/agent/internal/request"
)

// ImportScript projects the versioned native evidence document, retaining original-byte spans and parser provenance.
func ImportScript(data []byte) (Bundle, error) {
	var document struct {
		Schema           int    `json:"schema"`
		Language         string `json:"language"`
		SHA256           string `json:"sha256"`
		ByteLength       uint64 `json:"byte_length"`
		ExtractorVersion string `json:"extractor_version"`
		Functions        []struct {
			Start      uint64 `json:"start_byte"`
			End        uint64 `json:"end_byte"`
			Statements []struct {
				Start    uint64 `json:"start_byte"`
				End      uint64 `json:"end_byte"`
				Ordinal  uint64 `json:"ordinal"`
				Features []struct {
					Kind   string          `json:"kind"`
					Value  json.RawMessage `json:"value"`
					Start  uint64          `json:"start_byte"`
					End    uint64          `json:"end_byte"`
					Access string          `json:"access"`
					Basis  string          `json:"basis"`
					Node   string          `json:"source_node"`
				} `json:"features"`
			} `json:"statements"`
		} `json:"functions"`
	}
	var out Bundle
	if len(data) > 32<<20 {
		return out, errors.New("script evidence too large")
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return out, err
	}
	if document.Schema != 1 || !request.ValidHash(document.SHA256) || document.ByteLength > request.MaxInput || document.ExtractorVersion == "" {
		return out, errors.New("script evidence requires schema 1, source hash, byte length and extractor version")
	}
	switch document.Language {
	case "powershell", "python", "bash":
	default:
		return out, errors.New("unsupported script language")
	}
	out = Bundle{SampleSHA256: document.SHA256, Format: document.Language, CapaVersion: "native-schema-1", Features: []request.EvidenceRef{}}
	seen := map[string]bool{}
	functionsSeen := map[uint64]bool{}
	statements := map[string]bool{}
	count := 0
	for _, function := range document.Functions {
		if functionsSeen[function.Start] {
			return out, errors.New("duplicate function address")
		}
		functionsSeen[function.Start] = true
		if function.Start > function.End || function.End > document.ByteLength {
			return out, errors.New("invalid function span")
		}
		for _, statement := range function.Statements {
			key := fmt.Sprintf("%d:%d", statement.Start, statement.Ordinal)
			if statements[key] || statement.Start < function.Start || statement.Start > statement.End || statement.End > function.End {
				return out, errors.New("invalid or duplicate statement")
			}
			statements[key] = true
			for _, feature := range statement.Features {
				count++
				if count > 100000 {
					return out, errors.New("too many script features")
				}
				if feature.Start < statement.Start || feature.Start > feature.End || feature.End > statement.End || feature.Node == "" || (feature.Basis != "direct" && feature.Basis != "static-alias") {
					return out, errors.New("invalid script feature provenance")
				}
				switch feature.Kind {
				case "script-call", "script-variable", "script-structure", "string", "number":
				default:
					return out, errors.New("unknown script feature kind")
				}
				var value string
				if feature.Kind == "number" {
					decoder := json.NewDecoder(bytes.NewReader(feature.Value))
					decoder.UseNumber()
					var numeric any
					if err := decoder.Decode(&numeric); err != nil {
						return out, errors.New("invalid numeric feature")
					}
					number, ok := numeric.(json.Number)
					if !ok {
						return out, errors.New("number feature must be a JSON integer")
					}
					if _, err := number.Int64(); err != nil {
						return out, errors.New("number feature must be a JSON integer")
					}
					value = number.String()
				} else if err := json.Unmarshal(feature.Value, &value); err != nil {
					return out, errors.New("invalid script feature value")
				}
				kind := feature.Kind
				if kind == "script-variable" {
					if feature.Access != "read" && feature.Access != "write" {
						return out, errors.New("invalid variable access")
					}
					kind += "/" + feature.Access
				}
				address := feature.Start
				e := request.EvidenceRef{SampleSHA256: document.SHA256, Kind: kind, Value: value, Address: &address, Span: &request.Span{Start: feature.Start, End: feature.End}, CapaVersion: out.CapaVersion, ExtractorVersion: document.ExtractorVersion}
				b, _ := json.Marshal(e)
				e.ID = "e-" + request.Hash(b)[:24]
				if !seen[e.ID] {
					seen[e.ID] = true
					out.Features = append(out.Features, e)
				}
			}
		}
	}
	sort.Slice(out.Features, func(i, j int) bool { return out.Features[i].ID < out.Features[j].ID })
	return out, nil
}
