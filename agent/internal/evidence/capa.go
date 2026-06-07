// Package evidence normalizes recorded capa output without executing sample contents.
package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/Mordaax/capathy/agent/internal/request"
)

// Bundle is the evidence-only projection of a capa result document.
type Bundle struct {
	SampleSHA256 string                `json:"sample_sha256"`
	Format       string                `json:"format"`
	CapaVersion  string                `json:"capa_version"`
	Features     []request.EvidenceRef `json:"features"`
}
type address struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}
type match struct {
	Success bool `json:"success"`
	Node    struct {
		Type    string                     `json:"type"`
		Feature map[string]json.RawMessage `json:"feature"`
	} `json:"node"`
	Children  []match   `json:"children"`
	Locations []address `json:"locations"`
}
type result struct {
	Meta struct {
		Version string `json:"version"`
		Sample  struct {
			SHA256 string `json:"sha256"`
		} `json:"sample"`
		Analysis struct {
			Format string                     `json:"format"`
			Script map[string]json.RawMessage `json:"script"`
		} `json:"analysis"`
	} `json:"meta"`
	Rules map[string]struct {
		Matches []json.RawMessage `json:"matches"`
	} `json:"rules"`
}

// Import strictly projects observed successful leaves and stable addresses. Unsuccessful optional branches never become evidence.
func Import(data []byte) (Bundle, error) {
	var out Bundle
	if len(data) > 32<<20 {
		return out, errors.New("capa result exceeds 32 MiB")
	}
	var r result
	d := json.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(&r); err != nil {
		return out, fmt.Errorf("decode capa JSON: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return out, errors.New("trailing JSON")
	}
	if !request.ValidHash(r.Meta.Sample.SHA256) || r.Meta.Version == "" || r.Rules == nil {
		return out, errors.New("capa sample hash, version and rules required")
	}
	switch r.Meta.Analysis.Format {
	case "pe", "elf", "dotnet", "sc32", "sc64", "powershell", "python", "bash":
	default:
		return out, errors.New("unsupported capa format")
	}
	out.SampleSHA256 = r.Meta.Sample.SHA256
	out.CapaVersion = r.Meta.Version
	out.Format = r.Meta.Analysis.Format
	if out.Format == "powershell" || out.Format == "python" || out.Format == "bash" {
		if len(r.Meta.Analysis.Script) == 0 {
			return out, errors.New("script results require parser evidence metadata")
		}
		raw, err := json.Marshal(r.Meta.Analysis.Script)
		if err != nil {
			return out, err
		}
		script, err := ImportScript(raw)
		if err != nil {
			return out, err
		}
		if script.SampleSHA256 != out.SampleSHA256 || script.Format != out.Format {
			return out, errors.New("script evidence hash or language mismatch")
		}
		for i := range script.Features {
			script.Features[i].CapaVersion = out.CapaVersion
		}
		out.Features = script.Features
		return out, nil
	}
	seen := map[string]bool{}
	count := 0
	var walk func(match, int) error
	walk = func(m match, depth int) error {
		count++
		if depth > 128 || count > 100000 {
			return errors.New("capa evidence tree limit exceeded")
		}
		if !m.Success {
			return nil
		}
		if m.Node.Type == "feature" {
			var kind string
			if err := json.Unmarshal(m.Node.Feature["type"], &kind); err != nil {
				return errors.New("missing feature type")
			}
			if kind == "match" {
				return nil
			}
			valueRaw, ok := m.Node.Feature[kind]
			if !ok {
				return fmt.Errorf("missing value for %s", kind)
			}
			var text string
			if err := json.Unmarshal(valueRaw, &text); err != nil {
				text = string(valueRaw)
			}
			if len(text) > 65536 {
				return errors.New("feature value too large")
			}
			for _, loc := range m.Locations {
				if loc.Type != "file" && loc.Type != "absolute" && loc.Type != "relative" && loc.Type != "dn token" {
					continue
				}
				var value uint64
				if err := json.Unmarshal(loc.Value, &value); err != nil {
					return errors.New("invalid feature offset")
				}
				e := request.EvidenceRef{SampleSHA256: out.SampleSHA256, Kind: kind, Value: text, Address: &value, CapaVersion: out.CapaVersion}
				canonical, _ := json.Marshal(e)
				e.ID = "e-" + request.Hash(canonical)[:24]
				if !seen[e.ID] {
					out.Features = append(out.Features, e)
					seen[e.ID] = true
				}
			}
		}
		for _, child := range m.Children {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, rule := range r.Rules {
		for _, raw := range rule.Matches {
			var pair []json.RawMessage
			if err := json.Unmarshal(raw, &pair); err != nil || len(pair) != 2 {
				return out, errors.New("invalid capa match pair")
			}
			var m match
			if err := json.Unmarshal(pair[1], &m); err != nil {
				return out, err
			}
			if err := walk(m, 0); err != nil {
				return out, err
			}
		}
	}
	sort.Slice(out.Features, func(i, j int) bool { return out.Features[i].ID < out.Features[j].ID })
	return out, nil
}
