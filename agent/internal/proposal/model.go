// Package proposal validates structured model output against immutable evidence.
package proposal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"capathy/agent/internal/request"
	"gopkg.in/yaml.v3"
)

// Proposal contains only a candidate rule and exact evidence citation IDs.
type Proposal struct {
	Schema      int      `json:"schema"`
	RequestID   string   `json:"request_id"`
	YAML        string   `json:"yaml"`
	Citations   []string `json:"citations"`
	Uncertainty []string `json:"uncertainty"`
}

// Rule is the parsed YAML envelope used by deterministic checks.
type Rule struct {
	Rule struct {
		Meta struct {
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
			Scopes    struct {
				Static  string `yaml:"static"`
				Dynamic string `yaml:"dynamic"`
			} `yaml:"scopes"`
		} `yaml:"meta"`
		Features []any `yaml:"features"`
	} `yaml:"rule"`
}

// ParseRule rejects malformed/multiple YAML documents and missing rule structure.
func ParseRule(text string) (Rule, error) {
	var r Rule
	if len(text) > 1<<20 {
		return r, errors.New("candidate YAML too large")
	}
	dec := yaml.NewDecoder(strings.NewReader(text))
	if err := dec.Decode(&r); err != nil {
		return r, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return r, errors.New("candidate must contain exactly one YAML document")
	}
	if r.Rule.Meta.Name == "" || len(r.Rule.Meta.Name) > 256 || len(r.Rule.Features) == 0 {
		return r, errors.New("candidate rule requires name and features")
	}
	return r, nil
}

// Decode requires exactly the supported model schema, with no command/path/tool fields.
func Decode(data []byte) (Proposal, error) {
	var p Proposal
	if len(data) > 1<<20 {
		return p, errors.New("proposal too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	if dec.Decode(new(any)) != io.EOF {
		return p, errors.New("trailing proposal JSON")
	}
	return p, nil
}

// ValidateReferences proves model citations join immutable existing evidence before attempting YAML repair.
func (p Proposal) ValidateReferences(r request.RuleRequest) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if p.Schema != 1 || p.RequestID != r.ID || len(p.Citations) == 0 || len(p.Citations) > 10000 || len(p.Uncertainty) > 100 {
		return errors.New("proposal schema, request identity or citations invalid")
	}
	known := map[string]bool{}
	for _, e := range r.Evidence {
		known[e.ID] = true
	}
	seen := map[string]bool{}
	for _, id := range p.Citations {
		if !known[id] || seen[id] {
			return fmt.Errorf("unknown or duplicate citation %q", id)
		}
		seen[id] = true
	}
	return nil
}

// Validate checks immutable references, rule syntax and mandatory script format constraints.
func (p Proposal) Validate(r request.RuleRequest) error {
	if err := p.ValidateReferences(r); err != nil {
		return err
	}
	rule, err := ParseRule(p.YAML)
	if err != nil {
		return err
	}
	if r.Language == "powershell" || r.Language == "python" || r.Language == "bash" {
		if !containsFormat(rule.Rule.Features, r.Language) {
			return errors.New("script rule must explicitly constrain its format")
		}
		if rule.Rule.Meta.Scopes.Static != "statement" && rule.Rule.Meta.Scopes.Static != "function" && rule.Rule.Meta.Scopes.Static != "file" {
			return errors.New("script rule requires script-compatible static scope")
		}
	}
	return nil
}

// containsFormat conservatively accepts only mandatory top-level conjunctions.
// A format nested beneath not, optional or or cannot constrain every matching branch.
func containsFormat(value any, language string) bool {
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if containsFormat(item, language) {
				return true
			}
		}
	case map[string]any:
		if format, ok := v["format"]; ok && format == language {
			return true
		}
		if and, ok := v["and"]; ok {
			return containsFormat(and, language)
		}
	}
	return false
}

var ruleFilename = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,180}\.yml$`)

// Filename follows capa's official filename lint and confines the result to a safe basename.
func Filename(rule Rule) (string, error) {
	name := strings.ToLower(rule.Rule.Meta.Name)
	name = strings.ReplaceAll(name, ".net", "dotnet")
	name = strings.ReplaceAll(name, " ", "-")
	for _, punctuation := range []string{"(", ")", "+", "/", "."} {
		name = strings.ReplaceAll(name, punctuation, "")
	}
	name += ".yml"
	if !ruleFilename.MatchString(name) {
		return "", errors.New("rule name does not yield a safe capa filename")
	}
	return name, nil
}
