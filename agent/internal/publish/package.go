// Package publish builds local review bundles. It never sends GitHub writes.
package publish

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mordaax/capathy/agent/internal/proposal"
	"github.com/Mordaax/capathy/agent/internal/request"
	"github.com/Mordaax/capathy/agent/internal/validate"
)

// Package is a deterministic proposed branch and review body bound to a validated rule.
type Package struct {
	Branch           string `json:"branch"`
	RulePath         string `json:"rule_path"`
	RuleYAML         string `json:"rule_yaml"`
	Body             string `json:"body"`
	ValidationSHA256 string `json:"validation_sha256"`
}

// Build refuses forged, stale, private, unvalidated or incomplete proposals.
func Build(r request.RuleRequest, p proposal.Proposal, report validate.Report, lock validate.Lock) (Package, error) {
	if err := validate.QualityGate(r, p, lock); err != nil {
		return Package{}, err
	}
	if !report.Eligible || report.Schema != 1 || report.RequestID != r.ID || report.RequestSHA256 != validate.DigestJSON(r) || report.RuleSHA256 != request.Hash([]byte(p.YAML)) || report.LockSHA256 != validate.DigestJSON(lock) || report.PositiveMatches < 1 || report.NegativeMatches != 0 {
		return Package{}, errors.New("report is ineligible or does not bind exact request, rule and lock")
	}
	required := map[string]bool{"quality": false, "sample manifest": false, "duplicate rule name": false, "formatter": false, "thorough linter": false, "exact sample matches": false, "semantic duplicate review": false}
	for _, check := range report.Checks {
		if !check.Passed {
			return Package{}, errors.New("validation check failed")
		}
		if _, ok := required[check.Name]; ok {
			required[check.Name] = true
		}
	}
	for name, ok := range required {
		if !ok {
			return Package{}, fmt.Errorf("missing required check %s", name)
		}
	}
	rule, err := proposal.ParseRule(p.YAML)
	if err != nil {
		return Package{}, err
	}
	filename, err := proposal.Filename(rule)
	if err != nil {
		return Package{}, err
	}
	hash := validate.DigestJSON(report)
	var body strings.Builder
	fmt.Fprintf(&body, "<!-- capa-rule-agent:%s -->\n\nCapability: %s\n\nValidation: %s\n\nTools: capa %s; rules %s; agent %s; helper %s\n\nPositive matches: %d; negative matches: %d\n\nEvidence:\n", r.Key(), r.Capability, hash, lock.CapaRevision, lock.RulesRevision, lock.AgentRevision, lock.HelperVersion, report.PositiveMatches, report.NegativeMatches)
	for _, e := range r.Evidence {
		fmt.Fprintf(&body, "- `%s`: %s, sample `%s`", e.ID, e.Kind, e.SampleSHA256)
		if e.Address != nil {
			fmt.Fprintf(&body, ", offset %d", *e.Address)
		}
		body.WriteString("\n")
	}
	if r.Origin.Kind == "issue" {
		fmt.Fprintf(&body, "\nOrigin issue: %s\n", r.Origin.URL)
	}
	for _, uncertainty := range p.Uncertainty {
		fmt.Fprintf(&body, "\nUncertainty: %s\n", uncertainty)
	}
	return Package{Branch: "agent/" + r.Key()[:24], RulePath: "nursery/" + filename, RuleYAML: p.YAML, Body: body.String(), ValidationSHA256: hash}, nil
}

// WriteTriage always writes a private local candidate/report bundle, clearly marked ineligible when gates fail.
func WriteTriage(directory string, r request.RuleRequest, p proposal.Proposal, report validate.Report) error {
	if err := os.MkdirAll(filepath.Dir(directory), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return fmt.Errorf("review bundle must be a new directory: %w", err)
	}
	files := map[string]any{"request.json": r, "proposal.json": p, "validation.json": report}
	for name, value := range files {
		b, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		if err = writeNew(filepath.Join(directory, name), append(b, '\n')); err != nil {
			return err
		}
	}
	return writeNew(filepath.Join(directory, "candidate.yml"), []byte(p.YAML))
}

// Publish is a fail-closed operator kill switch in the initial delivery.
func Publish() error {
	return errors.New("GitHub publication is disabled: GitHub publisher and sandbox publication gates are not implemented")
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// WritePackage adds review metadata only after Build has passed all deterministic and operator gates.
func WritePackage(directory string, p Package) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err = writeNew(filepath.Join(directory, "package.json"), append(data, '\n')); err != nil {
		return err
	}
	return writeNew(filepath.Join(directory, "PR.md"), []byte(p.Body))
}
