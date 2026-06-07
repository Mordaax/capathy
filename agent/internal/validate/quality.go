package validate

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mordaax/capathy/agent/internal/proposal"
	"github.com/Mordaax/capathy/agent/internal/request"
)

// Lock pins every relevant tool and sample manifest to independently reviewable revisions.
type Lock struct {
	CapaRevision       string `json:"capa_revision"`
	RulesRevision      string `json:"rules_revision"`
	AgentRevision      string `json:"agent_revision"`
	HelperVersion      string `json:"helper_version,omitempty"`
	ScriptSchema       int    `json:"script_schema,omitempty"`
	SampleManifestHash string `json:"sample_manifest_hash"`
}

// Options selects installed tools, pinned checkouts and an operator-owned sample corpus.
type Options struct {
	Python         string
	CapaRoot       string
	RulesRoot      string
	SamplesRoot    string
	Lock           Lock
	SemanticReview string
}

// Check is one deterministic gate and its result.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// Report is a local validation record bound to exact proposal, request and lock digests.
type Report struct {
	Schema          int     `json:"schema"`
	RequestID       string  `json:"request_id"`
	RequestSHA256   string  `json:"request_sha256"`
	RuleSHA256      string  `json:"rule_sha256"`
	LockSHA256      string  `json:"lock_sha256"`
	Checks          []Check `json:"checks"`
	PositiveMatches int     `json:"positive_matches"`
	NegativeMatches int     `json:"negative_matches"`
	Logs            []Log   `json:"logs"`
	Eligible        bool    `json:"eligible"`
	Reason          string  `json:"reason,omitempty"`
}

func (r *Report) check(name string, err error) {
	r.Checks = append(r.Checks, Check{Name: name, Passed: err == nil, Detail: errorString(err)})
	if err != nil {
		r.Eligible = false
		if r.Reason == "" {
			r.Reason = name + ": " + err.Error()
		}
	}
}
func errorString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// QualityGate enforces a real public positive and independently hashed benign/adversarial negatives.
func QualityGate(r request.RuleRequest, p proposal.Proposal, lock Lock) error {
	if err := p.Validate(r); err != nil {
		return err
	}
	if !request.ValidHash(lock.SampleManifestHash) || !validRevision(lock.CapaRevision) || !validRevision(lock.RulesRevision) || !validRevision(lock.AgentRevision) {
		return errors.New("complete pinned tool revisions and sample manifest hash required")
	}
	if r.Language == "powershell" || r.Language == "python" || r.Language == "bash" {
		if lock.HelperVersion == "" || lock.ScriptSchema != 1 {
			return errors.New("compatible script helper and schema required")
		}

		for _, e := range r.Evidence {
			if e.ExtractorVersion != lock.HelperVersion {
				return errors.New("script evidence extractor version does not match lock")
			}
		}
	}
	positives, benign, adversarial := 0, 0, 0
	for _, s := range r.Samples {
		if s.Path == "" {
			return errors.New("validation requires operator-supplied local sample paths")
		}
		if !s.Shareable {
			return errors.New("every validation sample must be rights-reviewed and shareable")
		}
		switch s.Role {
		case "positive":
			if !s.Real {
				return errors.New("synthetic-only positives cannot qualify")
			}
			positives++
		case "benign":
			benign++
		case "adversarial":
			adversarial++
		}
	}
	if positives < 1 || benign < 2 || adversarial < 1 {
		return errors.New("need at least one real public positive, two benign negatives and one adversarial negative")
	}
	return nil
}
func samplePath(root, path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	base, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(base, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", errors.New("sample is outside configured corpus")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", err
	}
	relative, err = filepath.Rel(resolvedBase, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", errors.New("sample symlink leaves corpus")
	}
	if resolved != absolute {
		return "", fmt.Errorf("symlink sample path rejected")
	}
	return absolute, nil
}

func validRevision(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && (len(b) == 20 || len(b) == 32) && value == strings.ToLower(value)
}

// SemanticReviewKey binds an operator's overlap review to the exact candidate and pinned rules corpus.
func SemanticReviewKey(p proposal.Proposal, lock Lock) string {
	return DigestJSON(struct {
		RuleSHA256    string `json:"rule_sha256"`
		RulesRevision string `json:"rules_revision"`
	}{request.Hash([]byte(p.YAML)), lock.RulesRevision})
}
