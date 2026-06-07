package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mordaax/capathy/agent/internal/proposal"
	"github.com/Mordaax/capathy/agent/internal/publish"
	"github.com/Mordaax/capathy/agent/internal/request"
	"github.com/Mordaax/capathy/agent/internal/validate"
	"github.com/Mordaax/capathy/agent/internal/workflow"
)

type replayRunner struct {
	t        *testing.T
	lock     validate.Lock
	positive string
	failure  string
	scans    int
}

func (r *replayRunner) Run(ctx context.Context, c validate.Command) (validate.Log, error) {
	log := validate.Log{Command: c}
	if c.Program == "git" {
		switch c.Args[2] {
		case "rev-parse":
			log.Stdout = r.lock.RulesRevision
			if strings.Contains(c.Args[1], "capa") {
				log.Stdout = r.lock.CapaRevision
			}
		case "status":
			if r.failure == "dirty" {
				log.Stdout = " M tracked.py"
			}
		case "worktree":
			if c.Args[3] == "add" {
				if err := os.MkdirAll(c.Args[5], 0700); err != nil {
					return log, err
				}
			}
		}
		return log, nil
	}
	if c.Program != "trusted-python" {
		r.t.Fatal("unexpected tool", c)
	}
	if strings.HasSuffix(c.Args[0], "capafmt.py") && r.failure == "formatter" {
		return log, errors.New("formatter drift")
	}
	if strings.HasSuffix(c.Args[0], "lint.py") && r.failure == "lint" {
		return log, errors.New("lint failure")
	}
	if c.Args[0] == "-m" {
		r.scans++
		path := c.Args[len(c.Args)-1]
		if !filepath.IsAbs(path) {
			r.t.Fatal("scan path not normalized", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return log, err
		}
		hash := request.Hash(data)
		matches := hash == r.positive
		if r.failure == "negative" && hash != r.positive {
			matches = true
		}
		if r.failure == "positive" {
			matches = false
		}
		if r.failure == "hash" {
			hash = strings.Repeat("f", 64)
		}
		rules := map[string]any{}
		if matches {
			rules["test capability"] = map[string]any{"matches": []any{[]any{map[string]any{"type": "absolute", "value": 4096}, map[string]any{"success": true}}}}
		}
		b, err := json.Marshal(map[string]any{"meta": map[string]any{"sample": map[string]any{"sha256": hash}}, "rules": rules})
		if err != nil {
			return log, err
		}
		log.Stdout = string(b)
	}
	return log, nil
}
func replayFixture(t *testing.T) (request.RuleRequest, proposal.Proposal, validate.Options) {
	t.Helper()
	root := t.TempDir()
	r := request.RuleRequest{Schema: 1, ID: "replay", Origin: request.Origin{Kind: "manual"}, Capability: "test capability", Samples: []request.SampleRef{}, Evidence: []request.EvidenceRef{}}
	for i, role := range []string{"positive", "benign", "benign", "adversarial"} {
		path := filepath.Join(root, fmt.Sprintf("sample%d.bin", i))
		data := []byte(fmt.Sprintf("inert fixture %d", i))
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		relative, err := filepath.Rel(cwd, path)
		if err != nil {
			t.Fatal(err)
		}
		r.Samples = append(r.Samples, request.SampleRef{SHA256: request.Hash(data), Path: relative, Role: role, Shareable: true, Real: true, Language: "pe"})
	}
	r.Evidence = append(r.Evidence, request.EvidenceRef{ID: "e1", SampleSHA256: r.Samples[0].SHA256, Kind: "api", Value: "CreateProcess", CapaVersion: "10.0"})
	p := proposal.Proposal{Schema: 1, RequestID: r.ID, Citations: []string{"e1"}, YAML: "rule:\n  meta:\n    name: test capability\n    namespace: test/replay\n    scopes:\n      static: function\n  features:\n    - api: CreateProcess\n"}
	manifest := append([]request.SampleRef(nil), r.Samples...)
	for i := range manifest {
		manifest[i].Path = ""
	}
	lock := validate.Lock{CapaRevision: strings.Repeat("a", 40), RulesRevision: strings.Repeat("b", 40), AgentRevision: strings.Repeat("c", 40), SampleManifestHash: validate.DigestJSON(manifest)}
	opt := validate.Options{Python: "trusted-python", CapaRoot: filepath.Join(root, "capa"), RulesRoot: filepath.Join(root, "rules"), SamplesRoot: root, Lock: lock, SemanticReview: validate.SemanticReviewKey(p, lock)}
	return r, p, opt
}
func TestBinaryRuleFlowAndPackage(t *testing.T) {
	r, p, opt := replayFixture(t)
	draft, err := workflow.Draft(context.Background(), r, workflow.RecordedModel{Proposal: p})
	if err != nil {
		t.Fatal(err)
	}
	runner := &replayRunner{t: t, lock: opt.Lock, positive: r.Samples[0].SHA256}
	report, err := validate.Validate(context.Background(), r, draft, opt, runner)
	if err != nil || !report.Eligible || report.PositiveMatches != 1 || report.NegativeMatches != 0 || runner.scans != 4 {
		t.Fatal(report, err)
	}
	pkg, err := publish.Build(r, draft, report, opt.Lock)
	if err != nil || !strings.HasPrefix(pkg.Branch, "agent/") {
		t.Fatal(pkg, err)
	}
	directory := filepath.Join(t.TempDir(), "review")
	if err = publish.WriteTriage(directory, r, p, report); err != nil {
		t.Fatal(err)
	}
	if err = publish.WritePackage(directory, pkg); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(directory, "PR.md")); err != nil {
		t.Fatal(err)
	}
}
func TestFailedDeterministicGatesNeverPackage(t *testing.T) {
	for _, failure := range []string{"formatter", "lint", "negative", "positive", "hash", "dirty"} {
		t.Run(failure, func(t *testing.T) {
			r, p, opt := replayFixture(t)
			runner := &replayRunner{t: t, lock: opt.Lock, positive: r.Samples[0].SHA256, failure: failure}
			report, err := validate.Validate(context.Background(), r, p, opt, runner)
			if err != nil || report.Eligible {
				t.Fatal(report, err)
			}
			if _, err = publish.Build(r, p, report, opt.Lock); err == nil {
				t.Fatal("failed validation produced eligible package")
			}
		})
	}
}
