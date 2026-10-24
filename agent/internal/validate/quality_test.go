package validate

import (
	"capathy/agent/internal/proposal"
	"capathy/agent/internal/request"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (request.RuleRequest, proposal.Proposal, Lock) {
	t.Helper()
	r := request.RuleRequest{Schema: 1, ID: "r", Capability: "test", Origin: request.Origin{Kind: "manual"}}
	for i, role := range []string{"positive", "benign", "benign", "adversarial"} {
		r.Samples = append(r.Samples, request.SampleRef{SHA256: strings.Repeat(string(rune('a'+i)), 64), Path: filepath.Join(t.TempDir(), role), Role: role, Shareable: true, Real: true})
	}
	r.Evidence = []request.EvidenceRef{{ID: "e1", SampleSHA256: r.Samples[0].SHA256, Kind: "api", Value: "CreateProcess", CapaVersion: "10"}}
	p := proposal.Proposal{Schema: 1, RequestID: "r", Citations: []string{"e1"}, YAML: "rule:\n  meta:\n    name: test\n    scopes:\n      static: function\n  features:\n    - api: CreateProcess\n"}
	lock := Lock{CapaRevision: strings.Repeat("a", 40), RulesRevision: strings.Repeat("b", 40), AgentRevision: strings.Repeat("c", 40), SampleManifestHash: strings.Repeat("d", 64)}
	return r, p, lock
}
func TestQualityGate(t *testing.T) {
	r, p, lock := fixture(t)
	if err := QualityGate(r, p, lock); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		change func(*request.RuleRequest, *Lock)
	}{{"private", func(r *request.RuleRequest, l *Lock) { r.Samples[0].Shareable = false }}, {"synthetic", func(r *request.RuleRequest, l *Lock) { r.Samples[0].Real = false }}, {"missing negatives", func(r *request.RuleRequest, l *Lock) { r.Samples = r.Samples[:1] }}, {"missing lock", func(r *request.RuleRequest, l *Lock) { l.SampleManifestHash = "" }}} {
		t.Run(tt.name, func(t *testing.T) {
			r, p, l := fixture(t)
			tt.change(&r, &l)
			if QualityGate(r, p, l) == nil {
				t.Fatal("invalid request eligible")
			}
		})
	}
}

type noRun struct{ called bool }

func (n *noRun) Run(context.Context, Command) (Log, error) { n.called = true; return Log{}, nil }
func TestMissingRightsRunsNoTools(t *testing.T) {
	r, p, l := fixture(t)
	r.Samples[0].Shareable = false
	runner := &noRun{}
	report, err := Validate(context.Background(), r, p, Options{Lock: l}, runner)
	if err != nil || report.Eligible || runner.called {
		t.Fatal(report, err, "tools called", runner.called)
	}
}
func TestPathConfinement(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(outside, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := samplePath(root, outside); err == nil {
		t.Fatal("accepted external path")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := samplePath(root, link); err == nil {
		t.Fatal("accepted symlink")
	}
}
func TestRunnerNoShellAndOutputCaps(t *testing.T) {
	r := ExecRunner{MaxOutput: 4}
	log, err := r.Run(context.Background(), Command{Program: "printf", Args: []string{"%s", "$(touch /tmp/should-never-run)"}})
	if err == nil || len(log.Stdout) > 4 {
		t.Fatal("missing cap", log, err)
	}
	log, err = ExecRunner{}.Run(context.Background(), Command{Program: "printf", Args: []string{"%s", "literal; $HOME"}})
	if err != nil || log.Stdout != "literal; $HOME" {
		t.Fatal("arguments were evaluated", log, err)
	}
}
