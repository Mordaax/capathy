package workflow

import (
	"github.com/Mordaax/capathy/agent/internal/proposal"
	"github.com/Mordaax/capathy/agent/internal/request"
	"context"
	"strings"
	"testing"
)

type repairModel struct {
	candidate proposal.Proposal
	calls     int
}

func (m *repairModel) Draft(context.Context, DraftInput) (proposal.Proposal, error) {
	m.calls++
	next := m.candidate
	next.YAML += "\n# syntax correction"
	return next, nil
}

type repairValidator struct {
	failure string
	calls   int
	always  bool
}

func (v *repairValidator) Check(context.Context, proposal.Proposal) ([]Failure, error) {
	v.calls++
	if v.calls == 1 || v.always {
		return []Failure{{Kind: v.failure, Detail: "inert diagnostics"}}, nil
	}
	return nil, nil
}
func repairFixture() (request.RuleRequest, proposal.Proposal) {
	hash := strings.Repeat("a", 64)
	r := request.RuleRequest{Schema: 1, ID: "r", Capability: "test", Origin: request.Origin{Kind: "manual"}, Samples: []request.SampleRef{{SHA256: hash, Role: "positive"}}, Evidence: []request.EvidenceRef{{ID: "e1", SampleSHA256: hash, Kind: "api", Value: "CreateProcess", CapaVersion: "10"}}}
	p := proposal.Proposal{Schema: 1, RequestID: "r", Citations: []string{"e1"}, YAML: "rule:\n  meta:\n    name: test\n  features:\n    - api: CreateProcess\n"}
	return r, p
}
func TestRepairBudget(t *testing.T) {
	r, p := repairFixture()
	m := &repairModel{candidate: p}
	v := &repairValidator{failure: "lint"}
	if _, _, err := Repair(context.Background(), r, p, m, v); err != nil || m.calls != 1 || v.calls != 2 {
		t.Fatal("repair should pass second validation", m.calls, v.calls, err)
	}
	m = &repairModel{candidate: p}
	v = &repairValidator{failure: "negative sample"}
	if _, _, err := Repair(context.Background(), r, p, m, v); err == nil || m.calls != 0 {
		t.Fatal("sample failure must never repair", err)
	}
	m = &repairModel{candidate: p}
	v = &repairValidator{failure: "lint", always: true}
	if _, _, err := Repair(context.Background(), r, p, m, v); err == nil || m.calls > 2 || v.calls > 3 {
		t.Fatal("repair budget unbounded", err)
	}
}
