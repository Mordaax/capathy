package workflow

import (
	"capathy/agent/internal/proposal"
	"capathy/agent/internal/request"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type spy struct{ t *testing.T }

func (s spy) Draft(ctx context.Context, in DraftInput) (proposal.Proposal, error) {
	b, _ := json.Marshal(in)
	if strings.Contains(string(b), "private") || strings.Contains(string(b), "sourcebytes") {
		s.t.Fatal("local private contents or paths in prompt")
	}
	return proposal.Proposal{Schema: 1, RequestID: in.RequestID, Citations: []string{"fabricated"}, YAML: "rule:\n  meta:\n    name: test\n  features:\n    - string: test\n"}, nil
}
func TestEvidenceOnlyInputAndCitationGate(t *testing.T) {
	hash := strings.Repeat("a", 64)
	r := request.RuleRequest{Schema: 1, ID: "r", Capability: "test", Origin: request.Origin{Kind: "manual"}, Samples: []request.SampleRef{{SHA256: hash, Path: "/private/sourcebytes", Role: "positive"}}, Evidence: []request.EvidenceRef{{ID: "e1", SampleSHA256: hash, Kind: "string", Value: "observed", CapaVersion: "10"}}}
	if _, err := Draft(context.Background(), r, spy{t}); err == nil {
		t.Fatal("fabricated evidence accepted")
	}
}
