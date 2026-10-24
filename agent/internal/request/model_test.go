package request

import (
	"strings"
	"testing"
)

func fixture() RuleRequest {
	return RuleRequest{Schema: 1, ID: "test", Origin: Origin{Kind: "manual"}, Capability: "download", Samples: []SampleRef{{SHA256: strings.Repeat("a", 64), Role: "positive", Shareable: true, Real: true}}, Evidence: []EvidenceRef{{ID: "e1", SampleSHA256: strings.Repeat("a", 64), Kind: "script-call", Value: "invoke-webrequest", CapaVersion: "10"}}}
}
func TestRequestValidation(t *testing.T) {
	r := fixture()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*RuleRequest)
	}{
		{"schema", func(r *RuleRequest) { r.Schema = 2 }},
		{"hash", func(r *RuleRequest) { r.Samples[0].SHA256 = "x" }},
		{"duplicate", func(r *RuleRequest) { r.Evidence = append(r.Evidence, r.Evidence[0]) }},
		{"remote path", func(r *RuleRequest) { r.Origin.Kind = "issue"; r.Samples[0].Path = "/etc/passwd" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := fixture()
			tt.mutate(&r)
			if r.Validate() == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
}
func TestStableKey(t *testing.T) {
	a := fixture()
	b := fixture()
	b.ID = "other"
	if a.Key() != b.Key() {
		t.Fatal("key must not depend on transient request ID")
	}
}
