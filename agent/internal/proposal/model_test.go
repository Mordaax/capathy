package proposal

import (
	"capathy/agent/internal/request"
	"strings"
	"testing"
)

func TestDraftCitations(t *testing.T) {
	r := request.RuleRequest{Schema: 1, ID: "r", Origin: request.Origin{Kind: "manual"}, Capability: "download", Language: "powershell", Samples: []request.SampleRef{{SHA256: strings.Repeat("a", 64), Role: "positive"}}, Evidence: []request.EvidenceRef{{ID: "e1", SampleSHA256: strings.Repeat("a", 64), Kind: "script-call", Value: "invoke-webrequest", CapaVersion: "10"}}}
	p := Proposal{Schema: 1, RequestID: "r", Citations: []string{"e1"}, YAML: "rule:\n  meta:\n    name: download\n    scopes:\n      static: statement\n  features:\n    - and:\n      - format: powershell\n      - script-call: invoke-webrequest\n"}
	if err := p.Validate(r); err != nil {
		t.Fatal(err)
	}
	p.Citations = []string{"invented"}
	if p.Validate(r) == nil {
		t.Fatal("invented citation accepted")
	}
	if _, err := Decode([]byte(`{"schema":1,"command":"sh"}`)); err == nil {
		t.Fatal("model command accepted")
	}
}

func TestScriptFormatMustBeMandatory(t *testing.T) {
	for _, features := range []string{"- optional:\n      - format: powershell", "- not:\n      - format: powershell", "- or:\n      - format: powershell\n      - script-call: foo"} {
		r := request.RuleRequest{Schema: 1, ID: "r", Capability: "test", Origin: request.Origin{Kind: "manual"}, Language: "powershell", Samples: []request.SampleRef{{SHA256: strings.Repeat("a", 64), Role: "positive"}}, Evidence: []request.EvidenceRef{{ID: "e1", SampleSHA256: strings.Repeat("a", 64), Kind: "script-call", Value: "foo", CapaVersion: "10"}}}
		p := Proposal{Schema: 1, RequestID: "r", Citations: []string{"e1"}, YAML: "rule:\n  meta:\n    name: test\n    scopes:\n      static: statement\n  features:\n    " + features + "\n"}
		if p.Validate(r) == nil {
			t.Fatal("non-mandatory format accepted", features)
		}
	}
}

func TestCapaFilename(t *testing.T) {
	for _, tt := range []struct{ name, want string }{{"download a file", "download-a-file.yml"}, {"use .NET API (C++)", "use-dotnet-api-c.yml"}} {
		var rule Rule
		rule.Rule.Meta.Name = tt.name
		got, err := Filename(rule)
		if err != nil || got != tt.want {
			t.Fatal(got, err)
		}
	}
	var rule Rule
	rule.Rule.Meta.Name = "unsafe;touch"
	if _, err := Filename(rule); err == nil {
		t.Fatal("shell punctuation filename accepted")
	}
}
