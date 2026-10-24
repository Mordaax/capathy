package publish

import (
	"capathy/agent/internal/proposal"
	"capathy/agent/internal/request"
	"capathy/agent/internal/validate"
	"testing"
)

func TestRejectUnvalidatedPackageAndPublication(t *testing.T) {
	if _, err := Build(request.RuleRequest{}, proposal.Proposal{}, validate.Report{}, validate.Lock{}); err == nil {
		t.Fatal("unvalidated package accepted")
	}
	if Publish() == nil {
		t.Fatal("publication enabled")
	}
}

func TestTriageRefusesExistingBundle(t *testing.T) {
	dir := t.TempDir()
	if WriteTriage(dir, request.RuleRequest{}, proposal.Proposal{}, validate.Report{}) == nil {
		t.Fatal("existing output directory accepted")
	}
}
