package publish

import (
	"github.com/Mordaax/capathy/agent/internal/proposal"
	"github.com/Mordaax/capathy/agent/internal/request"
	"github.com/Mordaax/capathy/agent/internal/validate"
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
