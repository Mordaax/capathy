package workflow

import (
	"testing"

	"github.com/Mordaax/capathy/agent/internal/request"
)

func TestProposalSchemaBindsIdentityAndEvidence(t *testing.T) {
	schema := proposalSchema(DraftInput{RequestID: "request-1", Evidence: []request.EvidenceRef{{ID: "observed-1"}, {ID: "observed-2"}}})
	if schema["additionalProperties"] != false {
		t.Fatal("model response may introduce arbitrary fields")
	}
	properties := schema["properties"].(map[string]any)
	identity := properties["request_id"].(map[string]any)["enum"].([]string)
	if len(identity) != 1 || identity[0] != "request-1" {
		t.Fatal("request identity is not bound")
	}
	citations := properties["citations"].(map[string]any)["items"].(map[string]any)["enum"].([]string)
	if len(citations) != 2 || citations[0] != "observed-1" || citations[1] != "observed-2" {
		t.Fatal("fabricated citations are not constrained")
	}
}
