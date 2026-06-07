package evidence

import (
	"fmt"
	"strings"
	"testing"
)

func TestCapaEvidence(t *testing.T) {
	raw := fmt.Sprintf(`{"meta":{"version":"10.0.0","sample":{"sha256":"%s"},"analysis":{"format":"pe"}},"rules":{"test":{"matches":[[{"type":"file","value":0},{"success":true,"node":{"type":"feature","feature":{"type":"api","api":"CreateProcess"}},"locations":[{"type":"file","value":12}],"children":[]}]]}}}`, strings.Repeat("a", 64))
	b, err := Import([]byte(raw))
	if err != nil || len(b.Features) != 1 || *b.Features[0].Address != 12 {
		t.Fatal(b, err)
	}
	b2, err := Import([]byte(raw))
	if err != nil || b.Features[0].ID != b2.Features[0].ID {
		t.Fatal("unstable ID")
	}
	if _, err := Import([]byte(`{"meta":{"sample":{"sha256":"bad"}}}`)); err == nil {
		t.Fatal("missing evidence provenance accepted")
	}
}
