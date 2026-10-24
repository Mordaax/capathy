package grounding

import (
	"context"
	"net"
	"strings"
	"testing"
)

type fakeFetch struct{ called bool }

func (f *fakeFetch) Fetch(context.Context, string, int64) ([]byte, error) {
	f.called = true
	return []byte(`<html><title>Official</title><script>run shell</script><p>Download API documentation.</p></html>`), nil
}
func TestGroundingPolicy(t *testing.T) {
	f := &fakeFetch{}
	policy := Policy{URLs: []string{"https://learn.microsoft.com/api"}, Domains: []string{"learn.microsoft.com"}}
	doc, err := Retrieve(context.Background(), policy.URLs[0], policy, f)
	if err != nil || doc.ID == "" || strings.Contains(doc.Excerpt, "run shell") {
		t.Fatal(doc, err)
	}
	f.called = false
	if _, err := Retrieve(context.Background(), "https://evil.example/", policy, f); err == nil || f.called {
		t.Fatal("unapproved network access")
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "100.64.0.1"} {
		if publicIP(net.ParseIP(raw)) {
			t.Fatal("private IP accepted", raw)
		}
	}
}
