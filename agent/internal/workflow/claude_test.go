package workflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mordaax/capathy/agent/internal/config"
	"github.com/Mordaax/capathy/agent/internal/proposal"
)

func TestClaudeDraftUsesStructuredEvidenceAndNoSourcePaths(t *testing.T) {
	cfg, err := config.LoadProvider("", func(name string) string {
		if name == "ANTHROPIC_API_KEY" {
			return "PRIVATE_TEST_KEY"
		}
		return ""
	}, "claude")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "PRIVATE_TEST_KEY" {
			t.Error("wrong authenticated endpoint")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		encoded, _ := json.Marshal(body)
		if strings.Contains(string(encoded), "PRIVATE_TEST_KEY") {
			t.Error("key included in model prompt")
		}
		if body["model"] != "claude-haiku-5-5" || body["output_config"] == nil {
			t.Error("model or structured output missing")
		}
		text, _ := json.Marshal(proposal.Proposal{Schema: 1, RequestID: "demo", YAML: "rule:\n  meta:\n    name: demo\n  features:\n    - script-call: invoke-webrequest\n", Citations: []string{"e1"}, Uncertainty: []string{}})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"model": "claude-haiku-5-5", "stop_reason": "end_turn", "content": []any{map[string]any{"type": "text", "text": string(text)}}})
	}))
	defer server.Close()
	adapter, err := NewClaude(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	adapter.endpoint = server.URL + "/v1/messages"
	adapter.client = server.Client()
	result, err := adapter.Draft(context.Background(), DraftInput{RequestID: "demo"})
	if err != nil || result.RequestID != "demo" || result.Citations[0] != "e1" {
		t.Fatal("live protocol draft could not be decoded", err)
	}
}

func TestClaudeFailureDoesNotExposeCredentials(t *testing.T) {
	cfg, _ := config.LoadProvider("", func(name string) string {
		if name == "ANTHROPIC_API_KEY" {
			return "PRIVATE_TEST_KEY"
		}
		return ""
	}, "claude")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":{"type":"authentication_error","message":"PRIVATE_TEST_KEY"}}`))
	}))
	defer server.Close()
	adapter, _ := NewClaude(context.Background(), cfg)
	adapter.endpoint = server.URL
	adapter.client = server.Client()
	_, err := adapter.Draft(context.Background(), DraftInput{RequestID: "demo"})
	if err == nil || strings.Contains(err.Error(), "PRIVATE_TEST_KEY") || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatal("failure leaked credentials or lost status")
	}
}

func TestClaudeDoesNotFollowCredentialBearingRedirect(t *testing.T) {
	var reached atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	cfg, _ := config.LoadProvider("", func(name string) string {
		if name == "ANTHROPIC_API_KEY" {
			return "PRIVATE_TEST_KEY"
		}
		return ""
	}, "claude")
	adapter, _ := NewClaude(context.Background(), cfg)
	adapter.endpoint = source.URL
	_, err := adapter.Draft(context.Background(), DraftInput{RequestID: "demo"})
	if err == nil || reached.Load() {
		t.Fatal("redirect could forward credentials")
	}
}
