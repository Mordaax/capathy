package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigPrecedenceAndRedaction(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(p, []byte("GOOGLE_API_KEY=file-secret\nGEMINI_API_KEY=other-file-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p, func(k string) string {
		if k == "GEMINI_API_KEY" {
			return "process-secret"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey.Reveal() != "process-secret" {
		t.Fatal("process environment must take precedence")
	}
	b, _ := json.Marshal(cfg)
	if strings.Contains(string(b), "secret") || strings.Contains(fmt.Sprintf("%+v", cfg), "secret") {
		t.Fatal("secret exposed")
	}
	if _, err := Load("", func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultModelUsesCurrentFlash(t *testing.T) {
	cfg, err := Load("", func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ModelName != "gemini-3.8-flash" {
		t.Fatalf("unsupported default model: %s", cfg.ModelName)
	}
}

func TestClaudeProviderSelectsOnlyClaudeCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("GEMINI_API_KEY=google-only\nANTHROPIC_API_KEY=claude-file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadProvider(path, func(string) string { return "" }, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != "claude" || cfg.ModelName != "claude-haiku-5-5" || cfg.APIKey.Reveal() != "claude-file" {
		t.Fatal("Claude provider selected wrong model or credential")
	}
	cfg, err = LoadProvider(path, func(name string) string {
		if name == "CLAUDE_API_KEY" {
			return "claude-process"
		}
		return ""
	}, "claude")
	if err != nil || cfg.APIKey.Reveal() != "claude-process" {
		t.Fatal("process Claude key did not take precedence")
	}
	if _, err = LoadProvider(path, func(string) string { return "" }, "unknown"); err == nil {
		t.Fatal("unknown provider accepted")
	}
}
