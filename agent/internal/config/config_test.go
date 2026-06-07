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
