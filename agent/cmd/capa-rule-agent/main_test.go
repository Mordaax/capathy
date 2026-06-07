package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineDraftAndKillSwitch(t *testing.T) {
	sample := filepath.Join(t.TempDir(), "sample.ps1")
	if err := os.WriteFile(sample, []byte("Write-Host 'safe'"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"draft", "--sample", sample, "--capability", "print text", "--dry-run"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"sha256"`) || strings.Contains(out.String(), "Write-Host") {
		t.Fatal("source leaked or request missing", out.String())
	}
	if run(context.Background(), []string{"publish"}, &out) == nil {
		t.Fatal("publication enabled")
	}
}
