package intake

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestManualIntake(t *testing.T) {
	p := filepath.Join(t.TempDir(), "input.ps1")
	if err := os.WriteFile(p, []byte("Write-Host 'safe'"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := FromLocal(context.Background(), p, "print text", false)
	if err != nil || r.Samples[0].Path != p || r.Samples[0].Shareable {
		t.Fatal(r, err)
	}
	symlink := p + ".link"
	if err := os.Symlink(p, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := FromLocal(context.Background(), symlink, "test", false); err == nil {
		t.Fatal("accepted symlink")
	}
	if _, err := FromLocal(context.Background(), filepath.Dir(p), "test", false); err == nil {
		t.Fatal("accepted directory")
	}
}
