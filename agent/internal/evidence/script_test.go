package evidence

import (
	"fmt"
	"strings"
	"testing"
)

func TestNativeScriptEvidenceOffsets(t *testing.T) {
	raw := fmt.Sprintf(`{"schema":1,"language":"powershell","sha256":"%s","byte_length":3,"extractor_version":"0.1.0","functions":[{"start_byte":0,"end_byte":3,"statements":[{"start_byte":0,"end_byte":3,"ordinal":0,"features":[{"kind":"script-call","value":"foo","start_byte":0,"end_byte":3,"source_node":"command","basis":"direct"}]}]}]}`, strings.Repeat("a", 64))
	b, err := ImportScript([]byte(raw))
	if err != nil || len(b.Features) != 1 || b.Features[0].Span.End != 3 {
		t.Fatal(b, err)
	}
	bad := strings.Replace(raw, `"end_byte":3,"source_node"`, `"end_byte":4,"source_node"`, 1)
	if _, err := ImportScript([]byte(bad)); err == nil {
		t.Fatal("fabricated span accepted")
	}
}
