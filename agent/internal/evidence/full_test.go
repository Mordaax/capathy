package evidence

import (
	"strings"
	"testing"
)

func TestFullUnmatchedFeatures(t *testing.T) {
	data := []byte(`{"schema":1,"kind":"capathy.features","sample":{"sha256":"` + strings.Repeat("a", 64) + `","byte_length":100},"analysis":{"format":"elf","capa_version":"9","extractor":"test","runtime_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","complete":true},"functions":[{"address":{"type":"absolute","value":4096}}],"features":[{"kind":"api","value":"unmatched","scope":"instruction","address":{"type":"absolute","value":4097},"function":{"type":"absolute","value":4096},"basic_block":{"type":"absolute","value":4096},"feature":{"type":"api","api":"unmatched"}}],"diagnostics":[]}`)
	b, err := ImportFull(data)
	if err != nil {
		t.Fatal(err)
	}
	if b.Features[0].RuntimeRevision != strings.Repeat("b", 40) {
		t.Fatal("lost engine revision")
	}
	if len(b.Features) != 1 || b.Features[0].Value != "unmatched" || b.Features[0].Scope != "instruction" {
		t.Fatal(b)
	}
	for _, bad := range []string{strings.Replace(string(data), `"schema":1`, `"schema":2`, 1), strings.Replace(string(data), `"complete":true`, `"complete":false`, 1), string(data) + `{}`} {
		if _, err := ImportFull([]byte(bad)); err == nil {
			t.Fatal("accepted invalid export")
		}
	}
}
