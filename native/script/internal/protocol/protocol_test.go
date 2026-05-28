package protocol

import (
	"encoding/json"
	"testing"
)

func valid() Document {
	d := New("powershell", []byte("foo"))
	d.Functions = []Function{{StartByte: 0, EndByte: 3, Name: "<top-level>", TopLevel: true, Statements: []Statement{{StartByte: 0, EndByte: 3, Features: []Feature{{Kind: "script-call", Value: "foo", Basis: "direct", SourceNode: "command", StartByte: 0, EndByte: 3}}}}}}
	return d
}
func TestProtocolRejectsInvalidEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Document)
	}{
		{"schema", func(d *Document) { d.Schema = 2 }},
		{"hash", func(d *Document) { d.SHA256 = "xx" }},
		{"language", func(d *Document) { d.Language = "ruby" }},
		{"statement-collision", func(d *Document) {
			d.Functions[0].Statements = append(d.Functions[0].Statements, d.Functions[0].Statements[0])
		}},
		{"span", func(d *Document) { d.Functions[0].Statements[0].Features[0].EndByte = 4 }},
		{"basis", func(d *Document) { d.Functions[0].Statements[0].Features[0].Basis = "model" }},
		{"value", func(d *Document) { d.Functions[0].Statements[0].Features[0].Value = 7 }},
		{"source-node", func(d *Document) { d.Functions[0].Statements[0].Features[0].SourceNode = "" }},
		{"variable", func(d *Document) { d.Functions[0].Statements[0].Features[0].Kind = "script-variable" }},
		{"structure", func(d *Document) {
			v := &d.Functions[0].Statements[0].Features[0]
			v.Kind = "script-structure"
			v.Value = "invented"
		}},
		{"digest-mismatch", func(d *Document) { d.SHA256 = New("powershell", []byte("bar")).SHA256 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := valid()
			tc.change(&d)
			if err := d.ValidateSource([]byte("foo")); err == nil {
				t.Fatal("accepted invalid evidence")
			}
		})
	}
}
func TestProtocolRoundTrip(t *testing.T) {
	d := valid()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var out Document
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if err = out.ValidateSource([]byte("foo")); err != nil {
		t.Fatal(err)
	}
}
