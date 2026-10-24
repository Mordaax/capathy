package analyze

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/mandiant/capa/native/script/internal/protocol"
)

func calls(d protocol.Document) []string {
	var out []string
	for _, f := range d.Functions {
		for _, s := range f.Statements {
			for _, v := range s.Features {
				if v.Kind == "script-call" {
					out = append(out, v.Value.(string))
				}
			}
		}
	}
	return out
}
func TestLanguageFeatures(t *testing.T) {
	for _, tc := range []struct{ lang, code, want string }{
		{"powershell", "Invoke-WebRequest -Uri $u | Start-Process", "invoke-webrequest,start-process"},
		{"python", "import requests as r\nr.get(url)\n", "requests.get"},
		{"bash", "curl \"$url\" | sh\n", "curl,sh"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			d, err := Analyze(context.Background(), tc.lang, []byte(tc.code))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(calls(d), ","); got != tc.want {
				t.Fatalf("calls %q want %q", got, tc.want)
			}
			if err = d.ValidateSource([]byte(tc.code)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestNoInventedCalls(t *testing.T) {
	for _, tc := range []struct{ lang, code string }{
		{"powershell", "# Invoke-WebRequest\n'Invoke-WebRequest'\n& $cmd"},
		{"python", "# requests.get(url)\n'requests.get(url)'\ngetattr(obj,name)()"},
		{"bash", "# curl url\necho 'curl url'\n\"$cmd\" hi"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			d, err := Analyze(context.Background(), tc.lang, []byte(tc.code))
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range calls(d) {
				if c != "echo" {
					t.Fatalf("invented call %s", c)
				}
			}
			if len(d.Diagnostics) == 0 {
				t.Fatal("missing uncertainty")
			}
		})
	}
}
func TestStatementLocality(t *testing.T) {
	d, err := Analyze(context.Background(), "powershell", []byte("function F { Get-Item foo }; Write-Output hi; Start-Process there"))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Functions) != 2 {
		t.Fatalf("functions %#v", d.Functions)
	}
	if d.Functions[0].StartByte == d.Functions[1].StartByte {
		t.Fatal("function collision")
	}
	for _, f := range d.Functions {
		for _, s := range f.Statements {
			n := 0
			for _, v := range s.Features {
				if v.Kind == "script-call" {
					n++
				}
			}
			if n > 1 {
				t.Fatal("unrelated statements merged")
			}
		}
	}
}
func TestUTF16OriginalBytes(t *testing.T) {
	code := "# é😀\nInvoke-WebRequest hi"
	raw := []byte{0xff, 0xfe}
	for _, u := range utf16.Encode([]rune(code)) {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, u)
		raw = append(raw, b...)
	}
	d, err := Analyze(context.Background(), "powershell", raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Functions {
		for _, s := range f.Statements {
			for _, v := range s.Features {
				if v.Kind == "script-call" && v.StartByte != 14 {
					t.Fatalf("call original offset %d", v.StartByte)
				}
			}
		}
	}
}
func TestBounds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Analyze(ctx, "powershell", []byte("foo")); err == nil {
		t.Fatal("accepted canceled context")
	}
	if _, err := Analyze(context.Background(), "unknown", []byte("foo")); err == nil {
		t.Fatal("accepted language")
	}
	if _, err := Analyze(context.Background(), "powershell", make([]byte, 16<<20+1)); err == nil {
		t.Fatal("accepted huge input")
	}
}

func TestVariableReadsAndWrites(t *testing.T) {
	for _, tc := range []struct{ lang, code string }{
		{"powershell", "$x = 3; Write-Output \"$x\""},
		{"python", "x = 3\nprint(x)"},
		{"bash", "x=3\necho \"$x\""},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			d, err := Analyze(context.Background(), tc.lang, []byte(tc.code))
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, f := range d.Functions {
				for _, s := range f.Statements {
					for _, v := range s.Features {
						if v.Kind == "script-variable" && v.Value == "x" {
							seen[v.Access] = true
						}
					}
				}
			}
			if !seen["read"] || !seen["write"] {
				t.Fatalf("missing access %#v", seen)
			}
		})
	}
}
func TestBranchStatementsStayLocal(t *testing.T) {
	for _, tc := range []struct{ lang, code string }{
		{"powershell", "if ($ok) { Invoke-WebRequest foo; Start-Process bar }"},
		{"python", "if ok:\n a()\n b()\n"},
		{"bash", "if true; then curl url; sh script; fi"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			d, err := Analyze(context.Background(), tc.lang, []byte(tc.code))
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range d.Functions {
				for _, s := range f.Statements {
					n := 0
					for _, v := range s.Features {
						if v.Kind == "script-call" {
							n++
						}
					}
					if n > 1 {
						t.Fatalf("merged branch statements %#v", s)
					}
				}
			}
		})
	}
}
func TestPythonShadowedImport(t *testing.T) {
	for _, code := range []string{
		"import requests as r\ndef f(r):\n r.get(url)\n",
		"import requests as r\nr = other\nr.get(url)\n",
		"def f():\n import requests as r\nr.get(url)\n",
	} {
		d, err := Analyze(context.Background(), "python", []byte(code))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range calls(d) {
			if c == "requests.get" {
				t.Fatalf("resolved shadowed/out-of-scope alias: %s", code)
			}
		}
	}
}
func TestPowerShellUnicodeCaseFold(t *testing.T) {
	d, err := Analyze(context.Background(), "powershell", []byte("Straße $Straße"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls(d), ","); got != "strasse" {
		t.Fatalf("not Unicode folded: %s", got)
	}
}
func TestPowerShellStaticAlias(t *testing.T) {
	d, err := Analyze(context.Background(), "powershell", []byte("Set-Alias fetch Invoke-WebRequest; fetch hi"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls(d), ","); got != "set-alias,invoke-webrequest" {
		t.Fatalf("alias unresolved: %s", got)
	}
}
func TestAliasMutationNeverInventsTarget(t *testing.T) {
	for _, code := range []string{
		"Set-Alias iwr foo; Set-Alias iwr bar; iwr hi",
		"function iwr { Write-Output hello }; iwr hi",
		"Set-Alias fetch Invoke-WebRequest; if ($x) { Set-Alias fetch Write-Output }; fetch hi",
	} {
		d, err := Analyze(context.Background(), "powershell", []byte(code))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range calls(d) {
			if c == "invoke-webrequest" {
				t.Fatalf("ambiguous alias target resolved: %s", code)
			}
		}
	}
}
func TestMalformedInputHasBoundedDiagnostics(t *testing.T) {
	for _, tc := range []struct{ lang, code string }{
		{"powershell", "function Broken { Invoke-WebRequest 'unterminated"},
		{"python", "def broken(\n requests.get("},
		{"bash", "if true; then curl \"unterminated"},
	} {
		d, err := Analyze(context.Background(), tc.lang, []byte(tc.code))
		if err != nil {
			continue
		}
		if len(d.Diagnostics) == 0 {
			t.Fatalf("no diagnostic for malformed %s", tc.lang)
		}
		if err = d.ValidateSource([]byte(tc.code)); err != nil {
			t.Fatal(err)
		}
	}
}
func TestPythonSignedInteger(t *testing.T) {
	d, err := Analyze(context.Background(), "python", []byte("x=-5\n"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range d.Functions {
		for _, s := range f.Statements {
			for _, v := range s.Features {
				if v.Kind == "number" {
					if v.Value != int64(-5) {
						t.Fatalf("wrong signed integer %#v", v)
					}
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("missing signed integer")
	}
}
