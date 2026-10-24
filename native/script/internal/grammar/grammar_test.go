package grammar

import (
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

func TestPowerShellGrammarCoverage(t *testing.T) {
	for _, s := range []string{"Invoke-WebRequest -Uri $u | Start-Process", "function Test { Write-Output 'hi' }", "Get-ChildItem @args", "$x = \"hello $name\""} {
		t.Run(s, func(t *testing.T) {
			l, e := Language("powershell")
			if e != nil {
				t.Fatal(e)
			}
			p := sitter.NewParser()
			defer p.Close()
			if e = p.SetLanguage(l); e != nil {
				t.Fatal(e)
			}
			tree := p.Parse([]byte(s), nil)
			defer tree.Close()
			if tree.RootNode().HasError() {
				t.Fatalf("parse error: %s", tree.RootNode().ToSexp())
			}

			if !strings.Contains(tree.RootNode().ToSexp(), "pipeline") {
				t.Fatal("missing pipeline node")
			}
			if strings.HasPrefix(s, "function ") && !strings.Contains(tree.RootNode().ToSexp(), "function_statement") {
				t.Fatal("missing function node")
			}
		})
	}
	if _, e := Language("unknown"); e == nil {
		t.Fatal("accepted unknown language")
	}
}
func TestAliasGrammarCoverage(t *testing.T) {
	l, e := Language("powershell")
	if e != nil {
		t.Fatal(e)
	}
	p := sitter.NewParser()
	defer p.Close()
	if e = p.SetLanguage(l); e != nil {
		t.Fatal(e)
	}
	for _, source := range []string{"Set-Alias foo Invoke-WebRequest; foo hi", "Set-Alias -Name foo -Value Invoke-WebRequest", "New-Alias foo Invoke-WebRequest"} {
		tree := p.Parse([]byte(source), nil)
		if tree.RootNode().HasError() {
			t.Fatal(tree.RootNode().ToSexp())
		}
		tree.Close()
	}
}
