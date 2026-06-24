// Package grammar provides the statically linked, pinned script grammars.
package grammar

import (
	"fmt"
	sitter "github.com/tree-sitter/go-tree-sitter"
	bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
	c "github.com/tree-sitter/tree-sitter-c/bindings/go"
	cpp "github.com/tree-sitter/tree-sitter-cpp/bindings/go"
	js "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	ts "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
	ps "github.com/wharflab/tree-sitter-powershell/bindings/go"
)

// Language selects an exact protocol language name.
func Language(name string) (*sitter.Language, error) {
	switch name {
	case "javascript":
		return sitter.NewLanguage(js.Language()), nil
	case "typescript":
		return sitter.NewLanguage(ts.LanguageTypescript()), nil
	case "c":
		return sitter.NewLanguage(c.Language()), nil
	case "cpp":
		return sitter.NewLanguage(cpp.Language()), nil
	case "powershell":
		return sitter.NewLanguage(ps.Language()), nil
	case "python":
		return sitter.NewLanguage(python.Language()), nil
	case "bash":
		return sitter.NewLanguage(bash.Language()), nil
	}
	return nil, fmt.Errorf("unsupported language: %s", name)
}
