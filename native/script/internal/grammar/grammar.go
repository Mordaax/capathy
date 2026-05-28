// Package grammar provides the statically linked, pinned script grammars.
package grammar

import (
	"fmt"
	sitter "github.com/tree-sitter/go-tree-sitter"
	bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	ps "github.com/wharflab/tree-sitter-powershell/bindings/go"
)

// Language selects an exact protocol language name.
func Language(name string) (*sitter.Language, error) {
	switch name {
	case "powershell":
		return sitter.NewLanguage(ps.Language()), nil
	case "python":
		return sitter.NewLanguage(python.Language()), nil
	case "bash":
		return sitter.NewLanguage(bash.Language()), nil
	}
	return nil, fmt.Errorf("unsupported language: %s", name)
}
