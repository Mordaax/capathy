// Package extract implements conservative AST evidence extraction shared by script adapters.
package extract

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Mordaax/capathy/native/script/internal/grammar"
	"github.com/Mordaax/capathy/native/script/internal/protocol"
	"github.com/Mordaax/capathy/native/script/internal/source"
	sitter "github.com/tree-sitter/go-tree-sitter"
	"golang.org/x/text/cases"
)

const maxNodes = 500000

type walker struct {
	ctx            context.Context
	lang           string
	src            source.Source
	doc            protocol.Document
	ordinals       map[uint32]uint32
	aliases        map[string]string
	unsafeAliases  bool
	aliasPositions map[string]uint
	nodes          int
}

// Extract parses source without execution and emits source-local observations.
func Extract(ctx context.Context, src source.Source, language string) (protocol.Document, error) {
	d := protocol.New(language, src.Raw)
	if err := ctx.Err(); err != nil {
		return d, err
	}
	lang, err := grammar.Language(language)
	if err != nil {
		return d, err
	}
	parser := sitter.NewParser()
	defer parser.Close()
	if err = parser.SetLanguage(lang); err != nil {
		return d, fmt.Errorf("set grammar: %w", err)
	}
	tree := parser.ParseWithOptions(func(at int, _ sitter.Point) []byte {
		if ctx.Err() != nil || at >= len(src.Text) {
			return nil
		}
		return src.Text[at:]
	}, nil, &sitter.ParseOptions{ProgressCallback: func(_ sitter.ParseState) bool { return ctx.Err() != nil }})
	if err = ctx.Err(); err != nil {
		return d, err
	}
	if tree == nil {
		return d, errors.New("parse interrupted")
	}
	defer tree.Close()
	w := walker{ctx: ctx, lang: language, src: src, doc: d, ordinals: map[uint32]uint32{}, aliases: map[string]string{}, aliasPositions: map[string]uint{}}
	root := tree.RootNode()
	if err = w.walk(root, 0, func(n *sitter.Node) error {
		if n.IsError() || n.IsMissing() {
			w.diagnostic(n, "parse-error", "malformed syntax; evidence under ERROR nodes is omitted")
		}
		return nil
	}); err != nil {
		return d, err
	}
	if language == "python" {
		w.pythonImports(root)
	}
	if language == "powershell" {
		w.powerShellAliases(root)
	}
	var functions []*sitter.Node
	if err = w.walk(root, 0, func(n *sitter.Node) error {
		if w.isFunction(n) {
			functions = append(functions, n)
		}
		return nil
	}); err != nil {
		return d, err
	}
	for _, n := range functions {
		f := protocol.Function{StartByte: w.offset(n.StartByte()), EndByte: w.offset(n.EndByte()), Name: w.functionName(n), Statements: []protocol.Statement{}}
		header := protocol.Statement{StartByte: f.StartByte, EndByte: f.EndByte, Ordinal: w.ordinals[f.StartByte], Features: []protocol.Feature{}}
		w.ordinals[f.StartByte]++
		w.structure(&header, n, "function-definition")
		f.Statements = append(f.Statements, header)
		body := n.ChildByFieldName("body")
		if body == nil {
			for i := uint(0); i < n.NamedChildCount(); i++ {
				c := n.NamedChild(i)
				if c.Kind() == "script_block" {
					body = c
					break
				}
			}
		}
		if body != nil {
			if err = w.collect(body, &f, 0); err != nil {
				return d, err
			}
		}
		w.doc.Functions = append(w.doc.Functions, f)
	}
	top := protocol.Function{Name: "<top-level>", TopLevel: true, Statements: []protocol.Statement{}}
	if err = w.collect(root, &top, 0); err != nil {
		return d, err
	}
	if len(top.Statements) > 0 {
		top.StartByte = top.Statements[0].StartByte
		top.EndByte = uint32(len(src.Raw))
		w.doc.Functions = append(w.doc.Functions, top)
	}
	sort.Slice(w.doc.Functions, func(i, j int) bool { return w.doc.Functions[i].StartByte < w.doc.Functions[j].StartByte })
	if err = w.doc.ValidateSource(src.Raw); err != nil {
		return d, fmt.Errorf("validate extracted evidence: %w", err)
	}
	return w.doc, nil
}

func (w *walker) walk(n *sitter.Node, depth int, fn func(*sitter.Node) error) error {
	if n == nil {
		return nil
	}
	w.nodes++
	if w.nodes > maxNodes || depth > 512 {
		return errors.New("AST complexity limit exceeded")
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if err := fn(n); err != nil {
		return err
	}
	if n.IsError() || n.IsMissing() {
		return nil
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if err := w.walk(n.NamedChild(i), depth+1, fn); err != nil {
			return err
		}
	}
	return nil
}
func (w *walker) offset(at uint) uint32 { v, _ := w.src.OriginalOffset(uint32(at)); return v }
func (w *walker) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(w.src.Text)
}
func (w *walker) diagnostic(n *sitter.Node, code, msg string) {
	if len(w.doc.Diagnostics) >= 10000 {
		return
	}
	w.doc.Diagnostics = append(w.doc.Diagnostics, protocol.Diagnostic{Code: code, Message: msg, StartByte: w.offset(n.StartByte()), EndByte: w.offset(n.EndByte())})
}
func (w *walker) isFunction(n *sitter.Node) bool {
	return n.Kind() == "function_definition" || n.Kind() == "function_statement"
}
func (w *walker) functionName(n *sitter.Node) string {
	name := n.ChildByFieldName("name")
	if name != nil {
		return w.text(name)
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if c.Kind() == "function_name" {
			return w.text(c)
		}
	}
	return "<anonymous>"
}
func (w *walker) isStatement(n *sitter.Node) bool {
	k := n.Kind()
	switch w.lang {
	case "powershell":
		return k == "pipeline" || k == "if_statement" || k == "foreach_statement" || k == "for_statement" || k == "while_statement" || k == "do_statement" || k == "try_statement" || k == "switch_statement" || k == "return_statement" || k == "throw_statement"
	case "python":
		return k == "expression_statement" || k == "return_statement" || k == "raise_statement" || k == "import_statement" || k == "import_from_statement" || k == "if_statement" || k == "for_statement" || k == "while_statement" || k == "try_statement" || k == "with_statement" || k == "assert_statement" || k == "delete_statement"
	case "bash":
		return k == "command" || k == "pipeline" || k == "variable_assignment" || k == "if_statement" || k == "for_statement" || k == "while_statement" || k == "case_statement" || k == "redirected_statement"
	}
	return false
}
func (w *walker) isContainer(n *sitter.Node) bool {
	k := n.Kind()
	return k == "block" || k == "statement_list" || k == "script_block" || k == "script_block_body" || k == "compound_statement" || k == "do_group" || k == "else_clause" || k == "elif_clause" || k == "catch_clause" || k == "finally_clause"
}
func (w *walker) splitChildren(n *sitter.Node) bool {
	switch n.Kind() {
	case "if_statement", "switch_statement", "case_statement", "foreach_statement", "for_statement", "while_statement", "do_statement", "try_statement", "with_statement":
		return true
	}
	return false
}
func (w *walker) collect(n *sitter.Node, f *protocol.Function, depth int) error {
	if n == nil || w.isFunction(n) || n.IsError() || n.IsMissing() {
		return nil
	}
	if depth > 512 {
		return errors.New("statement nesting limit exceeded")
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.isStatement(n) {
		s := protocol.Statement{StartByte: w.offset(n.StartByte()), EndByte: w.offset(n.EndByte()), Features: []protocol.Feature{}}
		s.Ordinal = w.ordinals[s.StartByte]
		w.ordinals[s.StartByte]++
		if err := w.features(n, n, &s, 0); err != nil {
			return err
		}
		f.Statements = append(f.Statements, s)
		// Bodies receive their own statement scopes; pipeline components share a scope.
		var descend func(*sitter.Node, int) error
		descend = func(child *sitter.Node, d int) error {
			if d > 512 {
				return errors.New("statement nesting limit exceeded")
			}
			for i := uint(0); i < child.NamedChildCount(); i++ {
				c := child.NamedChild(i)
				if w.isContainer(c) || (w.splitChildren(n) && w.isStatement(c)) {
					if err := w.collect(c, f, depth+1); err != nil {
						return err
					}
				} else if !w.isStatement(c) && !w.isFunction(c) {
					if err := descend(c, d+1); err != nil {
						return err
					}
				}
			}
			return nil
		}
		return descend(n, 0)
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if err := w.collect(n.NamedChild(i), f, depth+1); err != nil {
			return err
		}
	}
	return nil
}
func (w *walker) add(s *protocol.Statement, n *sitter.Node, kind string, value any, access, basis string) {
	if n == nil || n.StartByte() == n.EndByte() {
		return
	}
	s.Features = append(s.Features, protocol.Feature{Kind: kind, Value: value, Access: access, Basis: basis, SourceNode: n.Kind(), StartByte: w.offset(n.StartByte()), EndByte: w.offset(n.EndByte())})
}
func (w *walker) structure(s *protocol.Statement, n *sitter.Node, value string) {
	w.add(s, n, "script-structure", value, "", "direct")
}
func (w *walker) features(root, n *sitter.Node, s *protocol.Statement, depth int) error {
	if n == nil || n.IsError() || n.IsMissing() || w.isFunction(n) {
		return nil
	}
	if depth > 512 {
		return errors.New("feature nesting limit exceeded")
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if n != root && (w.isContainer(n) || (w.splitChildren(root) && w.isStatement(n))) {
		return nil
	}
	k := n.Kind()
	switch k {
	case "assignment_expression", "assignment", "augmented_assignment", "variable_assignment":
		w.structure(s, n, "assignment")
	case "pipeline":
		if strings.Contains(w.text(n), "|") {
			w.structure(s, n, "pipeline")
		}
	case "if_statement", "switch_statement", "case_statement":
		w.structure(s, n, "branch")
	case "foreach_statement", "for_statement", "while_statement", "do_statement":
		w.structure(s, n, "loop")
	case "try_statement":
		w.structure(s, n, "try")
	case "file_redirect", "redirection", "redirected_statement":
		w.structure(s, n, "redirection")
	case "command_substitution":
		w.structure(s, n, "command-substitution")
	}
	if w.lang == "powershell" {
		w.powerShellFeature(n, s)
	} else if w.lang == "python" {
		w.pythonFeature(n, s)
	} else {
		w.bashFeature(n, s)
	}
	if k == "comment" {
		return nil
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if err := w.features(root, n.NamedChild(i), s, depth+1); err != nil {
			return err
		}
	}
	return nil
}

var psAliases = map[string]string{"iwr": "invoke-webrequest", "iex": "invoke-expression", "irm": "invoke-restmethod", "saps": "start-process", "echo": "write-output", "cat": "get-content", "gci": "get-childitem", "ls": "get-childitem", "dir": "get-childitem"}

func (w *walker) powerShellAliases(root *sitter.Node) {
	counts := map[string]int{}
	_ = w.walk(root, 0, func(n *sitter.Node) error {
		if w.isFunction(n) {
			if _, ok := psAliases[cases.Fold().String(w.functionName(n))]; ok {
				w.unsafeAliases = true
			}
			return nil
		}
		if n.Kind() != "command" {
			return nil
		}
		name := n.ChildByFieldName("command_name")
		if name == nil {
			return nil
		}
		command := cases.Fold().String(w.text(name))
		if command == "remove-item" || command == "set-item" || command == "remove-alias" {
			w.unsafeAliases = true
			return nil
		}
		if command != "set-alias" && command != "new-alias" {
			return nil
		}
		for p := n.Parent(); p != nil; p = p.Parent() {
			switch p.Kind() {
			case "pipeline_chain", "pipeline", "statement_list", "program":
			default:
				w.unsafeAliases = true
				return nil
			}
		}
		elements := n.ChildByFieldName("command_elements")
		if elements == nil {
			w.unsafeAliases = true
			return nil
		}
		args := []string{}
		for i := uint(0); i < elements.NamedChildCount(); i++ {
			child := elements.NamedChild(i)
			if child.Kind() == "command_argument_sep" {
				continue
			}
			if child.Kind() != "generic_token" && child.Kind() != "command_parameter" {
				w.unsafeAliases = true
				return nil
			}
			args = append(args, cases.Fold().String(w.text(child)))
		}
		var alias, target string
		if len(args) == 2 {
			alias, target = args[0], args[1]
		} else if len(args) == 4 && args[0] == "-name" && args[2] == "-value" {
			alias, target = args[1], args[3]
		} else {
			w.unsafeAliases = true
			return nil
		}
		if strings.ContainsAny(alias+target, "$@`{}()[];|& ") {
			w.unsafeAliases = true
			return nil
		}
		counts[alias]++
		w.aliases[alias] = target
		w.aliasPositions[alias] = n.EndByte()
		return nil
	})
	for alias, count := range counts {
		if count != 1 {
			delete(w.aliases, alias)
			w.unsafeAliases = true
		}
	}
}

func (w *walker) powerShellFeature(n *sitter.Node, s *protocol.Statement) {
	switch n.Kind() {
	case "command":
		name := n.ChildByFieldName("command_name")
		if name == nil || name.Kind() != "command_name" {
			w.diagnostic(n, "dynamic-call", "computed PowerShell command target is unresolved")
			return
		}
		value := cases.Fold().String(w.text(name))
		if value == "powershell" || value == "powershell.exe" || value == "pwsh" || value == "pwsh.exe" {
			elements := n.ChildByFieldName("command_elements")
			if elements != nil {
				for i := uint(0); i < elements.NamedChildCount(); i++ {
					c := elements.NamedChild(i)
					v := cases.Fold().String(w.text(c))
					if c.Kind() == "command_parameter" && (v == "-encodedcommand" || v == "-enc" || v == "-e") {
						w.diagnostic(c, "encoded-payload", "encoded payload is not decoded or executed")
					}
				}
			}
		}
		basis := "direct"
		if !w.unsafeAliases {
			if alias, ok := w.aliases[value]; ok && w.aliasPositions[value] < n.StartByte() {
				value = alias
				basis = "static-alias"
			} else if alias, ok := psAliases[value]; ok {
				value = alias
				basis = "static-alias"
			}
		}
		w.add(s, name, "script-call", value, "", basis)
	case "variable":
		value := w.text(n)
		if strings.HasPrefix(value, "@") {
			w.diagnostic(n, "splatting", "splatting arguments are unresolved")
			return
		}
		value = cases.Fold().String(strings.TrimPrefix(value, "$"))
		value = strings.Trim(value, "{}")
		access := "read"
		for p := n.Parent(); p != nil; p = p.Parent() {
			if p.Kind() == "left_assignment_expression" {
				access = "write"
				break
			}
			if p.Kind() == "pipeline" {
				break
			}
		}
		w.add(s, n, "script-variable", value, access, "direct")
	case "string_literal":
		if n.NamedChildCount() == 1 && n.NamedChild(0).Kind() == "verbatim_string_characters" {
			value := w.text(n)
			if len(value) >= 2 {
				value = strings.ReplaceAll(value[1:len(value)-1], "''", "'")
				w.add(s, n, "string", value, "", "direct")
			}
		} else {
			text := w.text(n)
			if strings.HasPrefix(text, "\"") && strings.HasSuffix(text, "\"") && !strings.ContainsAny(text, "$`") {
				w.add(s, n, "string", text[1:len(text)-1], "", "direct")
			}
		}
	case "integer_literal", "decimal_integer_literal", "hexadecimal_integer_literal":
		w.number(n, s)
	}
}
func (w *walker) pythonImports(root *sitter.Node) {
	// Imports are resolved only when that binding has no assignment anywhere.
	blocked := map[string]bool{}
	_ = w.walk(root, 0, func(n *sitter.Node) error {
		if n.Kind() == "parameters" {
			for i := uint(0); i < n.NamedChildCount(); i++ {
				c := n.NamedChild(i)
				if c.Kind() == "identifier" {
					blocked[w.text(c)] = true
				}
			}
		}
		if n.Kind() == "assignment" || n.Kind() == "augmented_assignment" {
			left := n.ChildByFieldName("left")
			if left != nil && left.Kind() == "identifier" {
				blocked[w.text(left)] = true
			}
		}
		return nil
	})
	_ = w.walk(root, 0, func(n *sitter.Node) error {
		if (n.Kind() == "import_statement" || n.Kind() == "import_from_statement") && n.Parent() != nil && n.Parent().Kind() != "module" {
			return nil
		}
		if n.Kind() == "import_statement" {
			for i := uint(0); i < n.NamedChildCount(); i++ {
				c := n.NamedChild(i)
				name, alias := c.ChildByFieldName("name"), c.ChildByFieldName("alias")
				if c.Kind() == "dotted_name" {
					v := w.text(c)
					short := strings.Split(v, ".")[0]
					if !blocked[short] {
						w.aliases[short] = short
					}
				} else if name != nil && alias != nil && !blocked[w.text(alias)] {
					w.aliases[w.text(alias)] = w.text(name)
				}
			}
		}
		if n.Kind() == "import_from_statement" {
			module := n.ChildByFieldName("module_name")
			if module == nil {
				return nil
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				c := n.NamedChild(i)
				if c.StartByte() == module.StartByte() {
					continue
				}
				name, alias := c, c
				if c.Kind() == "aliased_import" {
					name = c.ChildByFieldName("name")
					alias = c.ChildByFieldName("alias")
				}
				if name != nil && alias != nil && (c.Kind() == "dotted_name" || c.Kind() == "aliased_import") && !blocked[w.text(alias)] {
					w.aliases[w.text(alias)] = w.text(module) + "." + w.text(name)
				}
			}
		}
		return nil
	})
}
func (w *walker) pythonName(n *sitter.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	if n.Kind() == "identifier" {
		v := w.text(n)
		if a, ok := w.aliases[v]; ok {
			return a, true
		}
		return v, true
	}
	if n.Kind() == "attribute" {
		prefix, ok := w.pythonName(n.ChildByFieldName("object"))
		attr := n.ChildByFieldName("attribute")
		if ok && attr != nil {
			return prefix + "." + w.text(attr), true
		}
	}
	return "", false
}
func (w *walker) pythonFeature(n *sitter.Node, s *protocol.Statement) {
	switch n.Kind() {
	case "call":
		target := n.ChildByFieldName("function")
		value, ok := w.pythonName(target)
		if !ok || value == "getattr" || value == "eval" || value == "exec" {
			w.diagnostic(n, "dynamic-call", "computed or reflective Python call target is unresolved")
			return
		}
		basis := "direct"
		if target != nil && w.text(target) != value {
			basis = "static-alias"
		}
		w.add(s, target, "script-call", value, "", basis)
	case "identifier":
		p := n.Parent()
		if p != nil && (p.Kind() == "attribute" || p.Kind() == "dotted_name" || p.Kind() == "aliased_import" || p.Kind() == "parameters") {
			return
		}
		access := "read"
		if p != nil && (p.Kind() == "assignment" || p.Kind() == "augmented_assignment") {
			left := p.ChildByFieldName("left")
			if left != nil && left.StartByte() == n.StartByte() {
				access = "write"
			}
		}
		w.add(s, n, "script-variable", w.text(n), access, "direct")
	case "string":
		raw := w.text(n)
		if len(raw) >= 2 && (raw[0] == '\'' || raw[0] == '"') && raw[0] == raw[len(raw)-1] && !strings.Contains(raw, "\\") {
			quote := 1
			if strings.HasPrefix(raw, "'''") || strings.HasPrefix(raw, "\"\"\"") {
				quote = 3
			}
			if len(raw) >= quote*2 {
				w.add(s, n, "string", raw[quote:len(raw)-quote], "", "direct")
			}
		}
	case "integer":
		w.number(n, s)
	}
}
func (w *walker) bashFeature(n *sitter.Node, s *protocol.Statement) {
	switch n.Kind() {
	case "command":
		name := n.ChildByFieldName("name")
		if name == nil || name.NamedChildCount() != 1 || name.NamedChild(0).Kind() != "word" {
			w.diagnostic(n, "dynamic-call", "computed Bash command target is unresolved")
			return
		}
		w.add(s, name, "script-call", w.text(name), "", "direct")
	case "variable_name":
		p := n.Parent()
		access := "read"
		if p != nil && p.Kind() == "variable_assignment" {
			name := p.ChildByFieldName("name")
			if name != nil && name.StartByte() == n.StartByte() {
				access = "write"
			}
		}
		w.add(s, n, "script-variable", w.text(n), access, "direct")
	case "raw_string":
		text := w.text(n)
		if len(text) >= 2 {
			w.add(s, n, "string", text[1:len(text)-1], "", "direct")
		}
	case "string":
		if n.NamedChildCount() == 0 {
			text := w.text(n)
			if len(text) >= 2 && !strings.Contains(text, "\\") {
				w.add(s, n, "string", text[1:len(text)-1], "", "direct")
			}
		}
	case "number":
		w.number(n, s)
	}
}
func (w *walker) number(n *sitter.Node, s *protocol.Statement) {
	if p := n.Parent(); p != nil && p.Kind() == "unary_operator" {
		v := strings.TrimSpace(w.text(p))
		if strings.HasPrefix(v, "-") || strings.HasPrefix(v, "+") {
			n = p
		}
	}
	text := strings.ReplaceAll(w.text(n), "_", "")
	v, err := strconv.ParseInt(text, 0, 64)
	if err != nil {
		v, err = strconv.ParseInt(text, 10, 64)
	}
	if err == nil {
		w.add(s, n, "number", v, "", "direct")
	}
}
