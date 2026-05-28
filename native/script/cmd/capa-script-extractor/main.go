// Command capa-script-extractor emits bounded static script evidence on stdout.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Mordaax/capathy/native/script/internal/analyze"
	"github.com/Mordaax/capathy/native/script/internal/protocol"
	"github.com/Mordaax/capathy/native/script/internal/source"
)

const version = "0.1.0"

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
func run(args []string, input io.Reader, output, diagnostics io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		if err := json.NewEncoder(output).Encode(map[string]any{"version": version, "schema": protocol.Schema, "languages": []string{"powershell", "python", "bash"}}); err != nil {
			fmt.Fprintln(diagnostics, "write version:", err)
			return 3
		}
		return 0
	}
	if len(args) == 0 || args[0] != "analyze" {
		fmt.Fprintln(diagnostics, "usage: capa-script-extractor analyze --language powershell|python|bash < sample")
		return 2
	}
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	language := fs.String("language", "", "exact source language")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(diagnostics, "input is accepted only through stdin")
		return 2
	}
	if *language != "powershell" && *language != "python" && *language != "bash" {
		fmt.Fprintln(diagnostics, "unsupported language")
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(input, source.MaxInput+1))
	if err != nil {
		fmt.Fprintln(diagnostics, "read input:", err)
		return 2
	}
	if len(raw) > source.MaxInput {
		fmt.Fprintln(diagnostics, "script exceeds 16 MiB input limit")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	doc, err := analyze.Analyze(ctx, *language, raw)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintln(diagnostics, "parse timeout")
		} else {
			fmt.Fprintln(diagnostics, "analyze:", err)
		}
		return 2
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		fmt.Fprintln(diagnostics, "encode evidence:", err)
		return 3
	}
	if len(encoded)+1 > protocol.MaxOutput {
		fmt.Fprintln(diagnostics, "evidence exceeds 32 MiB output limit")
		return 2
	}
	encoded = append(encoded, '\n')
	if _, err = output.Write(encoded); err != nil {
		fmt.Fprintln(diagnostics, "write evidence:", err)
		return 3
	}
	return 0
}
