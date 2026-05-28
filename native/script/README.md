# Native script extractor

This Go companion parses PowerShell, Python and Bash with statically linked Tree-sitter grammars. Input is never executed. It emits versioned JSON consumed by capa's Python script adapter.

## Build and run

Requires Go 1.25 or newer, a C compiler, and CGO enabled. From this directory:

```sh
go mod download
go build -o bin/capa-script-extractor ./cmd/capa-script-extractor
./bin/capa-script-extractor --version
./bin/capa-script-extractor analyze --language powershell < example.ps1
export CAPA_SCRIPT_EXTRACTOR="$(pwd)/bin/capa-script-extractor"
```

For YAML rule matching, first run `python -m capathy setup`, then `python -m capathy analyze -f powershell -r examples/script-rules sample.ps1` from the Capathy root. The engine is fetched into an external cache and is not vendored here. The extractor is never downloaded at runtime.

## Contract and bounds

Schema 1 includes the exact language, original SHA-256/byte length, functions, statement identities `(start_byte, ordinal)`, source-located features and uncertainty diagnostics. Intervals are half-open original-file byte offsets, including UTF-8 BOM and BOM-marked UTF-16LE/BE. `extractor_version`, `grammar_version` and `normalization_version` record implementation provenance. `--version` is a JSON protocol handshake.

Input is capped at 16 MiB, emitted JSON at 32 MiB, parsing at 15 seconds, tree traversal at 500,000 visited nodes and nesting at 512. The caller should additionally impose its own subprocess deadline and deployment memory limit. The helper reports malformed syntax and omits evidence beneath Tree-sitter ERROR nodes. Exit 2 means rejected input/arguments; exit 3 means an output/internal failure. Diagnostics go to stderr only for failed analysis; successful uncertainty diagnostics are in JSON.

Functions and executable top-level statements are separate regions. Pipelines share one statement; statements inside branches are matched separately. Extraction includes direct calls, variable reads/writes, literal strings/integers, and structural observations. PowerShell names use Unicode case-folding. A single unconditional literal `Set-Alias`/`New-Alias` definition can resolve subsequent calls; ambiguous mutations disable canonicalization. Python top-level import aliases resolve conservatively when no assignment or parameter shadows the binding. Reflective/computed calls, splatting and encoded PowerShell payloads produce diagnostics instead of invented targets. Encoded payloads are never decoded or executed.

## Verification

```sh
go test -race ./...
go vet ./...
go mod verify
```

Tests cover all three grammars, command/string/comment separation, function and branch locality, ambiguous aliases, Python shadowed imports, computed calls, malformed encodings/syntax, cancellation, bounds, protocol validation and original UTF-16 offsets.

## Pinned dependencies and limitations

- Go Tree-sitter binding v0.25.0 (MIT).
- wharflab PowerShell grammar v0.38.1 (MIT).
- official Python grammar v0.25.0 and Bash grammar v0.25.1 (MIT).
- golang.org/x/text v0.28.0 (BSD) for Unicode case-folding.

The pinned grammar/runtime ABI compatibility is probed by the Go grammar tests on the current Linux amd64 host. Other OS/architecture combinations require a native C toolchain and CI verification; this change does not claim prebuilt cross-platform packages. Source fixtures are synthetic unit data, not a rights-reviewed public malware evaluation corpus. This implementation does not prove variable dataflow, resolve arbitrary runtime imports/aliases, analyze every language construct, decode obfuscation, or execute embedded script blocks. Python alias handling deliberately sacrifices some coverage when shadowing is uncertain. Real-world precision/recall, public positive/negative corpus gates, and release packaging remain separate delivery gates.
