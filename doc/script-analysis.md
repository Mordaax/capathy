# Native script analysis

capa can statically inspect PowerShell, Python, and Bash source with a Go Tree-sitter helper. Input source is parsed and is never executed. This is conservative source analysis: dynamic command names and reflective calls may be unresolved and are recorded as diagnostics rather than guessed targets.

## Build and run

Install Go 1.25 or newer and a C compiler for the pinned Tree-sitter grammars. ADK in the separate agent module requires Go 1.26.6 or newer.

From the capa checkout, `scripts/build-script-tools.sh` builds both Go tools. It also detects Go toolchains cached outside `PATH`; use `CAPA_GO` to select an explicit executable. To build just the parser and run examples:

```sh
(cd native/script && go build -o bin/capa-script-extractor ./cmd/capa-script-extractor)
export CAPA_SCRIPT_EXTRACTOR="$PWD/native/script/bin/capa-script-extractor"
python -m capa.main -f powershell -r examples/script-rules -vv examples/scripts/request.ps1
python -m capa.main -f python -r examples/script-rules -vv examples/scripts/request.py
python -m capa.main -f bash -r examples/script-rules -vv examples/scripts/request.sh
```

Use the Python interpreter where capa's dependencies are installed; in this workspace it is `.venv/bin/python`. Alternatively put the compiled helper on `PATH` as `capa-script-extractor`. capa does not download or build executables at analysis time. A missing helper, incompatible protocol, timeout, or invalid evidence produces an error.

Automatic detection recognizes `.ps1`, `.psm1`, `.py`, `.sh`, and `.bash` after binary magic detection. Explicit `-f` is recommended for extensionless source. PE and ELF input is rejected by the script adapter even when script format is requested.

## Features and rule scope

Script rules use `statement` as a sibling of binary instruction and basic-block scopes. A statement rule sees only the evidence in that statement; function rules can combine observations from several statements. File rules consume matched rules from lower scopes.

```yaml
rule:
  meta:
    name: issue web request from PowerShell source
    scopes:
      static: statement
      dynamic: unsupported
  features:
    - and:
      - format: powershell
      - script-call: invoke-webrequest
```

Available script features are `script-call`, `script-variable/read`, `script-variable/write`, and `script-structure`. Strings and numbers can also occur in source evidence. Explicitly constrain script branches with `format: powershell`, `format: python`, or `format: bash`.

Source addresses are original-file byte offsets, including BOM-marked UTF-16. The schema 1 evidence document includes functions, statements, feature spans, provenance, and uncertainty diagnostics. JSON results retain this under `meta.analysis.script`; protobuf preserves it too. Script freezes use version 4; binary freezes continue using version 3 and old version 3 freezes remain readable.

Input is capped at 16 MiB and helper output at 32 MiB. Both subprocess output streams and the process deadline are bounded. Comments and string literals do not become command calls.

## Validation and limits

```sh
(cd native/script && go test -race ./... && go vet ./...)
python -m pytest -q tests/test_script_protocol.py tests/test_script_rules.py tests/test_script_capabilities.py tests/test_script_extractor.py tests/test_script_serialization.py
```

The three bundled demonstration rules and samples show extraction and matching; they are synthetic examples, not a reviewed malware-detection corpus. Dynamic invocation, ambiguous aliases, obfuscation, reflection, computed commands, and runtime-only behavior can reduce coverage. Inspect diagnostics and evaluate your own positive and negative samples before depending on a rule.

See [the implementation ledger](../docs/implementation/2026-10-24-progress.md) for release gates and [the rule agent](../agent/README.md) for local drafting and validation.
