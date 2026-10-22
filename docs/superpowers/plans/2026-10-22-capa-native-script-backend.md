# capa Native Script Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make stock capa analyze PowerShell, Python, and Bash source through a Go Tree-sitter extractor and match source-located YAML rules, with PowerShell delivered first.

**Architecture:** A Go executable emits a bounded versioned evidence document for one script. A Python `TreeSitterScriptExtractor` adapter converts it to capa features; a sibling `statement` scope matches those features and rolls matches into function/file results. PowerShell, Python, and Bash have separate semantic adapters sharing one transport and source map.

**Tech Stack:** Go 1.25+, `github.com/tree-sitter/go-tree-sitter`, `github.com/wharflab/tree-sitter-powershell/bindings/go`, official Python/Bash grammars, Python 3.10+, pytest, Ruff, mypy, capa YAML/protobuf/freeze.

**Spec:** [2026-10-22-capa-script-analysis-rule-agent-design.md](../specs/2026-10-22-capa-script-analysis-rule-agent-design.md)

## Global Constraints

- Language order: PowerShell, Python, Bash. The first independently shippable slice ends with PowerShell rule matches.
- Go implements parsing and feature extraction. Python code is limited to capa's required integration boundary; capa keeps Python `>=3.10` support.
- Never execute input scripts. Auto detection must not reclassify an existing supported binary by extension alone.
- Source locations are original-file byte offsets (`FileOffsetAddress`); names and node spans remain in evidence metadata.
- A script `statement` is separate from binary `instruction` and `basic block`; existing binary and dynamic semantics remain unchanged.
- Do not download a helper binary at runtime; use a known executable with a protocol/version handshake and bounded subprocess call.
- Rules using new features require a compatible capa release and a real positive plus benign/adversarial negatives before public PR eligibility.

## Review Focus

- UTF-16LE PowerShell text with a BOM: offsets must map back to original bytes, including after non-ASCII characters (Task 2).
- Nested calls or a function starting at byte zero: evidence must not leak across unrelated statements or collide with the top-level region (Tasks 2, 4, 5).
- Dynamic PowerShell invocation, Python reflection, and Bash computed commands: produce an uncertainty diagnostic, not a concrete call feature (Tasks 5, 10, 11).
- A forged script extension on a PE/ELF file: binary detection wins; malformed/oversized script exits with a bounded error (Tasks 6, 7).
- Old freeze v3 and protobuf results: load/round-trip without losing old matches; new script fields survive a new round trip (Task 8).

---

## File structure and stable interfaces

| Unit | Files and responsibility |
| --- | --- |
| Go CLI and protocol | `native/script/cmd/capa-script-extractor/main.go`, `native/script/internal/analyze/analyze.go`, `native/script/internal/protocol/protocol.go`: one sample in, one JSON document out; schema v1, exact language, SHA-256, functions, statements, features, diagnostics. |
| Go source mapping | `native/script/internal/source/source.go`: decode UTF-8 and BOM-marked UTF-16LE/BE, retain a UTF-8 to original-byte offset map. |
| Go grammar adapters | `native/script/internal/powershell/extract.go`, `internal/python/extract.go`, `internal/bash/extract.go`: grammar-specific queries and conservative feature semantics. |
| capa model and matcher | `capa/features/script.py`, `capa/features/extractors/base_extractor.py`, `capa/rules/__init__.py`, `capa/capabilities/static.py`: new feature kinds, `StatementHandle`, `ScriptStaticFeatureExtractor` contract, statement matcher. |
| capa transport | `capa/features/extractors/script/protocol.py`, `extractor.py`: validate JSON, invoke Go helper, expose `TreeSitterScriptExtractor` through capa's `StaticFeatureExtractor` API. |
| capa CLI/loader | `capa/features/common.py`, `capa/helpers.py`, `capa/main.py`, `capa/loader.py`: formats, detection, backend selection. |
| Persistence and display | `capa/features/freeze/__init__.py`, `features.py`, `capa/render/result_document.py`, `capa/render/proto/capa.proto`, generated `capa_pb2.py`/`.pyi`, `capa/render/proto/__init__.py`, `capa/render/{default,verbose,vverbose}.py`: round trips and source locations. |
| Rules and gates | `rules/nursery/*.yml` in the separate rules repository, `scripts/lint.py`, `tests/fixtures/scripts/**`, `tests/test_script_*.py`, `.github/workflows/{tests,build}.yml`, `.github/pyinstaller/pyinstaller.spec`. |

**Wire contract v1 (Go to Python):** `Document{schema:1, language:"powershell"|"python"|"bash", sha256, byte_length, functions:[Function], diagnostics:[Diagnostic]}`. `Function{start_byte,end_byte,name,top_level,statements:[Statement]}`. `Statement{start_byte,end_byte,ordinal,features:[Feature]}`. `Feature{kind:"script-call"|"script-variable"|"script-structure"|"string"|"number",value,display_value?,access?:"read"|"write",basis:"direct"|"static-alias",source_node,start_byte,end_byte}`. Every offset is in original bytes, every interval is half-open, statements have unique `(start_byte,ordinal)` identities, and features remain inside their statement/function interval. The top-level region exists only when executable top-level statements exist; its address is the first such statement's byte offset. Nested calls attach to the nearest enclosing statement and do not create duplicate statement addresses. The Python adapter converts only validated `basis` values to capa features and preserves spelling/node provenance in sidecar metadata.

**Feature vocabulary:** `script-call` stores a statically resolved name (`invoke-webrequest`, `requests.get`, `curl`); `script-variable/read|write` stores a language-normalized identifier; `script-structure` stores one of `assignment`, `pipeline`, `branch`, `loop`, `try`, `redirection`, `command-substitution`, or `function-definition`. PowerShell identifiers are Unicode case-folded, while Python and Bash retain case. An explicit `format` condition is required in each script rule branch. Grammar version, normalization version, and extraction diagnostics are recorded in analysis metadata, not used as LLM assertions.

## Tasks

### Task 1: Pin Go grammar toolchain and prove parser coverage

**Files:** Create `native/script/go.mod`, `native/script/internal/grammar/grammar.go`, `native/script/internal/grammar/grammar_test.go`, `tests/fixtures/scripts/powershell/grammar_cases.json`; modify `doc/installation.md`.

**Interfaces:** Produce `func Language(name string) (*sitter.Language, error)` for the three exact names above. The grammar corpus records source, expected named-node types, and whether `ERROR` nodes are expected. It must cover direct calls, pipelines, functions, aliases, splatting, interpolation, malformed input, and a large but bounded file.

- [ ] Write `TestPowerShellGrammarCoverage` asserting representative `.ps1` inputs yield `command`, `pipeline`, and `function_statement` nodes without unexpected `ERROR` nodes; assert an unsupported language returns an error.
- [ ] Run `go test ./internal/grammar` from `native/script`; expect failure because the module and `Language` do not exist. Provision Go `>=1.25` for execution first; `go` is absent in the current planning environment.
- [ ] Add pinned Go/grammar dependencies and `Language`; document grammar license, ABI, supported platforms, and the compatibility probe result in `doc/installation.md`.
- [ ] Run `go test ./internal/grammar` and `go mod verify`; expect pass. Record any grammar gaps as fixtures and an upstream issue before relying on the affected node.
- [ ] Commit `feat(script): pin Tree-sitter Go grammars`.

### Task 2: Define bounded evidence protocol and original-byte source map

**Files:** Create `native/script/internal/protocol/{protocol.go,protocol_test.go}`, `native/script/internal/source/{source.go,source_test.go}`, `native/script/internal/analyze/{analyze.go,analyze_test.go}`, `native/script/cmd/capa-script-extractor/{main.go,main_test.go}`.

**Interfaces:** Produce `source.DecodeSource(raw []byte) (Source, error)`, `func (Source) OriginalOffset(utf8Offset uint32) (uint32,error)`, `analyze.Analyze(ctx context.Context, language string, raw []byte) (protocol.Document,error)`, and `func (Document) Validate() error`. The `analyze` package owns language dispatch to avoid a protocol/adapter import cycle. CLI: `capa-script-extractor analyze --language <name>`, reads stdin, writes one JSON document to stdout, diagnostics to stderr, uses exit status 2 for invalid input and 3 for internal failure.

- [ ] Write table tests asserting UTF-8 and UTF-16LE/BE BOM samples map a non-ASCII call's start to its original byte offset; reject invalid intervals, duplicate `(start_byte,ordinal)`, mismatched SHA-256, missing source-node/basis provenance, a sample over 16 MiB, and an unknown schema version. Assert `analyze.Analyze` returns typed `ErrAdapterUnavailable` before a language adapter is registered.
- [ ] Run `go test ./internal/protocol ./internal/source ./internal/analyze ./cmd/capa-script-extractor`; expect failures for missing types and methods.
- [ ] Implement streaming source decoding/mapping and JSON validation; cap input at 16 MiB and JSON output at 32 MiB, never run source text. `analyze.Analyze` returns typed `ErrAdapterUnavailable` until Tasks 5, 10, and 11 add compiled adapters, with no shell or filesystem-selected grammar.
- [ ] Run the same tests, `go vet ./...`, and `go test -race ./...`; expect pass.
- [ ] Commit `feat(script): add bounded evidence protocol`.

### Task 3: Add script features and a non-binary statement rule scope

**Files:** Create `capa/features/script.py`, `tests/test_script_rules.py`; modify `capa/rules/__init__.py`, `capa/features/common.py`.

**Interfaces:** Produce `ScriptCall(value: str)`, `ScriptVariable(value: str, access: Literal["read","write"])`, `ScriptStructure(value: str)`, and `Scope.STATEMENT`. Accepted YAML keys are `script-call`, `script-variable/read`, `script-variable/write`, and `script-structure`. `is_subscope_compatible()` uses the two explicit branches `file > function > statement` and `file > function > basic block > instruction`.

- [ ] Write `test_statement_scope_is_sibling_of_binary_scopes`: `Rule.from_yaml` accepts a statement rule and a function rule with a statement subscope, rejects a statement rule containing `instruction`/`basic block`, and rejects script features at binary instruction scope. Assert exact feature equality/hash semantics for `read` versus `write`.
- [ ] Run `pytest -q tests/test_script_rules.py`; expect failure for missing scope/features.
- [ ] Implement feature classes, scope parser/index/support tables and sibling compatibility; add `FORMAT_POWERSHELL`, `FORMAT_PYTHON`, `FORMAT_BASH` to static formats and valid `format` values.
- [ ] Run `pytest -q tests/test_script_rules.py tests/test_rules.py tests/test_rules_insn_scope.py`; expect pass.
- [ ] Commit `feat(script): add statement scope and features`.

### Task 4: Match statements without changing binary matcher behavior

**Files:** Modify `capa/features/extractors/base_extractor.py`, `capa/features/extractors/null.py`, `capa/capabilities/static.py`; create `tests/test_script_capabilities.py`.

**Interfaces:** Produce `StatementHandle(address: Address, inner: Any, ordinal: int)`, `ScriptStaticFeatureExtractor(StaticFeatureExtractor)` with `get_statements(fh: FunctionHandle) -> Iterator[StatementHandle]` and `extract_statement_features(fh, sh) -> Iterator[tuple[Feature,Address]]`. `NullScriptFeatureExtractor` provides in-memory script fixtures. `find_statement_capabilities(ruleset, extractor, fh, sh)` matches `Scope.STATEMENT`; `find_script_code_capabilities()` aggregates to function. Statement matches flow to file only as indexed matched-rule features, consistent with existing capa scope aggregation.

- [ ] Write `test_statement_locality_and_rollup`: two statements in one function must not satisfy one statement-level `and` rule across locations; a function rule may combine their features; a file rule may match the function rule. Assert a function at byte zero and top-level code later have distinct handles.
- [ ] Run `pytest -q tests/test_script_capabilities.py`; expect failure for missing extractor and matcher.
- [ ] Implement script-specific dispatch from `find_static_capabilities`, leaving binary traversal unchanged; add deterministic statement match counts/layout addresses and prevent duplicate top-level/nested-function extraction.
- [ ] Run `pytest -q tests/test_script_capabilities.py tests/test_capabilities.py`; expect pass.
- [ ] Commit `feat(script): match source statements`.

### Task 5: Extract conservative PowerShell semantics in Go

**Files:** Create `native/script/internal/powershell/{extract.go,extract_test.go,normalize.go}`, `tests/fixtures/scripts/powershell/{features.json,direct.ps1,ambiguous.ps1}`; modify `native/script/internal/analyze/analyze.go` dispatch.

**Interfaces:** Produce `func Extract(ctx context.Context, src source.Source) (protocol.Document,error)`. Direct command/cmdlet names are case-folded; script-defined aliases resolve only when unambiguous. Emit reads/writes and structures with source spans. Dynamic invocation, splatting, encoded payloads, and unresolved aliases yield diagnostics without invented call targets.

- [ ] Write `TestPowerShellFeatures` asserting `Invoke-WebRequest -Uri $u | Start-Process` yields two call values, one pipeline, and `$u` read; assert a string/comment containing `Invoke-WebRequest` yields no call; assert `& $cmd` yields an uncertainty diagnostic and no concrete `script-call`.
- [ ] Run `go test ./internal/powershell`; expect failure for missing `Extract`.
- [ ] Implement AST walks/queries and semantic normalization; attach nested calls to a single enclosing statement, keep source order and original offsets, and reject features under `ERROR` nodes.
- [ ] Run `go test ./internal/powershell ./internal/protocol` and `go test -race ./...`; expect pass.
- [ ] Commit `feat(script): extract PowerShell features`.

### Task 6: Add a strict Python adapter for the Go evidence process

**Files:** Create `capa/features/extractors/script/{__init__.py,protocol.py,extractor.py}`, `tests/test_script_protocol.py`, `tests/test_script_extractor.py`.

**Interfaces:** Produce `parse_document(data: bytes, raw: bytes, expected_language: str) -> ScriptDocument` and `TreeSitterScriptExtractor.from_path(path: Path, language: str, executable: Path | None = None) -> TreeSitterScriptExtractor`. Locate only a configured or packaged helper; invoke it with `subprocess.Popen([...], shell=False)` while concurrently draining stdout/stderr with 32 MiB/1 MiB caps and a 20-second deadline. Map spans to `FileOffsetAddress`, hash original bytes, and return `NO_ADDRESS` as base address.

- [ ] Write tests with a fake executable and a fixture document: valid statement features round-trip; wrong schema/hash/language, out-of-bounds span, duplicate statement identity, helper timeout, missing helper, and oversized stdout all raise typed `ScriptAnalysisError` without leaking sample text.
- [ ] Run `pytest -q tests/test_script_protocol.py tests/test_script_extractor.py`; expect failure for missing adapter.
- [ ] Implement typed JSON validation, helper lookup/version handshake, bounded process invocation that terminates the child at the output cap, and all required `StaticFeatureExtractor` methods; binary-only methods yield no handles. Do not pass untrusted text as arguments or environment variables.
- [ ] Run the two tests and `python -m mypy capa/features/extractors/script`; expect pass.
- [ ] Commit `feat(script): bridge Go evidence into capa`.

### Task 7: Wire native script formats into CLI and loader

**Files:** Modify `capa/helpers.py`, `capa/main.py`, `capa/loader.py`, `capa/features/common.py`; create `tests/test_script_cli.py`; update `doc/usage.md`.

**Interfaces:** `get_auto_format(path)` recognizes `.ps1`/`.psm1`, `.py`, `.sh`/`.bash` plus trusted shebangs after binary magic checks. `get_backend_from_cli()` selects `tree-sitter` for script formats. `loader.get_extractor()` returns the script adapter; explicit `-f powershell|python|bash` can analyze an extensionless script. `-b tree-sitter` rejects a binary format.

- [ ] Write `test_script_format_selection`: auto-detect each language, explicit override on extensionless text, PE bytes named `sample.ps1` stay PE, ambiguous text is rejected, and incompatible backend/format errors are clear.
- [ ] Run `pytest -q tests/test_script_cli.py`; expect failure for unknown CLI choices.
- [ ] Add format/backend choices and loader routing; ensure the main path skips binary OS/arch validation for scripts and records `format=<language>`, `arch=unknown`, and appropriate OS metadata.
- [ ] Run `pytest -q tests/test_script_cli.py tests/test_main.py tests/test_helpers.py`; expect pass for fixtures available locally; run `capa -f powershell -b tree-sitter <fixture.ps1> -j` once the Go helper is built.
- [ ] Commit `feat(script): route source files through capa CLI`.

### Task 8: Preserve new scope/features in freeze, JSON, protobuf, and text output

**Files:** Modify `capa/features/freeze/{__init__.py,features.py}`, `capa/render/result_document.py`, `capa/render/proto/{capa.proto,__init__.py,capa_pb2.py,capa_pb2.pyi}`, `capa/render/{default,verbose,vverbose}.py`, `capa/loader.py`; create `tests/test_script_serialization.py`.

**Interfaces:** Freeze v4 adds optional `statements` under each static function, and `loads_static()` accepts both v3 and v4; v3 binary output retains its semantics. Protobuf adds `SCOPE_STATEMENT=9` and new feature messages/oneof fields with unused field numbers, not renumbered old values. Result layout adds optional matched statement offsets and source span/line-column metadata derived from original bytes.

- [ ] Write `test_script_round_trips`: freeze dump/load, JSON result, protobuf result, and verbose text retain `script-call`, `statement` scope, and original byte offset; assert an existing v3 freeze and old protobuf fixture still load.
- [ ] Run `pytest -q tests/test_script_serialization.py`; expect failures for absent models and scope mapping.
- [ ] Add serializers, null-script loader, renderers, protobuf schema and regenerated bindings; document the exact protobuf generation command in a reproducible script. Keep old wire field numbers and reject new script data with an old reader rather than silently losing it where protocol permits.
- [ ] Run `pytest -q tests/test_script_serialization.py tests/test_freeze_static.py tests/test_result_document.py tests/test_proto.py tests/test_render.py`; expect pass.
- [ ] Commit `feat(script): serialize and render source matches`.

### Task 9: Verify PowerShell capability rules on real and benign samples

**Files:** In the separate rules repository create `rules/nursery/download-file-via-powershell-invoke-webrequest.yml`, `rules/nursery/execute-powershell-expression.yml`, `rules/nursery/start-process-from-powershell.yml`; modify `scripts/lint.py`; create `tests/fixtures/scripts/powershell/rule_cases.json`, `tests/test_script_rule_corpus.py`; update `rules/doc/format.md` in its own PR.

**Interfaces:** Each YAML uses `scopes.static: statement|function`, `scopes.dynamic: unsupported`, explicit `format: powershell`, normalized script features, namespace and examples. Add `ScriptRuleRequiresFormat` lint that checks every satisfiable branch containing a script feature includes the matching format constraint. Corpus manifest records SHA-256, origin, redistribution permission, expected rule names/offsets, and negative classification.

- [ ] Write `test_powershell_rules_positive_negative`: each rule matches its documented positive at an exact byte offset and none of the benign/adversarial negatives; write a linter test showing a script rule without format fails.
- [ ] Run `pytest -q tests/test_script_rule_corpus.py` and `python scripts/lint.py rules/`; expect the new assertions/lint to fail before implementation.
- [ ] Add three scoped rules and permitted corpus entries; place redistributable real samples in `capa-testfiles` only after provenance/rights review, otherwise hold the rule in local validation or nursery with honest status. Extend lint and format docs.
- [ ] Run `python scripts/capafmt.py -c <rule-path>` separately for each rule, `python scripts/lint.py --thorough --samples <populated-sample-dir> rules/`, and the corpus test; expect zero failures for PR-eligible rules.
- [ ] Commit rules/test-data changes in their own repositories, then capa tests/docs separately; do not commit only a submodule pointer as a substitute for a rules PR.

### Task 10: Add Python source semantics through the same contract

**Files:** Create `native/script/internal/python/{extract.go,extract_test.go}`, `tests/fixtures/scripts/python/{features.json,direct.py,ambiguous.py}`; extend `tests/test_script_rule_corpus.py`; add Python rules in the rules repository.

**Interfaces:** `python.Extract(ctx,src)` emits direct/qualified calls, local import aliases when statically unambiguous, variable reads/writes, string/number literals, and branch/loop/try structures. Reflection, monkey-patching, and dynamic imports yield uncertainty diagnostics.

- [ ] Write `TestPythonFeatures` asserting `import requests as r; r.get(url)` yields `requests.get` and a read of `url`; assert `getattr(obj,name)()` does not invent a target. Add a positive and benign negative rule corpus pair.
- [ ] Run `go test ./internal/python` and `pytest -q tests/test_script_rule_corpus.py -k python`; expect failure before implementation.
- [ ] Implement Python grammar adapter, language-specific normalization, and at least two capability rules supported by real examples.
- [ ] Run Go tests, Python corpus tests, and `python scripts/lint.py --thorough rules/`; expect pass.
- [ ] Commit Go/capa work and rules work in their respective repositories.

### Task 11: Add Bash source semantics through the same contract

**Files:** Create `native/script/internal/bash/{extract.go,extract_test.go}`, `tests/fixtures/scripts/bash/{features.json,direct.sh,ambiguous.sh}`; extend `tests/test_script_rule_corpus.py`; add Bash rules in the rules repository.

**Interfaces:** `bash.Extract(ctx,src)` emits direct commands/functions, variable reads/writes, assignments, pipelines, redirections, substitutions, and control structures; computed commands and expansion-dependent targets remain unresolved.

- [ ] Write `TestBashFeatures` asserting `curl "$u" | sh` yields `curl`, `sh`, pipeline, and `$u` read; assert `"$cmd" "$arg"` yields no concrete call target. Add positive and negative corpus assertions.
- [ ] Run `go test ./internal/bash` and `pytest -q tests/test_script_rule_corpus.py -k bash`; expect failure before implementation.
- [ ] Implement Bash grammar adapter and at least two evidence-backed capability rules.
- [ ] Run Go tests, Bash corpus tests, and thorough lint; expect pass.
- [ ] Commit Go/capa work and rules work in their respective repositories.

### Task 12: Bound resource use and measure detection quality

**Files:** Create `native/script/internal/quality/{fuzz_test.go,benchmark_test.go}`, `native/script/cmd/capa-script-eval/main.go`, `tests/test_script_robustness.py`, `tests/fixtures/scripts/corpus-manifest.json`, `doc/script-analysis.md`.

**Interfaces:** A manifest enumerates positive/benign/ambiguous samples, source rights, expected parser status, expected features/rules, and holdout designation. `capa-script-eval --manifest <path> --output <path>` produces a machine-readable report with parse-error rate, per-rule precision/recall, extraction time, peak RSS, and false positive cases. Maintain separate synthetic unit fixtures and real held-out examples.

- [ ] Write fuzz/regression tests for malformed UTF-8/UTF-16, huge nesting, deeply nested interpolation, empty input, and random bytes; assert no panic, unbounded process, or fabricated feature from an error node.
- [ ] Run `go test ./internal/quality -fuzz=FuzzSource -fuzztime=30s` and `pytest -q tests/test_script_robustness.py`; expect failure for missing limit/diagnostic behavior.
- [ ] Add early abort and error accounting, corpus evaluation command, and benchmark report. Approve rollout thresholds with maintainers from measured baseline before moving rules out of nursery.
- [ ] Run `go test -race ./...`, `go test ./internal/quality -fuzz=FuzzSource -fuzztime=30s`, Python robustness tests, and `go run ./cmd/capa-script-eval --manifest ../../tests/fixtures/scripts/corpus-manifest.json --output <report-path>`; expect pass plus saved report artifact without raw private sample text.
- [ ] Commit `test(script): harden parser and report quality`.

### Task 13: Ship cross-platform helper packaging and documentation

**Files:** Modify `.github/workflows/tests.yml`, `.github/workflows/build.yml`, `.github/pyinstaller/pyinstaller.spec`, `pyproject.toml`, `doc/installation.md`, `doc/usage.md`; create `native/script/README.md`, `tests/test_script_packaging.py`.

**Interfaces:** Build a named helper for Linux x86_64/arm64, macOS x86_64/arm64, and Windows x86_64 with `CGO_ENABLED=1`; include its SHA-256/version in artifacts. The adapter finds a bundled helper in PyInstaller or an explicitly installed helper in source installs, checks schema/version before analysis, and emits a clear install instruction if absent.

- [ ] Write `test_helper_discovery_and_version` asserting matching packaged helper is found, wrong version/checksum is rejected, and binary-only capa works when the helper is absent. Add CI smoke tests running a small `.ps1`, `.py`, and `.sh` under each supported artifact.
- [ ] Run `pytest -q tests/test_script_packaging.py`; expect failure for missing lookup/version logic.
- [ ] Add Go build jobs, artifact wiring, PyInstaller data inclusion, installation instructions, and CI smoke commands. Request upstream packaging review before release because the Go sidecar changes distribution.
- [ ] Run the local test, `pytest -q tests/` with initialized test-data submodule, `pre-commit run --hook-stage=manual --all-files`, and all GitHub Actions matrix jobs; expect pass. If `tests/data` is unavailable locally, report that as an unrun gate rather than a pass.
- [ ] Commit `build(script): package Tree-sitter helper across platforms`.

## Backend completion gate

Demonstrate `capa -f powershell`, `-f python`, and `-f bash` on held-out scripts; verify byte-accurate evidence, expected rule matches, zero corpus-negative matches, freeze/JSON/protobuf round trips, normal PE/ELF/.NET/dynamic regression tests, and reproducible helper builds. Obtain maintainer review of the new scope, feature vocabulary, sidecar packaging, grammar license/pinning, and rule/test-data PRs before publishing a release.
