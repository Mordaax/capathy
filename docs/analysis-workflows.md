# Binary, decompiler, source, and corpus workflows

All commands run from an installed Capathy checkout. First build the helper with `scripts/build-script-tools.sh` and prepare the external engine with `python -m capathy setup`. Outputs below are private, create-only JSON files: choose a new name for each run.

## Complete binary observations

```sh
python -m capathy export-features sample.elf --out out/features.json
python -m capathy agent draft --evidence-json out/features.json \
  --capability 'create a reverse shell on Linux' --out out/request.json
python -m capathy agent draft --request out/request.json \
  --provider claude --live --env-file .env --out out/proposal.json
```

The export walks global, file, function, basic-block, and instruction observations. It requires no rules and retains observations that existing rules never matched. Each record retains its address space and parent function/block. The sample SHA-256 and pinned capa extractor identify the observation set. “Complete” means traversal finished within limits, not that static analysis recovered every runtime behavior. Packed/encrypted payloads, unsupported architectures, and indirect dispatch may hide behavior.

Legacy `--capa-json` remains available; its binary importer sees only successful rule-match leaves. Prefer `--evidence-json` for binary rule discovery. Both commands normalize evidence locally unless `--live` is explicitly supplied. No binaries or pseudocode are uploaded by these commands. Live drafting sends normalized feature values, including extracted strings, to the selected provider; review sensitive observations first. Full exports can exceed the hosted model's 2 MiB input limit; choose a narrower independently reviewed evidence request rather than silently dropping observations.

## ELF decompilation

Install a full **JDK 25+**, then:

```sh
python -m capathy setup-ghidra
python -m capathy decompile sample.elf --max-functions 100 --out out/decompiled.json
```

Ghidra 12.2 is downloaded to the external tools cache and checked against a pinned SHA-256. An existing installation can be selected with `--ghidra-home`. Each run uses a temporary project and removes it afterward. Default wall-clock budget: 240 seconds; analysis budget: 120 seconds; decompilation: 10 seconds per function; at most 500 functions and 32 MiB output. Timeouts fail the command. Per-function `complete` and report `truncated` identify incomplete recovery.

Output includes virtual addresses, recovered function names, C-like pseudocode, and called-function addresses. Pseudocode is approximate analyst context, not original source and not proof of a behavior. It is kept separate from agent evidence. Targets are never executed. Native analyzers still parse untrusted files; use an isolated analysis machine for suspicious inputs. Capathy bounds processes and output but does not provide an OS sandbox.

## Source projects

```sh
python -m capathy analyze-project ./src --out out/project.json
python -m capathy export-features ./src/client.ts --out out/client-features.json
python -m capathy agent draft --evidence-json out/client-features.json \
  --capability 'invoke fetch from TypeScript source' --out out/client-request.json
```

Supported languages: PowerShell, Python, Bash, JavaScript/JSX, TypeScript, C, C++. Use `.ps1`, `.psm1`, `.py`, `.sh`, `.bash`, `.js`, `.jsx`, `.ts`, `.c`, `.h`, `.cpp`, `.cc`, `.cxx`, or `.hpp`. Headers default to C; use `export-features -f cpp header.h` for a C++ header. TSX, preprocessing, macro expansion, imported dependency execution, and type inference are not implemented.

Directory analysis records source hashes, function/statement spans, parser versions, diagnostics, and syntactically named calls. Call links list possible same-name definitions; `name-candidate` does **not** establish import resolution, runtime dispatch, cross-file data flow, or reachability. Python's existing conservative static alias normalization remains available. Dynamic/computed calls are unresolved. JS/TS/C/C++ currently export named calls, simple literals and control structures, not comprehensive variable-access semantics.

Defaults: 500 source files, 100,000 visited directory entries, 32 MiB aggregate source, 16 MiB per file, 16 MiB aggregate parser evidence, and 120 seconds total. JSON artifacts are capped at 32 MiB. Symlinks are skipped; hidden files, build outputs, dependencies and virtual environments are excluded. Limit violations fail rather than return a success-marked partial project. Malformed source produces parser diagnostics; source text is never imported, compiled, or executed. Rule drafting uses a selected file's evidence, preserving statement/function boundaries; project call candidates are review context.

## Reproducible public corpus pilot

The manifest pins public sample revisions, SHA-256 values, label provenance and explicit capability expectations. Samples stay in `~/.cache/capathy/samples`, mode 0600; they are never committed or executed.

Prepare the pinned rules separately:

```sh
git clone https://github.com/mandiant/capa-rules.git ~/.cache/capathy/pilot-rules
git -C ~/.cache/capathy/pilot-rules checkout 21332a057f5be39fa145bc4aea7ae2431ff05fc3
python -m capathy evaluate-corpus corpus/pilot.json \
  --rules ~/.cache/capathy/pilot-rules --out out/pilot.json
```

The command verifies the clean rules revision and every sample hash before static analysis. A mismatch in a declared expectation returns nonzero. Reports record engine/rule revisions and TP/FP/TN/FN **for declared capability expectations only**. A benign proxy can legitimately match socket rules; it is not a false positive for doing so.

Pilot inputs: a public Linux remote-shell binary (family/in-the-wild origin unverified), MicroSocks (benign utility), and Practical Malware Analysis Lab 01-01 (educational malware, not an independently attributed in-the-wild sample). One expected Linux reverse-shell match and two expected absences passed. This small regression uses the upstream rule's published example, so it measures reproducibility, not held-out accuracy, malware classification, model-generated rule quality, or generalization. See [recorded results](../corpus/pilot-results.json). Larger independently labeled, held-out corpora remain future evaluation work.
