# Script analysis

Build the Go tools with `scripts/build-script-tools.sh`, then prepare the external engine with `.venv/bin/python -m capathy setup`.

```sh
.venv/bin/python -m capathy analyze -f powershell -r examples/script-rules -vv examples/scripts/request.ps1
.venv/bin/python -m capathy analyze -f python -r examples/script-rules -vv examples/scripts/request.py
.venv/bin/python -m capathy analyze -f bash -r examples/script-rules -vv examples/scripts/request.sh
```

The launcher verifies the pinned external runtime and selects the built Go helper. `CAPA_SCRIPT_EXTRACTOR` overrides the helper path. It never downloads or builds a helper during analysis.

A script is parsed as data. The Go helper returns functions, statement identities, feature spans, provenance, parser versions and diagnostics; Python capa evaluates YAML rules against that evidence. The source sample is never executed.

Script rule branches use an explicit `format: powershell`, `format: python`, or `format: bash`. Available source features include `script-call`, `script-variable/read`, `script-variable/write`, `script-structure`, strings and numbers. Statement matches stay local before aggregation into function and file matches.

Addresses are original-file byte offsets, including BOM-marked UTF-16. JSON results retain source evidence under `meta.analysis.script`. JSON/protobuf round trips and version 4 script freezes preserve the new data; existing binary freeze version 3 remains supported.

Input is capped at 16 MiB and helper output at 32 MiB, with bounded subprocess pipes and deadlines. Dynamic invocation, reflection, computed commands, ambiguous aliases and malformed syntax may produce diagnostics instead of concrete targets.

The bundled rules and samples are synthetic demonstrations. They verify the analysis pipeline and do not establish real-world detection quality. See the [implementation ledger](implementation/2026-10-24-progress.md) for outstanding release gates.


## Additional source formats

The native helper and capa integration also accept `javascript`, `typescript`, `c`, and `cpp`. These adapters extract syntactically named calls, simple literals, functions, and control structures. They do not resolve receiver types, macro expansions, computed calls, or whole-program data flow. `.h` defaults to C; TSX is unsupported. For directory inventory and explicit candidate call links, use `python -m capathy analyze-project DIRECTORY --out out/project.json`. See [analysis workflows](analysis-workflows.md) for complete export, limits, and examples.
