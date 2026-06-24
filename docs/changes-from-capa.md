# What Capathy adds

Capathy is maintained as a standalone extension project. The full capa engine, upstream web UI, plugins, documentation, binary tests, signatures, and submodules are not tracked in the current source tree.

## Independent Go components

- `native/script/`: pinned Tree-sitter parsers for PowerShell/Python/Bash, original byte offsets, conservative source features, uncertainty diagnostics, and bounded JSON transport.
- `agent/`: evidence intake, explicit ADK/Gemini drafting, exact citations, SQLite audit/dedupe, deterministic validation, and local review packages.

## Engine integration changes

The bundle at `capathy/integrations/capa/` includes four new adapter files and a focused patch for existing capa files. It adds:

- Script-specific call, variable and structure features.
- A statement rule scope alongside binary instruction/basic-block scopes.
- Statement-local matching, function/file aggregation, and correct source evidence rendering.
- Script loader/CLI formats and a bounded Go subprocess adapter.
- JSON/protobuf source metadata and version 4 script freezes while retaining binary version 3 support.
- Official rule-linter checks for statement scope and required script format guards.

The external engine checkout is pinned and reproducible. `python -m capathy runtime-path` identifies the engine used for analysis; the manifest records both upstream and patched revisions.

## Presentation and review

Start with the root README, parser and agent directories, then inspect the small adapter overlay and engine patch. Capathy's own tests and examples remain here. The original planning documents and implementation ledger describe remaining evaluation and release work.

The current repository history starts from standalone Capathy snapshots. No active branch inherits the earlier full-engine checkout. See [HISTORY.md](../HISTORY.md) for the retrospective date convention and source attribution.
