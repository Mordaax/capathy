# Standalone repository migration

> Historical record of the file-tree migration. A later authorized history cleanup removed inherited ancestors and branches; see [HISTORY.md](../../HISTORY.md).

The earlier implementation was developed inside the full Mandiant capa repository. The current tree contains Capathy's own components and a focused integration bundle instead.

## Structure

- Kept the Go parser, Go agent, examples, script test corpus, implementation plans and Apache-2.0 license.
- Removed the inherited engine, web UI, plugins, binary test corpus, signatures, upstream scripts and submodules from the tracked root tree.
- Moved four new Python adapter files into `capathy/integrations/capa/overlay/`.
- Preserved changes to 16 existing engine/linter files as a focused patch.
- Pinned upstream `2bdf7a4788ffe8696d3eabf7f746ca682eba294b` and reproducible patched runtime `c64946b19af05c6cbe0ac9427b23e7bfca2c05d5` in the integration manifest.
- Added the `capathy setup`, `runtime-path`, `analyze` and `agent` commands. Setup creates an external cached checkout; analysis verifies its exact commit and cleanliness before loading it.
- Renamed Go module import paths to `github.com/Mordaax/capathy/...`.
- Replaced upstream package metadata and CI entry points with standalone Capathy metadata and integration setup.

## Verification

- Prepared the pinned runtime by fetching the actual public upstream repository and applying the bundle; its resulting commit matches the recorded revision.
- Installed the standalone package and external engine in the existing virtual environment.
- Built both Go executables with the updated module paths.
- All 63 retained/new Python tests passed. These include script scopes, protocol checks, native extraction, freeze/JSON/protobuf round trips, linter behavior and runtime verification/rejection tests.
- Both Go race-test suites passed after the module rename.
- PowerShell, Python and Bash examples matched through `python -m capathy analyze`; the agent imported the actual PowerShell result with two evidence entries.
- The official thorough rule linter passed against the bundled synthetic corpus.
- The Python wheel built successfully, contains four adapter source files and the patch, and contains no upstream `capa/` engine package. Wheel size is about 43 KB.
- Targeted Ruff and mypy checks passed on the new launcher/setup implementation.

The removed upstream regression tests are not represented as part of the 63-test result. Real public sample evaluation, live Gemini evaluation, cross-platform release verification and other outstanding roadmap gates remain unfinished.

## History

The initial file-tree migration was a normal follow-up commit. The subsequently authorized history cleanup replaces those published branches with standalone snapshots. The current branches have no inherited full-engine ancestors. The reconstructed date range and actual reconstruction date are documented in HISTORY.md.
