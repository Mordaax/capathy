# Analysis expansion execution ledger

Accepted scope: full binary feature export; a reproducible real-malware/benign corpus evaluation; optional Ghidra decompilation with original addresses; source-project analysis and JavaScript/TypeScript/C/C++ syntax support.

## Plan and acceptance

- [x] Export all extractor observations without requiring existing rule matches. Preserve sample identity, scopes, address kinds, and tool provenance; import this evidence into the Go agent. Verify on ELF and a no-rule-match regression.
- [x] Add bounded corpus fetch/evaluation with pinned provenance and hashes, external sample storage, positive/negative expectations, and machine-readable reports. Run actual malware and benign samples without execution.
- [x] Add an external Ghidra setup and bounded headless decompiler. Export function addresses, C-like pseudocode, and call links. Verify on a real ELF; reject malformed results and never execute the target.
- [x] Add bounded source-directory analysis, module/call relationships with uncertainty labels, and JS/TS/C/C++ grammar adapters. Preserve source provenance and verify all languages through the existing rule pipeline.
- [x] Update documentation/CI, run targeted regressions and a final integrated review. Commit/push status is recorded below.

## Rulings

- Use external caches for downloaded engines and samples; only manifests, hashes, our adapters, and synthetic fixtures are tracked. This preserves the standalone repository and sample provenance. A cache is not a reviewed malware distribution.
- Decompiler pseudocode is analyst context. Rules remain grounded in actual extractor observations and addresses; speculative call links are explicitly labeled.
- Evaluation distinguishes capability expectations from malware labels. A benign program can legitimately match a networking capability; benign status alone does not mean every capability match is a false positive.
- Existing inherited source/history remains outside the repository. Integration changes are maintained through the pinned external-engine patch and adapter bundle.

## Evidence and outstanding work

Implementation checks and corpus results will be recorded here as work lands. No completion is implied by the unchecked plan.


- Full-feature export regression passed with an unmatched API, and all four added source formats passed actual capa rule matches. The Linux remote-shell binary exported 14,672 observations across 144 functions; the Go agent imported all 14,672.
- Public pilot: Linux remote-shell ELF, MicroSocks ELF and PMA Lab 01-01 PE; one declared reverse-shell positive and two negatives passed (TP=1, TN=2, FP=0, FN=0). Labels explicitly distinguish educational malware and unverified family provenance. This is an upstream-example regression, not held-out accuracy.
- Ghidra 12.2 archive SHA-256 verified. A full JDK was missing locally; an external cached JDK supplied it. Real runs recovered 10 functions with pseudocode from `/usr/bin/true` and 25 from the remote-shell ELF. Fixed installer preservation of native executable bits; regression covers it.
- Source directory report produced per-file evidence and candidate links without execution. JS/TS/C/C++ support includes named calls, literals and structures; comprehensive variable access and semantic cross-file resolution remain outside this adapter's claims.
- Provenance correction: capture runtime revision when evaluation starts, so a manifest update during a scan cannot relabel a result with a different engine. The final pilot is rerun against the final pinned engine.
- All downloaded engines, JDKs, rules and sample bytes remain in external caches. No full capa checkout or malware bytes are added to this repository.


## Final independent review and fixes

A read-only independent review identified six important defects. Reproducing regressions failed first; fixes are verified by the final suites:

- Nested JavaScript generators and C++ lambdas now create separate function scopes; their uncalled bodies cannot supply enclosing-function co-occurrence.
- Full exports capture the verified runtime commit, and Go citations preserve it. Actual custom Ghidra installations are labeled from their own application properties.
- Source traversal counts ignored entries and checks its deadline throughout discovery; aggregate parser evidence is bounded too.
- Interrupted Ghidra downloads remain temporary and are removed; successful checked archives are published atomically. Installer hashing remains Python 3.10 compatible.
- Ghidra post-processing explicitly checks analysis timeout status; timed-out analysis cannot produce a successful decompilation artifact.

No review findings are deferred. Scope decisions remain as stated above: pseudocode and candidate call links are review context; the corpus pilot is not held-out accuracy. No general malware-classifier or production-readiness claim is made.


## Final verification (October 25, 2026)

- Python: `python -m pytest -q` — **76 passed** after review fixes.
- Both Go modules: `go test -race ./...`, `go vet ./...`, `go mod verify` — passed. Both CLI binaries rebuilt.
- Ruff and `git diff --check` — passed. Python wheel built; contains the Ghidra Java resource and analysis modules, with no sample bytes or secrets.
- Final real ELF run: **14,672 observations / 144 functions**, all observations imported with the exact runtime revision. Ghidra **12.2 (PUBLIC)** emitted **25 complete function pseudocode records**, `analysis_timed_out=false`; the report explicitly marks the function-count truncation.
- Seven-language example-directory analysis and TypeScript full-export/agent import passed. New languages also passed actual capa statement-rule matches.
- Three-binary pilot: **TP=1, TN=2, FP=0, FN=0** for the one explicitly declared capability; manifest and runtime revisions verified. Recorded metadata is in `corpus/pilot-results.json`.
- Cross-platform workflow execution and held-out/model-generated rule accuracy were not evaluated locally. Existing publication/release gates remain as described in the historical roadmap ledger.
