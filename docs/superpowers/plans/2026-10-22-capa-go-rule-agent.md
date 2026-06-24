# capa Go Rule Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go ADK agent that turns binary or script evidence and reviewed issue/feed ideas into capa rule PRs that have passed deterministic lint, sample, and duplicate checks.

**Architecture:** A separate Go module owns intake, provenance, ADK/Gemini drafting, validation, audit state, and GitHub publication. It consumes capa JSON as evidence and uses pinned capa and capa-rules checkouts for all rule checks. Model output cannot select commands, sample paths, destinations, or pass its own gate; publication requires a validation report and a human still merges.

**Tech Stack:** Go 1.25+, `google.golang.org/adk/v2`, Gemini API, `database/sql` with pinned SQLite driver, capa CLI and official formatter/linter, GitHub REST API, RSS/Atom/JSON feeds, GitHub Actions.

**Spec:** [2026-10-22-capa-script-analysis-rule-agent-design.md](../specs/2026-10-22-capa-script-analysis-rule-agent-design.md)

## Global Constraints

- All paths below are relative to a new `capa-rule-agent` repository; choose its Go module import path when its remote is created. The `capa` backend and `capa-rules` stay in their own repositories.
- Go owns orchestration. Use hosted Gemini through ADK Go v2; local `.env` may supply the key, but test and dry-run paths require no key or network.
- `GOOGLE_API_KEY` takes precedence over `GEMINI_API_KEY`; process environment takes precedence over `.env` for the same name. Never print either value.
- Input scripts, binaries, attachments, retrieved text, and model output are untrusted data. Never execute samples, generated code, or model-selected commands.
- Raw source upload is off by default; an operator must explicitly enable it per run and permit that sample's sharing status.
- A public PR needs a real, shareable positive, benign/adversarial negatives, passing official formatter and thorough linter, exact match results, and compatible pinned engine/rules versions. Otherwise produce a local triage report.
- Publish only new rule YAML and permitted test artifacts to a designated fork branch; never merge, push to an upstream branch, or modify an existing rule automatically.
- PowerShell script evidence is the first combined integration; Python then Bash follow the backend rollout. Binary rule generation must work before script support lands.

## Review Focus

- Issue text or retrieved pages containing tool instructions or fake role delimiters must remain cited data and cannot change tool/URL/command selection (Tasks 3, 6, 7).
- A ZIP attachment with `../` or a symlink must be rejected before extraction; no attachment is downloaded by default (Task 3).
- A model proposal with a fabricated source offset or sample hash must fail evidence validation even if YAML and lint pass (Tasks 5, 8, 9).
- A linter process that exits zero while its sample directory is empty must fail the PR gate (Task 8).
- A crash after branch push or two simultaneous triggers must reuse one idempotency key and at most one PR (Tasks 2, 12).

---

## File structure and stable interfaces

| Unit | Files and responsibility |
| --- | --- |
| CLI/config | `cmd/capa-rule-agent/main.go`, `internal/config/config.go`: manual, issue, feed, validate, and publish commands; dotenv and secret precedence. |
| Data contracts | `internal/request/model.go`, `internal/evidence/model.go`, `internal/proposal/model.go`, `internal/report/model.go`: versioned JSON records and strict validation. |
| Intake/state | `internal/intake/{manual,github,feed}.go`, `internal/state/sqlite.go`: bounded read-only intake, normalized provenance, durable dedupe/audit. |
| Evidence/grounding | `internal/evidence/capa.go`, `internal/grounding/retrieve.go`: pinned capa JSON, source locations, official documentation citations. |
| ADK workflow | `internal/agent/{workflow,prompt}.go`: structured proposal and bounded repair through an injectable model interface. |
| Validation | `internal/validate/{workspace,runner,quality,repair}.go`: fixed commands, isolated checkouts, positives/negatives, typed failures. |
| Publication | `internal/publish/{package,github}.go`: dry-run PR bundle, fork branch and PR idempotency. |
| Operations | `config/example.yaml`, `integration.lock.json`, `docs/{setup,security,operations}.md`, `.github/workflows/{tests,feeds}.yml`: reproducible run and release gates. |

**RuleRequest v1:** `RuleRequest{schema:1,id,origin:{kind,url,observed_at},capability,language?,samples:[{sha256,path?,shareable,role}],evidence:[EvidenceRef],sources:[URL]}`. Only a local operator may supply `path`; issue and feed payloads supply links and hashes. `EvidenceRef{id,sample_sha256,kind,value,address?,span?,capa_version,extractor_version?}`. `Proposal{schema:1,request_id,yaml,citations:[EvidenceRef|DocRef],uncertainty:[string]}`. `ValidationReport{schema:1,request_id,rule_sha256,lock_sha256,checks,positive_matches,negative_matches,logs,eligible,reason}`. Every model-supplied citation must join an existing evidence or grounding record by exact ID. The `integration.lock.json` pins capa commit/release, capa-rules commit, Go extractor protocol/grammar revision when applicable, agent revision, and sample-manifest hash.

## Tasks

### Task 1: Bootstrap a key-safe Go CLI and dry run

**Files:** Create `go.mod`, `go.sum`, `cmd/capa-rule-agent/main.go`, `internal/config/{config.go,config_test.go}`, `config/example.yaml`, `.gitignore`, `docs/setup.md`.

**Interfaces:** `Load(path string, getenv func(string) string) (Config,error)` reads a fixed `.env` path and `config/example.yaml` schema. `Config` carries `ModelName`, pinned checkout paths, fork/upstream coordinates, feed allowlist, limits, and `APIKey` as a secret field. CLI defaults to `--dry-run`; publishing requires an explicit `publish` subcommand plus an enabled config flag. Pin `google.golang.org/adk/v2` at a reviewed release.

- [ ] Write `TestConfigPrecedenceAndRedaction`: process `GOOGLE_API_KEY` wins, then process `GEMINI_API_KEY`, then `.env` in the same order; `fmt`/JSON/log output omits the key; dry-run with no key loads.
- [ ] Run `go test ./internal/config`; expect failure because `Load` does not exist. Install Go `>=1.25` in the execution environment first.
- [ ] Implement strict config loading and the dry-run CLI entry; ignore `.env`, local state, worktrees, and sample bytes in Git. Do not copy the planning workspace's key into the new repo.
- [ ] Run `go test ./internal/config ./cmd/capa-rule-agent` and `go mod verify`; expect pass.
- [ ] Commit `feat(agent): bootstrap Go CLI and safe config`.

### Task 2: Normalize versioned requests and durable idempotency

**Files:** Create `internal/request/{model.go,model_test.go}`, `internal/state/{sqlite.go,sqlite_test.go}`, `internal/report/model.go`, `testdata/requests/{binary,script}.json`; modify `go.mod`, `go.sum` for the pinned SQLite driver.

**Interfaces:** `Validate(req RuleRequest) error`, `Key(req RuleRequest) string` (SHA-256 of canonical origin ID plus capability plus sorted sample hashes), `Store.Claim(ctx,key) (claimed bool,error)`, `Store.Record(ctx,key,event AuditEvent) error`, `Store.Get(ctx,key) (RunState,error)`. SQLite uses a unique key and a transaction; schema migrations are versioned.

- [ ] Write `TestRequestAndClaim`: schema 1 binary/script fixtures validate; unknown schema, missing SHA-256, duplicate evidence ID, and an issue-supplied local path fail; two concurrent claims return exactly one `claimed=true`, with a persisted audit event after reopen.
- [ ] Run `go test ./internal/request ./internal/state`; expect missing model/store failures.
- [ ] Implement canonical JSON, validation, SQLite schema/migration, transactional claim and append-only audit events; cap lengths/counts before allocation.
- [ ] Run the targeted tests and `go test -race ./internal/state`; expect pass.
- [ ] Commit `feat(agent): version requests and deduplicate runs`.

### Task 3: Ingest allowlisted GitHub rule-idea issues

**Files:** Create `internal/intake/{github.go,github_test.go,attachment.go,attachment_test.go}`, `testdata/issues/{rule_idea,prompt_injection,attachment}.json`; update `config/example.yaml`.

**Interfaces:** `FetchIssues(ctx, client GitHubReader, repo Repo, labels []string, since time.Time) ([]request.RuleRequest,error)` reads only configured repositories and labels with pagination and ETag/cursor support. `InspectAttachment(meta AttachmentMeta, r io.Reader, policy AttachmentPolicy) (SampleRef,error)` accepts only operator-enabled MIME/size/host rules; default policy rejects downloads. A signed webhook is optional later; initial trigger is read-only polling.

- [ ] Write `TestIssueIntakeBoundary`: accepted `rule idea` issue becomes one request with URL/provenance; an unlabeled issue is skipped; fake instructions in issue text cannot alter repo/URL; over-limit pagination is bounded; default attachment download and ZIP traversal/symlink cases are rejected.
- [ ] Run `go test ./internal/intake -run 'TestIssue|TestAttachment'`; expect missing intake failures.
- [ ] Implement allowlisted GitHub reader, normalization, size caps, and safe attachment inspection. Do not fetch issue-linked arbitrary URLs or archives through the default path.
- [ ] Run the targeted tests; expect pass with fake HTTP only.
- [ ] Commit `feat(agent): ingest rule-idea issues safely`.

### Task 4: Accept analyst-supplied files and existing capa JSON

**Files:** Create `internal/intake/{manual.go,manual_test.go}`, `testdata/manual/{sample_request.json,capa_result.json}`; modify `cmd/capa-rule-agent/main.go`.

**Interfaces:** `FromLocal(ctx, path string, capability string, shareable bool) (request.RuleRequest,error)` hashes a regular file but never executes it; `FromCapaResult(ctx, path string, capability string) (request.RuleRequest,error)` imports recorded evidence. CLI `draft --sample <path> --capability <text>` or `draft --capa-json <path>` writes a normalized request in dry-run mode.

- [ ] Write `TestManualIntake`: a local binary and a preexisting capa JSON create valid requests with SHA-256 and analyst provenance; symlink, directory, >16 MiB script, and malformed JSON are rejected or bounded; no API key is required.
- [ ] Run `go test ./internal/intake -run TestManual`; expect missing functions.
- [ ] Implement local-path handling only for explicit manual CLI arguments and ensure no sample bytes enter logs or request JSON by default.
- [ ] Run targeted tests and `go run ./cmd/capa-rule-agent draft --capa-json testdata/manual/capa_result.json --capability example --dry-run`; expect a redacted request artifact.
- [ ] Commit `feat(agent): add manual evidence intake`.

### Task 5: Collect pinned capa evidence for binaries and scripts

**Files:** Create `internal/evidence/{model.go,capa.go,capa_test.go}`, `integration.lock.json`, `testdata/evidence/{binary.json,powershell.json}`.

**Interfaces:** `Analyze(ctx context.Context, sample SampleRef, lock Lock, runner CommandRunner) (EvidenceBundle,error)` executes only the fixed `capa -j -f <allowed-format> <sample-path>` argument vector in a network-disabled worker; `Import(data []byte, sampleSHA string, lock Lock) (EvidenceBundle,error)` validates a recorded result. `EvidenceBundle` contains normalized feature IDs, source addresses/spans, matched rules, parser diagnostics, tool versions, and sample hash.

- [ ] Write `TestCapaEvidence`: binary and PowerShell fixture JSON produce stable IDs and exact offsets; mismatched SHA, unsupported schema/format, missing parser version, fabricated offset, sample path outside the worker, and a fake runner asking for shell execution fail. A PowerShell fixture uses the backend's `script-call`/`statement` contract.
- [ ] Run `go test ./internal/evidence`; expect missing importer/runner failures.
- [ ] Implement strict result parsing and fixed command arguments; pin the exact engine/rules/helper versions in `integration.lock.json`. Keep binary import usable before the script backend release.
- [ ] Run the targeted tests and one local capa binary fixture if test data is present; expect pass and record skipped live fixtures honestly.
- [ ] Commit `feat(agent): normalize capa evidence`.

### Task 6: Ground API and command claims in bounded documentation

**Files:** Create `internal/grounding/{retrieve.go,retrieve_test.go}`, `testdata/grounding/{official_page.html,injected_page.html}`, `docs/security.md`; update `config/example.yaml`.

**Interfaces:** `Retrieve(ctx, query Query, policy Policy, fetch Fetcher) ([]DocRef,error)` accepts only operator-configured official domains and exact URL allowlist rules, returns URL/title/access time/content hash and bounded excerpts. A Google Search ADK tool may suggest candidate URLs; `Retrieve` enforces the policy before fetching. `DocRef` is cited by stable ID.

- [ ] Write `TestGroundingPolicy`: official docs yield a cited excerpt; redirect to an unapproved host, local address, oversized page, embedded instruction to run a command, and an uncertified URL all fail or remain inert data. Search queries use normalized evidence terms, never raw issue/sample text.
- [ ] Run `go test ./internal/grounding`; expect missing retriever failure.
- [ ] Implement URL/DNS/redirect checks, byte/time caps, HTML text extraction, and doc provenance; keep retrieved text out of validation commands.
- [ ] Run the targeted tests; expect pass with fake network.
- [ ] Commit `feat(agent): ground proposals in approved docs`.

### Task 7: Generate structured rule proposals with ADK Go v2

**Files:** Create `internal/proposal/{model.go,model_test.go}`, `internal/agent/{workflow.go,workflow_test.go,prompt.go}`, `prompts/rule_draft_v1.txt`, `testdata/model/{valid,invalid,injection}.json`; modify `go.mod`, `go.sum` for the pinned YAML parser if the standard library is insufficient.

**Interfaces:** `Model.Draft(ctx, DraftInput) (proposal.Proposal,error)` is injectable; `Draft(ctx, req, evidence, docs, model) (proposal.Proposal,error)` invokes an ADK Go v2 workflow with a Gemini model in production and a fake model in tests. Output is schema 1 with rule YAML, exact evidence/doc citations, uncertainty, and request ID; use a pinned model ID and max output tokens in config.

- [ ] Write `TestDraftCitations`: fake model returns a valid binary proposal; unknown citation, raw command/tool instruction, malformed YAML, wrong request ID, and prompt-injected issue text are rejected or treated as data. Assert raw source is absent from `DraftInput` unless per-run sharing is enabled and allowed.
- [ ] Run `go test ./internal/agent ./internal/proposal`; expect missing model/workflow failures.
- [ ] Implement the ADK workflow and structured output parser; allow only the grounding tool, never shell or arbitrary file tools. Keep model calls behind `Model` so tests use no key/network.
- [ ] Run targeted tests and `go vet ./internal/agent`; expect pass.
- [ ] Commit `feat(agent): draft cited rules with ADK`.

### Task 8: Run official formatter, linter, and sample tests in isolation

**Files:** Create `internal/validate/{workspace.go,runner.go,runner_test.go}`, `testdata/validation/{lint_failure.txt,positive.json,negative.json}`; update `docs/setup.md`.

**Interfaces:** `Validate(ctx, proposal, req, lock, runner) (report.ValidationReport,error)` creates a disposable checked-out rules worktree at the pinned commit and writes one new YAML file under an allowlisted rules path. It executes fixed argument vectors for `python scripts/capafmt.py -c <rule>`, `python scripts/lint.py --thorough --samples <populated-sample-dir> <rules-dir>`, and capa positive/negative scans; no shell. `CommandRunner` records command, exit status, bounded stdout/stderr, and elapsed time.

- [ ] Write `TestDeterministicRunner`: formatter drift, lint error, empty samples directory despite exit 0, a missing real positive, and one negative match mark `eligible=false`; a good binary fixture records exact positive/negative matches and versions. Reject a YAML path escape and a malicious filename without invoking a shell.
- [ ] Run `go test ./internal/validate -run TestDeterministicRunner`; expect missing validator failure.
- [ ] Implement isolated worktree setup, fixed tools, time/memory/output caps, parsed diagnostics, and cleanup. Keep `--thorough` mandatory for eligibility, using the initialized `capa-testfiles` tree or a permitted, hash-verified sample directory.
- [ ] Run targeted tests and a local dry-run against a pinned, populated fixture directory; expect a report with command logs and no publication.
- [ ] Commit `feat(agent): validate rules with capa tooling`.

### Task 9: Enforce evidence, sample rights, and duplicate quality gates

**Files:** Create `internal/validate/{quality.go,quality_test.go}`, `testdata/validation/{duplicate_rule.yml,overlap_rule.yml,script_mismatch.json}`.

**Interfaces:** `QualityGate(req, proposal, evidence, corpus, existingRules, report) report.ValidationReport` checks exact citation joins, source offsets, public sharing, one real positive, several benign/adversarial negatives, zero negative matches, and rule overlap. A new script rule additionally requires compatible script feature/scope release and the matching `format` condition.

- [ ] Write `TestQualityGate`: reject fabricated evidence, synthetic-only positive, private-only positive, missing/duplicate negatives, overlap with an existing rule, script rule without `format`, and incompatible engine revision; accept a distinct binary rule with one real public positive and at least two benign plus one adversarial negative.
- [ ] Run `go test ./internal/validate -run TestQualityGate`; expect missing gate failure.
- [ ] Implement policy checks over parsed rule AST/metadata and recorded match sets; classify borderline duplicate/semantic cases for human triage rather than automatic PR.
- [ ] Run targeted tests; expect pass and explicit failure reasons in the report.
- [ ] Commit `feat(agent): gate evidence and rule quality`.

### Task 10: Repair syntax failures within a fixed budget

**Files:** Create `internal/validate/{repair.go,repair_test.go}`, `testdata/model/{repair_good,repair_loop}.json`.

**Interfaces:** `Repair(ctx, req, proposal, failures []TypedFailure, model Model, validator Validator) (proposal.Proposal,report.ValidationReport,error)` permits at most three total draft/validation attempts; only the candidate YAML may change. Evidence, sample paths, command list, citations, and rule destination are immutable from the original request. Only formatter/schema/lint failures are model-repairable; sample misses, duplicate/rights failures, and missing evidence end in triage.

- [ ] Write `TestRepairBudget`: a syntax error is fixed on attempt 2; identical YAML or three failures stop; sample-negative and fabricated-citation failures never call the model again; a model-suggested shell command is ignored.
- [ ] Run `go test ./internal/validate -run TestRepairBudget`; expect missing repair loop failure.
- [ ] Implement typed error projection and bounded ADK retry state; attach every attempt to the audit trail without raw sample text.
- [ ] Run targeted tests; expect pass with a fake model/runner.
- [ ] Commit `feat(agent): bound rule repair attempts`.

### Task 11: Build a reviewable dry-run PR package

**Files:** Create `internal/publish/{package.go,package_test.go}`, `testdata/publish/{expected_body.md,eligible_report.json}`, `docs/operations.md`.

**Interfaces:** `Package(req, proposal, report, lock) (PRPackage,error)` emits one rule YAML, a branch name and body marker derived from the idempotency key, and Markdown PR body containing issue/feed links, capability rationale, source evidence offsets/hashes, sharing status, exact tool versions, formatter/linter summaries, positive/negative results, uncertainties, and maintainer decisions. Non-eligible reports return an error and a local triage bundle.

- [ ] Write `TestPRPackage`: eligible report produces deterministic files/body and `closes` issue link only for an issue origin; a failed lint, private sample, or missing lock hash produces no publishable package. Assert no API key or raw sample bytes appear.
- [ ] Run `go test ./internal/publish -run TestPRPackage`; expect missing packager failure.
- [ ] Implement deterministic package rendering and content hashing; CLI `validate --dry-run` writes this bundle to an ignored output directory.
- [ ] Run targeted tests and inspect one dry-run bundle; expect exact hashes and no network calls.
- [ ] Commit `feat(agent): package verified PR drafts`.

### Task 12: Publish idempotently to a designated fork

**Files:** Create `internal/publish/{github.go,github_test.go}`, `testdata/publish/{existing_pr,create_pr}.json`; modify `internal/state/sqlite.go`, `cmd/capa-rule-agent/main.go`.

**Interfaces:** `Publish(ctx, pkg PRPackage, gh GitHubWriter, store *state.Store, policy PublishPolicy) (PRRef,error)` checks `eligible`, rechecks pinned head/base and existing PR by key, creates/updates one fork branch containing only packaged files, and opens a PR against `mandiant/capa-rules` with the package body. Use a GitHub App installation token scoped to fork contents write and upstream PR creation/read; token never enters logs.

- [ ] Write `TestPublishIdempotency`: two concurrent publish calls produce one PR; retry after branch push finds/reuses branch; changed validation hash requires a fresh validation report; wrong upstream, protected branch, or non-eligible report fails before any write.
- [ ] Run `go test ./internal/publish -run TestPublishIdempotency`; expect missing publisher failure.
- [ ] Implement CAS state transitions and GitHub API adapter with fake HTTP tests; keep `publish` disabled unless operator config and CLI both permit it. Never merge or write upstream branches.
- [ ] Run targeted tests and `go test -race ./internal/publish ./internal/state`; expect pass, then perform only a fork/sandbox dry-run before enabling real publication.
- [ ] Commit `feat(agent): publish verified rules to fork PRs`.

### Task 13: Add daily allowlisted public-feed intake

**Files:** Create `internal/intake/{feed.go,feed_test.go}`, `testdata/feeds/{rss.xml,atom.xml,report.json,injected.xml}`; modify `cmd/capa-rule-agent/main.go`, `config/example.yaml`; create `.github/workflows/feeds.yml`.

**Interfaces:** `PollFeeds(ctx, policy FeedPolicy, fetch Fetcher, store *state.Store) ([]request.RuleRequest,error)` supports RSS, Atom, and configured JSON field maps, records URL/title/publish time/content hash, enforces HTTPS/host/redirect/size limits, and deduplicates with `state.Key`. Scheduled workflow runs daily and includes a read-only `capa-rules` issue scan plus one operator-approved public threat-report feed fixture; no default payload download.

- [ ] Write `TestFeedPoll`: each format normalizes provenance; repeated item or changed order yields one request; off-domain link, old/oversized item, prompt instructions in a summary, and feed failure cannot select a new URL or download a payload.
- [ ] Run `go test ./internal/intake -run TestFeed`; expect missing feed adapter failure.
- [ ] Implement bounded parsers, rate/backoff and dedupe; wire scheduled job to dry-run/triage by default with configured feed allowlist and secret store.
- [ ] Run targeted tests and a fixture-backed daily workflow replay; expect no GitHub write or model call unless separately enabled.
- [ ] Commit `feat(agent): poll approved feeds daily`.

### Task 14: Replay binary and PowerShell flows, audit security and operations

**Files:** Create `tests/integration/{binary_flow_test.go,powershell_flow_test.go}`, `testdata/replays/{binary,powershell}/`; modify `integration.lock.json`.

**Interfaces:** `Replay(ctx, requestFixture, evidenceFixture, fakeModel, fakeRunner, fakeGitHub) (report.ValidationReport,error)` tests intake → evidence → draft → validate → package with no network. The PowerShell case uses the backend v1 protocol and a real, rights-reviewed `.ps1` positive plus three negatives; Python and Bash are added to this same matrix after their backend gates.

- [ ] Write `TestBinaryFlow` and `TestPowerShellFlow`: both yield source or binary evidence citations, exact positive match, zero negative matches, formatter/linter pass, and one dry-run PR package; injection, missing helper, incompatible lock, parser timeout, and absent sample rights yield triage only.
- [ ] Run `go test ./tests/integration`; expect failure for the missing replay harness or integration gap.
- [ ] Implement fixture replay and compatibility lock checks; record the exact capa, rules, helper, and agent revisions in each report.
- [ ] Run `go test ./tests/integration`, `go test -race ./...`, and `go vet ./...`; expect pass for binary and PowerShell fixture flows.
- [ ] Commit `test(agent): replay binary and PowerShell rule flows`.

### Task 15: Ship CI, redacted audit, and operator controls

**Files:** Create `internal/report/{audit.go,audit_test.go}`, `.github/workflows/tests.yml`; modify `docs/security.md`, `docs/operations.md`, `config/example.yaml`, `integration.lock.json`, `internal/publish/{github.go,github_test.go}`.

**Interfaces:** `ExportAudit(run state.RunState, cfg config.Config) ([]byte,error)` emits event IDs, hashes, versions, decisions, and bounded diagnostics with no credentials or raw samples. `DisablePublication` is an operator config switch checked before any GitHub write. CI runs Go race/vet/tests, bounded parser fuzz tests, and integration replays; a separate manual workflow evaluates capped public fixtures against live Gemini and saves cost and quality metrics.

- [ ] Write `TestRedactedAuditAndKillSwitch`: an audit containing key-like strings and a private sample omits both; a disabled publisher makes zero GitHub write calls; a parser fuzz seed with a huge feed or issue stays bounded.
- [ ] Run `go test ./internal/report ./internal/publish -run 'TestRedactedAudit|TestKillSwitch'`; expect missing audit/kill-switch failures.
- [ ] Implement audit export, disable switch, CI jobs, and the runbook for dry-run, scheduled feeds, manual approval, rollback, and sample provenance. Review prompt injection, archives, privacy, command confinement, resource limits, secrets, and GitHub permissions.
- [ ] Run `go test -race ./...`, `go vet ./...`, bounded fuzz tests for request/feed/issue parsers, and CI; run a separately budgeted live Gemini quality evaluation with a capped public fixture set. Record precision/recall, token cost, false positives, and any unrun gate.
- [ ] Commit `build(agent): add operational and security gates`.

## Agent completion gate

An operator can run a binary issue/manual flow without the script backend, then a PowerShell flow with it, and obtain a redacted dry-run PR package. Public publication remains disabled until the official formatter, thorough linter with a populated sample directory, exact positive/negative tests, rights, duplicate check, compatibility lock, and human review fields all pass. Maintain the package, audit report, and CI evidence with the PR; never treat a live Gemini answer as a substitute for deterministic validation.
