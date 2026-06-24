# capa rule agent — initial local delivery

This Go module prepares evidence-grounded capa rule candidates, validates them using installed capa tooling, and writes private review bundles. Samples are hashed and parsed by capa; their code is never executed. Raw source and local sample paths are excluded from model input. Model/network calls occur only with explicit `draft --live`.

Requires Go **1.26.6+** (pinned ADK v2.6.0 minimum), Python with the external patched capa runtime installed (`python -m capathy setup`), and a built script helper for script analysis.

```sh
cd agent
go build -o bin/capa-rule-agent ./cmd/capa-rule-agent
go test -race ./...
go vet ./...
./bin/capa-rule-agent version
```

## Offline intake

```sh
./bin/capa-rule-agent draft --sample /absolute/sample.ps1 --capability 'download a file' --dry-run --out out-request.json
./bin/capa-rule-agent draft --capa-json /absolute/result.json --capability 'download a file' --out out-request.json
```

The output is a schema 1 request. Source bytes are excluded. Script capa results require `meta.analysis.script` parser provenance. Imported sample paths and rights claims are ignored: operators must explicitly supply local validation sample paths, roles (`positive`, `benign`, `adversarial`), `shareable`, and `real` attestations before validation. Imported evidence retains exact hash, original byte offsets, parser version and stable citation IDs.

## Drafting

Replay a recorded proposal without credentials/network, or explicitly call Gemini through ADK or Claude through the Messages API:

```sh
./bin/capa-rule-agent draft --request out-request.json --proposal recorded-proposal.json
./bin/capa-rule-agent draft --request out-request.json --provider gemini --live --env-file /absolute/private/.env
./bin/capa-rule-agent draft --request out-request.json --provider claude --live --env-file /absolute/private/.env
```

Select `--provider gemini` (the default) or `--provider claude`. Claude defaults to `claude-haiku-5-5` and uses `ANTHROPIC_API_KEY` or `CLAUDE_API_KEY`; Gemini uses `GOOGLE_API_KEY` or `GEMINI_API_KEY`. Process credentials take precedence over the selected dotenv file, and keys are never shared between providers. Credentials are hidden from formatting/JSON. `CAPA_AGENT_MODEL` selects a model (default `gemini-3.8-flash`). Both providers request a closed JSON schema with the exact request ID and known evidence IDs. Calls have deadlines, bounded input/output and no tools. Gemini 3 drafting uses low reasoning and omits deprecated sampling parameters; provider failures expose only a safe HTTP status. Strict output rejects invented citations and command/tool fields.

```json
{
  "schema": 1,
  "request_id": "copy exact request id",
  "yaml": "complete capa rule YAML",
  "citations": ["copy exact existing evidence IDs"],
  "uncertainty": ["review required"]
}
```

## Deterministic local validation

Prepare a request with at least one genuine public positive, two distinct benign negatives and one adversarial negative, all with SHA-256 and sharing attestations. Copy `integration.lock.example.json`, fill exact capa/rules/agent revisions, and compute the manifest hash:

```sh
./bin/capa-rule-agent manifest --request validation-request.json
./bin/capa-rule-agent validate --request validation-request.json --proposal candidate.json --lock integration.lock.json --python /absolute/capathy/.venv/bin/python --capa-root /absolute/external-capa-runtime --rules-root /absolute/approved-rules --samples /absolute/approved-corpus --out out/review --dry-run
```

Validation rehashes/constrains every sample, checks checkout pins, creates a disposable rules worktree, writes one nursery candidate, checks duplicate names, runs official `capafmt.py -c`, `lint.py --thorough` against the populated corpus/full rules worktree, then scans every positive/negative sample using fixed argument vectors. No shell; credentials excluded from child environments; capped time/output. A network namespace and OS memory sandbox are not yet provided; use a separately isolated worker for untrusted corpus processing.

Reports bind exact request/candidate/lock hashes. Failed gates produce private ineligible triage bundles. Semantic overlap needs explicit human review. After reviewing the exact candidate against the pinned rules corpus, use `review-key --proposal candidate.json --lock integration.lock.json`, then pass its value as `validate --semantic-review KEY`. Without this attestation the final gate stays ineligible. Eligible validation with `--out` also writes deterministic `package.json` and `PR.md`. Checkout pins must be clean; modified development checkouts produce triage. `publish` always returns an explicit disabled error; no GitHub write path exists.

## Durable audit

```sh
./bin/capa-rule-agent audit --state state.db --key REQUEST_KEY --claim
./bin/capa-rule-agent audit --state state.db --key REQUEST_KEY
```

SQLite claims are transactional/unique under concurrent workers, and audit events survive reopening. Audit is currently operator-driven; automatic pipeline resumption is pending.

## Current limits

This is an initial implementation, not all 15 roadmap tasks. No external publication, live Gemini quality evaluation, automated semantic overlap review, CLI-wired repair automation, scheduled feed polling, OS resource sandbox, or public sample corpus has been completed. Tests use fake models/runners or local files; synthetic positives never qualify as genuine public samples. Live detection precision/recall is unmeasured. Example YAML config documents defaults; runtime settings are CLI flags/environment.

## Public report intake and documentation grounding

Recorded public-source intake is read-only and never follows attachments/payload links:

```sh
./bin/capa-rule-agent issues --fixture issues.json --repo mandiant/capa-rules
./bin/capa-rule-agent feed --fixture feed.xml --url https://reports.example/feed --allow-hosts reports.example
```

Issues require the `rule idea` label and an allowlisted repository. RSS, Atom and JSON item arrays are bounded; report links require HTTPS and an approved host. Provenance and durable request keys are preserved; issue/feed requests without sample evidence remain triage ideas, never publishable rules. Network polling/scheduling is pending.

Explicit documentation retrieval supports only operator-approved exact URLs on learn.microsoft.com, docs.python.org and www.gnu.org:

```sh
./bin/capa-rule-agent ground --url https://docs.python.org/3/library/subprocess.html --allow-url https://docs.python.org/3/library/subprocess.html
```

The fetcher forbids redirects/proxies, resolves and connects only to public IPs, caps bytes/time, strips HTML scripts/styles and records content hashes/excerpts. Retrieved text remains inert data. Doc references are emitted for analyst review; automatic documentation citation incorporation into model proposals is pending.

The library also provides a bounded repair controller: at most three total validation attempts, formatter/schema/lint failures only, immutable request/evidence/citations/uncertainty, no retries on sample or rights failures, and repeated YAML terminates. It is covered by offline tests and is not yet wired to the production validation CLI.

The Capathy repository no longer vendors capa. Obtain the clean, patched engine path with `python -m capathy runtime-path`; pin its HEAD as `capa_revision`. The rules repository is a separate operator-managed checkout.

A live Claude Haiku 5.5 smoke test generated a PowerShell rule and passed two synthetic positive and three synthetic negative checks. This is a functional smoke test, not a real-corpus accuracy evaluation. Gemini 2.5 access was rejected for this account; Gemini 3.8 requests timed out during the same session.
