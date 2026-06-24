# Capathy

**Structural script analysis and evidence-grounded capability-rule tooling.**

Capathy parses PowerShell, Python, and Bash without executing them, matches source evidence against YAML capability rules, and helps an analyst draft and validate new rules. The parser and agent are Go programs. Rule matching uses a separately downloaded, pinned [Mandiant capa](https://github.com/mandiant/capa) engine.

This repository contains Capathy's tools, integration patch, adapters, tests, and examples. The full upstream capa codebase is not vendored here or inherited by the current branches.

Maintained by [Mordaax](https://github.com/Mordaax). The commit sequence is a **retrospective reconstruction** dated May 24–June 24, 2026; these dates organize the imported implementation and do not establish when it was developed. See [HISTORY.md](HISTORY.md).

## What can I use it for?

| Use | Example | Result |
| --- | --- | --- |
| Triage a PowerShell script | Find an actual `Invoke-WebRequest` command | A capability match with the original source offset |
| Review Python automation | Resolve `import requests as r; r.get(url)` conservatively | A `requests.get` call observation with provenance |
| Inspect a shell script | Recognize `curl "$url"` and a pipeline | Calls, variable reads, structures, and literal evidence |
| Reduce text-search false positives | Put `Invoke-WebRequest` only in a comment or quoted message | No command-call feature for that text |
| Write a structural rule | Require two calls in the same statement | A rule that cannot combine unrelated statements accidentally |
| Investigate uncertainty | Analyze `& $cmd` or `"$cmd"` | Diagnostics instead of a guessed concrete command target |
| Draft a rule from evidence | Import capa JSON and supply a capability description | A request with stable evidence citation IDs |
| Validate a candidate | Check a real positive and benign/adversarial negatives | A detailed eligible or ineligible local report |
| Prepare analyst review | Package a candidate after all required checks | Candidate YAML, validation records, and a local PR description |

A structural observation is not a verdict that a script is malicious. The bundled examples are synthetic demonstrations, not an evaluated malware corpus.

## Architecture and repository layout

```text
                             this repository
script ──> Go Tree-sitter parser ──> versioned source evidence
                                               │
                                               ▼
                                external patched capa engine
                                               │
                                               ▼
                           capability report + evidence offsets
                                               │
                                               ▼
                             Go rule agent ──> local review bundle
```

| Location | Contents |
| --- | --- |
| `native/script/` | Standalone Go extractor and pinned grammars |
| `agent/` | Go ADK/Gemini adapter, intake, validation, audit, and packaging |
| `capathy/` | Python launcher and external-runtime setup |
| `capathy/integrations/capa/` | Upstream revision, checksums, focused patch, and four new adapter files |
| `examples/scripts/` | PowerShell, Python, and Bash demonstration inputs |
| `examples/script-rules/` | Capability rules used by the examples |
| `tests/` | Capathy's own integration and runtime-verification tests |
| `docs/` | Design, usage, implementation records, and remaining release gates |

## Build and first run

Requirements: Git, Python 3.10+, Go 1.26.6+ to build both Go tools, and a C compiler for the Tree-sitter bindings. The commands below use a POSIX shell.

```sh
git clone https://github.com/Mordaax/capathy.git
cd capathy
python3 -m venv .venv
.venv/bin/python -m pip install -e .
scripts/build-script-tools.sh
.venv/bin/python -m capathy setup

.venv/bin/python -m capathy analyze \
  -f powershell -r examples/script-rules -vv examples/scripts/request.ps1
```

The build script produces:

- `native/script/bin/capa-script-extractor`
- `agent/bin/capa-rule-agent`

`setup` fetches the pinned upstream engine into `~/.cache/capathy/` (or `$XDG_CACHE_HOME/capathy/`), checks the integration patch and adapter hashes, applies them, creates a reproducible integration commit, and installs the engine's Python dependencies into the active environment. It does not fetch sample files, initialize rule/test-data submodules, or call Gemini.

```sh
# Show the external engine used by this installation.
.venv/bin/python -m capathy runtime-path

# Reuse an existing git clone as the source of the pinned upstream commit.
.venv/bin/python -m capathy setup --source /path/to/existing/capa-clone

# Prepare the checkout without installing its Python dependencies.
.venv/bin/python -m capathy setup --no-install
```

`CAPATHY_CAPA_ROOT` chooses an alternative external runtime location. An existing runtime must match the exact recorded integration commit and contain no tracked modifications or untracked files. The engine remains an external dependency; installing unmodified stock capa alone does not add Capathy's statement scope or script features.

## Feature 1: analyze three script languages

### PowerShell: inspect a direct cmdlet call

The bundled source contains:

```powershell
Invoke-WebRequest -Uri 'https://example.invalid/'
```

Run:

```sh
.venv/bin/python -m capathy analyze \
  -f powershell -r examples/script-rules -vv examples/scripts/request.ps1
```

The demonstration reports:

```text
issue web request from PowerShell source
statement @ file+0x3A
  and:
    format: powershell
    script-call: invoke-webrequest @ file+0x3A
```

Use this to locate a command in a script during triage or code review. PowerShell names use Unicode case-folding. A single, unconditional literal `Set-Alias`/`New-Alias` definition can resolve later calls when the binding is unambiguous; uncertain mutations reduce canonicalization.

### Python: inspect calls and conservative import aliases

```python
import requests
requests.get('https://example.invalid/')
```

```sh
.venv/bin/python -m capathy analyze \
  -f python -r examples/script-rules -vv examples/scripts/request.py
```

The rule matches `script-call: requests.get`. The parser can also resolve a top-level `import requests as r` followed by `r.get(...)` when assignment, parameters, or other ambiguous bindings do not invalidate the alias. This is useful for reviewing automation that uses standard client libraries. It is conservative syntax analysis, not proof of runtime object identity.

### Bash: inspect commands, variables, and pipelines

```bash
curl 'https://example.invalid/'
```

```sh
.venv/bin/python -m capathy analyze \
  -f bash -r examples/script-rules -vv examples/scripts/request.sh
```

The rule matches `script-call: curl`. Pipelines such as `curl "$url" | cat` can carry multiple command observations plus a variable read and pipeline structure. Use this for shell-script inventory and capability review.

## Feature 2: obtain evidence without capa

The Go extractor can run independently of the Python engine:

```sh
native/script/bin/capa-script-extractor --version
native/script/bin/capa-script-extractor analyze --language powershell \
  < examples/scripts/request.ps1
```

Its schema 1 JSON includes:

| Data | Example or purpose |
| --- | --- |
| Sample identity | SHA-256 and original byte length |
| Parser provenance | Extractor, grammar, and normalization versions |
| Functions | Named functions and a separate executable top-level region |
| Statements | Source intervals and `(start_byte, ordinal)` identities |
| Features | A direct call such as `invoke-webrequest`, with source node and span |
| Diagnostics | Parse errors and unresolved/dynamic constructs |

Intervals are half-open byte ranges in the original file. UTF-8 and BOM-marked UTF-16LE/BE are supported; a multibyte character does not turn an offset into a character index. This output can feed another analysis system or an analyst's own evidence viewer.

## Feature 3: match structural YAML rules

Script rules support these features:

| Feature | Example | Typical use |
| --- | --- | --- |
| `script-call` | `invoke-webrequest`, `requests.get`, `curl` | Require an observed concrete call |
| `script-variable/read` | A normalized variable identifier | Locate reads within a relevant statement |
| `script-variable/write` | A normalized variable identifier | Locate assignments separately from reads |
| `script-structure` | `assignment`, `pipeline`, `branch`, `loop`, `try`, `redirection`, `command-substitution` | Constrain source shape |
| `string` | A literal URL or argument | Combine a literal with structural evidence |
| `number` | A literal integer | Match relevant literal configuration |

For example, a rule can require two directly observed commands in one PowerShell statement:

```yaml
rule:
  meta:
    name: request content and start a process in one pipeline
    namespace: execution/script
    authors:
      - Mordaax
    scopes:
      static: statement
      dynamic: unsupported
  features:
    - and:
      - format: powershell
      - script-call: invoke-webrequest
      - script-call: start-process
      - script-structure: pipeline
```

Load your rule directory with `-r /path/to/rules`. This example identifies a source pattern; it does not prove that downloaded content was executed.

A **statement** rule evaluates one statement at a time. A **function** rule can combine observations from multiple statements in that function. A **file** rule can consume matched lower-scope rules. A statement cannot be treated as a binary instruction/basic block, and separate statements cannot satisfy one statement-level `and` rule by pooling their evidence. Required `format` guards are checked by the integrated rule linter.

## Feature 4: distinguish text from behavior and expose uncertainty

A comment or quoted string containing a command name is not itself a command call:

```powershell
# Invoke-WebRequest -Uri 'https://example.invalid/'
Write-Host 'Invoke-WebRequest'
```

The demonstration web-request rule does not match this merely because the text appears. Conversely, a computed invocation such as `& $cmd` or Bash `"$cmd"` is unresolved; the parser records uncertainty instead of inventing a concrete target.

Other conservative cases include ambiguous aliases, Python reflection/shadowing, splatting, encoded PowerShell payloads, and malformed syntax. Encoded input payloads are not executed or dynamically unpacked. Inspect diagnostics when a capability might be hidden behind runtime behavior.

## Feature 5: preserve source evidence in reports

```sh
mkdir -p out
.venv/bin/python -m capathy analyze \
  -f powershell -r examples/script-rules -j examples/scripts/request.ps1 \
  > out/powershell.json
```

`-vv` shows matched evidence and original file offsets. JSON keeps the source evidence under `meta.analysis.script`, including parser metadata and diagnostics. Protobuf conversions preserve the new features and source layout. Script freezes use version 4; existing binary version 3 freezes remain supported. These formats are useful for retaining an analysis result, comparing extractor revisions, or sharing precise evidence with a reviewer.

## Feature 6: import evidence into a local rule request

```sh
.venv/bin/python -m capathy agent draft \
  --capa-json out/powershell.json \
  --capability 'issue a web request from PowerShell' \
  --out out/request.json
```

The request contains stable evidence IDs, sample hashes, versions, and source spans. Imported sample paths and sharing assertions are not trusted as operator attestations.

You can also register a local file without executing it:

```sh
.venv/bin/python -m capathy agent draft \
  --sample examples/scripts/request.ps1 \
  --capability 'issue a web request from PowerShell' \
  --out out/sample-request.json
```

The sample-only command hashes the file; import capa results before asking the model to draft from behavioral evidence. Sample contents do not become request JSON. Sharing and genuine-positive status default to false; do not attest that synthetic examples are real positives.

Existing binary capa JSON can also supply evidence for PE, ELF, or .NET rule work. For binary analysis, provide a compatible external rules checkout with `-r`; the upstream rules repository is not included here.

## Feature 7: replay drafts offline or explicitly use Gemini

For deterministic replay, provide a recorded proposal with this shape:

```json
{
  "schema": 1,
  "request_id": "copy the exact request id",
  "yaml": "complete capa YAML rule",
  "citations": ["copy an existing evidence id"],
  "uncertainty": ["Explain what still needs analyst review"]
}
```

```sh
.venv/bin/python -m capathy agent draft \
  --request out/request.json --proposal out/recorded-proposal.json
```

This path makes no model calls and requires no API key. Unknown or duplicate citations, a wrong request ID, unsupported fields, and malformed rule YAML are rejected. It is useful for reproducible tests and reviewing a saved model response.

Hosted drafting is opt-in:

```sh
.venv/bin/python -m capathy agent draft \
  --request out/request.json --live --env-file /absolute/private/.env
```

The pinned Go ADK Gemini adapter receives normalized evidence and the capability description; raw source and local sample paths are excluded from its input. It has no shell/file execution tools, bounds input/output, and rejects attempted tool/code responses. A model proposal still has to pass deterministic validation.

Credential precedence is process `GOOGLE_API_KEY`, process `GEMINI_API_KEY`, then those names in the explicitly selected dotenv file. `CAPA_AGENT_MODEL` selects a model; the configured default is `gemini-2.5-flash`, whose live availability and quality have not been evaluated for this release. Never put credentials in a rule request or commit them.

## Feature 8: validate a candidate against a reviewed corpus

A candidate can qualify for a local review package only with:

- At least one genuine, shareable positive sample.
- At least two distinct benign negatives and one adversarial negative.
- Operator-supplied local sample paths, verified hashes, and sharing attestations.
- Pinned, clean engine and rules checkouts plus a sample-manifest digest.
- Passing official formatter and thorough linter checks.
- An exact candidate match on every positive and no negative matches.
- Valid evidence citations, compatible helper/schema metadata, and an explicit human semantic-overlap review.

Prepare a validation request and fill `agent/integration.lock.example.json` with your real revisions. The external engine path comes from `python -m capathy runtime-path`.

```sh
# Obtain the sample-manifest digest for your reviewed request.
.venv/bin/python -m capathy agent manifest --request /approved/validation-request.json

# Run installed tools against a disposable rules worktree.
.venv/bin/python -m capathy agent validate \
  --request /approved/validation-request.json \
  --proposal /approved/candidate.json \
  --lock /approved/integration.lock.json \
  --python "$PWD/.venv/bin/python" \
  --capa-root "$(.venv/bin/python -m capathy runtime-path)" \
  --rules-root /approved/capa-rules \
  --samples /approved/sample-corpus \
  --out out/review --dry-run
```

Validation confines and rehashes samples, verifies returned sample identities, uses fixed argument vectors, and writes one safe candidate filename without overwriting an existing rule. A disposable, pinned rules worktree isolates candidate changes. Time/output limits and subprocess credential filtering are enforced.

Without semantic review, the report remains ineligible. After actually reviewing overlap against the pinned corpus, obtain the exact candidate/corpus attestation key with `agent review-key --proposal ... --lock ...` and pass its `semantic_review` value to `validate --semantic-review KEY`. A key records an operator assertion; it does not automate that review.

## Feature 9: produce local review packages and triage reports

An ineligible run writes a private local bundle with `request.json`, `proposal.json`, `validation.json`, and `candidate.yml`. The report records reasons such as a missed positive, a negative match, changed samples, dirty tools, or a missing review.

An eligible run additionally writes `package.json` and `PR.md`, binding the request, rule, lock, and validation digests. This is useful for handing a reproducible candidate to a human maintainer. The publisher remains disabled: a local PR description does not mean anything has been uploaded or merged.

## Feature 10: maintain durable claims and audit decisions

```sh
.venv/bin/python -m capathy agent audit \
  --state out/state.db --key REQUEST_KEY --claim
.venv/bin/python -m capathy agent audit \
  --state out/state.db --key REQUEST_KEY
```

SQLite admits a claim once under concurrent workers and preserves audit events across reopening. Request keys are stable across input ordering. This supports duplicate prevention in an analyst's own scheduler; automatic end-to-end resume is not wired into the current CLI.

## Feature 11: normalize recorded issues and public report feeds

Recorded GitHub issue intake accepts the allowlisted `mandiant/capa-rules` repository and the `rule idea` label. A small fixture can look like:

```json
[{"number": 1, "title": "recognize a script capability", "labels": [{"name": "rule idea"}]}]
```

```sh
.venv/bin/python -m capathy agent issues \
  --fixture /path/to/issues.json --repo mandiant/capa-rules
```

RSS, Atom, and JSON feed arrays are also supported. For example:

```json
[{"title": "Analysis report", "url": "https://reports.example/analysis/1"}]
```

```sh
.venv/bin/python -m capathy agent feed \
  --fixture /path/to/feed.json \
  --url https://reports.example/feed --allow-hosts reports.example
```

These commands retain source URLs and durable identities, enforce bounds and host policy, and do not follow payload or attachment links. They are useful for turning an existing report queue into triage ideas. Ideas without sample evidence cannot become eligible proposals. Live polling and scheduled feed processing are not implemented.

## Feature 12: retrieve bounded documentation for analyst grounding

```sh
.venv/bin/python -m capathy agent ground \
  --url https://docs.python.org/3/library/subprocess.html \
  --allow-url https://docs.python.org/3/library/subprocess.html
```

Retrieval requires an exact approved URL on an allowed official domain (`learn.microsoft.com`, `docs.python.org`, or `www.gnu.org`). The fetcher rejects redirects/proxies and non-public resolved addresses, bounds bytes/time, strips scripts/styles, and records a document ID, URL, title, content hash, access time, and excerpt.

Use this to retain source attribution for an analyst's command/API interpretation. Retrieved text is inert data. Automatic incorporation of these documentation citations into model proposals is pending.

## Feature 13: bound repair attempts and processing resources

The repair library permits at most three total validation attempts. Only syntax/formatter/lint failures are repairable. Request evidence, sample identity, citations, and destination remain fixed; a sample mismatch, missing rights, fabricated citation, repeated YAML, or exhausted budget terminates the flow. This controller is tested as a library and is not yet connected to the production validation CLI.

The parser caps input at 16 MiB, JSON output at 32 MiB, parsing at 15 seconds, visited AST nodes at 500,000, and nesting at 512. The Python adapter separately bounds both helper output pipes and a subprocess deadline and checks hashes, schema, language, intervals, identities, and provenance before constructing features. Processing samples does not execute them. A hard OS memory/network sandbox is not provided by these application-level limits.

## Test and verify

```sh
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
(cd native/script && go test -race ./... && go vet ./... && go mod verify)
(cd agent && go test -race ./... && go vet ./... && go mod verify)
```

The standalone suite currently has 63 Python tests. The Go suites cover parser behavior, source maps, intake, citation validation, concurrency, deterministic validation/package replay, and failure gates. Local demos cover all three languages and reject the comment/string-only web-request control. The official thorough linter passes against the bundled synthetic examples.

CI definitions cover native helper builds on Linux/Windows/macOS, Python 3.10/3.13 integration, Go race tests, vet, and dependency verification. Definitions are not evidence that every platform has passed a release evaluation. The small Python wheel contains the launcher, patch, and adapters, not the full engine or compiled Go programs.

## Current limits and further reading

The complete roadmap is not finished. Outstanding work includes real public-sample precision/recall evaluation, live Gemini quality/cost evaluation, release verification across platforms, automatic semantic-overlap detection, repair CLI wiring, model documentation-citation integration, scheduled intake/resume, a hard OS worker sandbox, and external rule publication.

Read [script analysis usage](docs/script-analysis.md), [agent usage](agent/README.md), [integration details](capathy/integrations/capa/README.md), [changes from capa](docs/changes-from-capa.md), and the [implementation record](docs/implementation/2026-10-24-progress.md). Historical design notes document intent; implemented behavior and limits above describe the current delivery.

## License and attribution

Capathy integrates with Mandiant capa under Apache-2.0; see [LICENSE.txt](LICENSE.txt) and [NOTICE](NOTICE). Upstream copyright and dependency license notices are retained. The integration patch modifies existing engine interfaces; Capathy does not claim these script features are present in an unmodified stock release.
