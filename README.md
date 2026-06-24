# Capathy

**Create new capa rules from evidence about what a program does.**

## What is capa?

[capa](https://github.com/mandiant/capa) is an open-source tool that identifies capabilities in executable files and sandbox reports. It can recognize behaviors such as making HTTP requests, creating processes, or accessing the registry, and show the evidence behind each match.

## What are capa rules?

A capa rule is a YAML description of a capability. It defines patterns of features—such as API calls, strings, or instructions—that must appear together. When those conditions match, capa reports the capability named by the rule. Rules can combine conditions with logic such as `and` and `or`.

For example, a rule could recognize process creation from relevant API calls. Capathy adds script features so a rule can also recognize a direct PowerShell `Invoke-WebRequest` call.

## What does Capathy do?

Capathy helps create new rules through three steps:

1. **Collect evidence:** extract binary features, parse source files in seven languages, or inspect a source directory.
2. **Draft a rule:** use a Go agent with Gemini or Claude to propose YAML rules with citations to the observed evidence.
3. **Validate and review:** check candidates with capa's formatter, linter, and positive/negative sample tests, then prepare a local review package.

Examples:

| Input evidence | Rule to create |
| --- | --- |
| PowerShell `Invoke-WebRequest` | Detect a script making a web request |
| Python `requests.get(...)` | Detect HTTP requests through the requests library |
| Bash `curl "$url"` | Detect a shell script invoking curl |
| PE or ELF binary | Create rules from APIs, strings, and instructions, including unmatched features |
| JavaScript/TypeScript or C/C++ | Detect syntactically named calls such as `fetch` or `std::puts` |

Scripts are parsed without executing them. Structural matching distinguishes actual calls from command names appearing only in comments or strings.

## Setup

Requires Git, Python 3.10+, Go 1.26.6+, and a C compiler.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
scripts/build-script-tools.sh
.venv/bin/python -m capathy setup
```

The capa engine is installed separately into an external cache. This repository contains the Go tools, integration patch, adapters, tests, and examples.

## Create a rule

Collect evidence from the bundled PowerShell example:

```sh
mkdir -p out
.venv/bin/python -m capathy analyze \
  -f powershell -r examples/script-rules -j examples/scripts/request.ps1 \
  > out/evidence.json
```

Import the evidence and describe the capability you want to detect:

```sh
.venv/bin/python -m capathy agent draft \
  --capa-json out/evidence.json --capability 'make a web request from PowerShell' \
  --out out/request.json
```

Generate a candidate with Claude using `ANTHROPIC_API_KEY` (or `CLAUDE_API_KEY`) in your `.env` file:

```sh
.venv/bin/python -m capathy agent draft \
  --request out/request.json --provider claude --live --env-file .env --out out/draft.json
```

Use `--provider gemini` for Gemini instead. Both providers use the same evidence and validation checks.

For this evidence, a candidate rule could look like:

```yaml
rule:
  meta:
    name: make a web request from PowerShell
    namespace: communication/http/client
    authors: [analyst]
    scopes:
      static: statement
      dynamic: unsupported
  features:
    - and:
      - format: powershell
      - script-call: invoke-webrequest
```

For binaries or source files, collect complete observations without needing an existing matching rule:

```sh
.venv/bin/python -m capathy export-features sample.elf --out out/features.json
.venv/bin/python -m capathy agent draft --evidence-json out/features.json \
  --capability 'describe the observed capability' --out out/request.json
```

Use `analyze-project ./src --out out/project.json` for a source inventory and candidate call links. Optional `setup-ghidra` and `decompile sample.elf --out out/decompiled.json` produce address-linked ELF pseudocode (requires JDK 25+). See [analysis examples and corpus evaluation](docs/analysis-workflows.md).

## Validate and review

Candidates must pass formatting, thorough linting, evidence checks, and tests against a reviewed corpus: at least one real positive, two benign negatives, and one adversarial negative. Passing candidates can produce a local review package; GitHub rule publication is disabled.

The public three-binary pilot checks one reverse-shell capability; it is not a general accuracy benchmark. Bundled source examples are synthetic. Model-generated rules still need independent validation.

See [agent commands and validation](agent/README.md), [script analysis](docs/script-analysis.md), [implementation status](docs/implementation/2026-10-25-analysis-expansion.md), and [history conventions](HISTORY.md).

Apache-2.0; upstream attribution is retained in [NOTICE](NOTICE) and [LICENSE.txt](LICENSE.txt).
