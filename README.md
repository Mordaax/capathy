# Capathy

**Create new [capa](https://github.com/mandiant/capa) capability rules from program evidence.**

Capathy extracts features from PowerShell, Python, and Bash scripts, or imports existing capa results for binaries. A Go agent uses Gemini to draft YAML rules with evidence citations, then checks candidates with capa's formatter, linter, and positive/negative sample tests.

Examples:

| Input evidence | Rule to create |
| --- | --- |
| PowerShell `Invoke-WebRequest` | Detect a script making a web request |
| Python `requests.get(...)` | Detect HTTP requests through the requests library |
| Bash `curl "$url"` | Detect a shell script invoking curl |
| Binary capa JSON | Describe a capability using observed APIs, strings, and existing matches |

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

Generate a candidate with Gemini using an API key in your `.env` file:

```sh
.venv/bin/python -m capathy agent draft \
  --request out/request.json --live --env-file .env --out out/draft.json
```

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

For Python or Bash, use `-f python` or `-f bash` with your source file. For binaries, import existing capa JSON directly with `agent draft --capa-json`.

## Validate and review

Candidates must pass formatting, thorough linting, evidence checks, and tests against a reviewed corpus: at least one real positive, two benign negatives, and one adversarial negative. Passing candidates can produce a local review package; GitHub rule publication is disabled.

The bundled samples are synthetic demonstrations. Real-world detection accuracy and live model quality remain unevaluated.

See [agent commands and validation](agent/README.md), [script analysis](docs/script-analysis.md), [implementation status](docs/implementation/2026-10-24-progress.md), and [history conventions](HISTORY.md).

Apache-2.0; upstream attribution is retained in [NOTICE](NOTICE) and [LICENSE.txt](LICENSE.txt).
