#!/bin/sh
# Build the native script helper and local rule agent without executing samples.
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
capa_go=${CAPA_GO:-}
if [ -z "$capa_go" ]; then
    capa_go=$(command -v go || true)
fi
# Go's automatically downloaded toolchains can exist outside PATH.
if [ -z "$capa_go" ]; then
    for candidate in "$HOME"/go/pkg/mod/golang.org/toolchain@*/bin/go; do
        if [ -x "$candidate" ]; then
            capa_go=$candidate
        fi
    done
fi
if [ -z "$capa_go" ]; then
    echo 'Go is required. Install Go 1.26.6+ or set CAPA_GO to its executable.' >&2
    exit 1
fi
"$capa_go" version
(cd "$project_root/native/script" && "$capa_go" build -o bin/capa-script-extractor ./cmd/capa-script-extractor)
(cd "$project_root/agent" && "$capa_go" build -o bin/capa-rule-agent ./cmd/capa-rule-agent)
printf '\nBuilt both tools. To enable script analysis:\nexport CAPA_SCRIPT_EXTRACTOR="%s/native/script/bin/capa-script-extractor"\n' "$project_root"
