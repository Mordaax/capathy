"""Developer CLI for Capathy's standalone tools and external capa integration."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from capathy.runtime import manifest, prepare_runtime, verify_runtime


def project_root():
    return Path(os.environ.get("CAPATHY_ROOT", str(Path(__file__).resolve().parents[1])))


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] in ("--help", "-h"):
        print(
            "Usage: capathy setup [--source GIT_REPO] [--no-install]\n"
            "       capathy runtime-path\n"
            "       capathy analyze [capa arguments]\n"
            "       capathy agent [agent arguments]\n"
            "       capathy version"
        )
        return 0
    command, rest = arguments[0], arguments[1:]
    try:
        if command == "version":
            print(json.dumps({"capathy": "0.1.0", "capa_integration": manifest()}, indent=2))
            return 0
        if command == "setup":
            parser = argparse.ArgumentParser(prog="capathy setup")
            parser.add_argument("--source", help="alternative git source, such as a local existing clone")
            parser.add_argument(
                "--no-install", action="store_true", help="prepare checkout without installing Python dependencies"
            )
            options = parser.parse_args(rest)
            root = prepare_runtime(options.source)
            if not options.no_install:
                subprocess.run([sys.executable, "-m", "pip", "install", "-e", str(root)], check=True)
            print(root)
            return 0
        if command == "runtime-path":
            print(verify_runtime())
            return 0
        environment = dict(os.environ)
        helper = project_root() / "native/script/bin/capa-script-extractor"
        if "CAPA_SCRIPT_EXTRACTOR" not in environment and helper.is_file():
            environment["CAPA_SCRIPT_EXTRACTOR"] = str(helper)
        if command == "analyze":
            root = verify_runtime()
            # Use the pinned engine even if another capa distribution is installed.
            environment["PYTHONPATH"] = str(root)
            return subprocess.run([sys.executable, "-m", "capa.main", *rest], env=environment, check=False).returncode
        if command == "agent":
            executable = project_root() / "agent/bin/capa-rule-agent"
            if not executable.is_file():
                located = shutil.which("capa-rule-agent")
                if not located:
                    raise ValueError("agent is missing; run scripts/build-script-tools.sh")
                executable = Path(located)
            return subprocess.run([str(executable), *rest], env=environment, check=False).returncode
        raise ValueError(f"unknown command: {command}")
    except (ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"capathy: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
