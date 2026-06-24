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
            "       capathy export-features SAMPLE [--format FORMAT] [--out FILE]\n"
            "       capathy analyze-project DIRECTORY [--out FILE]\n"
            "       capathy setup-ghidra\n"
            "       capathy decompile ELF [--out FILE]\n"
            "       capathy evaluate-corpus MANIFEST --rules DIRECTORY [--out FILE]\n"
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
        if command == "export-features":
            from capathy.evidence import export_features
            from capathy.process import write_json

            parser = argparse.ArgumentParser(prog="capathy export-features")
            parser.add_argument("sample", type=Path)
            parser.add_argument("-f", "--format", default="auto")
            parser.add_argument("-b", "--backend", default="auto")
            parser.add_argument("--timeout", type=float, default=120)
            parser.add_argument("--out", type=Path)
            options = parser.parse_args(rest)
            result = export_features(
                options.sample, input_format=options.format, backend=options.backend, timeout=options.timeout
            )
            encoded = write_json(options.out, result)
            if options.out is None:
                sys.stdout.buffer.write(encoded)
            return 0
        if command == "evaluate-corpus":
            from capathy.corpus import evaluate
            from capathy.process import write_json

            parser = argparse.ArgumentParser(prog="capathy evaluate-corpus")
            parser.add_argument("manifest", type=Path)
            parser.add_argument("--rules", type=Path, required=True)
            parser.add_argument("--cache", type=Path)
            parser.add_argument("--timeout", type=float, default=120)
            parser.add_argument("--out", type=Path)
            options = parser.parse_args(rest)
            report = evaluate(options.manifest, options.rules, cache=options.cache, timeout=options.timeout)
            encoded = write_json(options.out, report)
            if options.out is None:
                sys.stdout.buffer.write(encoded)
            return 0 if report["passed"] else 1
        if command == "analyze-project":
            from capathy.process import write_json
            from capathy.project import analyze_project

            parser = argparse.ArgumentParser(prog="capathy analyze-project")
            parser.add_argument("directory", type=Path)
            parser.add_argument("--helper")
            parser.add_argument("--max-files", type=int, default=500)
            parser.add_argument("--max-bytes", type=int, default=32 << 20)
            parser.add_argument("--timeout", type=float, default=120)
            parser.add_argument("--out", type=Path)
            options = parser.parse_args(rest)
            encoded = write_json(
                options.out,
                analyze_project(
                    options.directory,
                    helper=options.helper,
                    max_files=options.max_files,
                    max_bytes=options.max_bytes,
                    timeout=options.timeout,
                ),
            )
            if options.out is None:
                sys.stdout.buffer.write(encoded)
            return 0
        if command == "setup-ghidra":
            from capathy.decompile import setup_ghidra

            print(setup_ghidra())
            return 0
        if command == "decompile":
            from capathy.decompile import decompile
            from capathy.process import write_json

            parser = argparse.ArgumentParser(prog="capathy decompile")
            parser.add_argument("sample", type=Path)
            parser.add_argument("--ghidra-home", type=Path)
            parser.add_argument("--max-functions", type=int, default=100)
            parser.add_argument("--timeout", type=float, default=240)
            parser.add_argument("--out", type=Path)
            options = parser.parse_args(rest)
            encoded = write_json(
                options.out,
                decompile(
                    options.sample,
                    ghidra_home=options.ghidra_home,
                    max_functions=options.max_functions,
                    timeout=options.timeout,
                ),
            )
            if options.out is None:
                sys.stdout.buffer.write(encoded)
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
