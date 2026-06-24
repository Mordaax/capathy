"""Bounded source-project inventory and explicitly uncertain call relationships."""

import hashlib
import json
import os
import shutil
import time
from pathlib import Path

from capathy.evidence import read_sample
from capathy.process import run_bounded

LANGUAGES = {
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".py": "python",
    ".sh": "bash",
    ".bash": "bash",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
}
MAX_EVIDENCE_BYTES = 16 << 20
EXCLUDED = {".git", ".venv", "venv", "node_modules", "vendor", "__pycache__", "build", "dist", "out"}


def analyze_project(root, *, helper=None, max_files=500, max_bytes=32 << 20, timeout=120):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("project root must be a real directory")
    if not 1 <= max_files <= 5000 or not 1 <= max_bytes <= 128 << 20 or not 0 < timeout <= 3600:
        raise ValueError("invalid project limits")
    root = root.resolve()
    executable = (
        helper
        or os.environ.get("CAPA_SCRIPT_EXTRACTOR")
        or str(Path(__file__).resolve().parents[1] / "native/script/bin/capa-script-extractor")
    )
    if not Path(executable).is_file() and not shutil.which(executable):
        raise ValueError("source helper is missing; run scripts/build-script-tools.sh")
    files, skipped, definitions, links = [], [], {}, []
    total = 0
    evidence_bytes = 0
    deadline = time.monotonic() + timeout
    # Source bytes travel over a private temporary input file through the bounded helper wrapper.
    import tempfile

    for path in _source_paths(root, deadline):
        relative = path.relative_to(root).as_posix()
        language = LANGUAGES.get(path.suffix.lower())
        if not language or path.name.startswith("."):
            continue
        if path.is_symlink():
            skipped.append({"path": relative, "reason": "symlink"})
            continue
        if len(files) >= max_files:
            raise ValueError("project file count limit exceeded")
        raw = read_sample(path)
        total += len(raw)
        if total > max_bytes:
            raise ValueError("project byte limit exceeded")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("project analysis timed out")
        with tempfile.TemporaryDirectory(prefix="capathy-source-") as temporary:
            source = Path(temporary) / "source"
            source.write_bytes(raw)
            source.chmod(0o600)
            # A small Python bridge supplies stdin without a shell or inherited model credentials.
            import sys

            encoded = run_bounded(
                [sys.executable, "-m", "capathy.source_worker", str(executable), language, str(source)],
                timeout=min(20, remaining),
            )
        evidence_bytes += len(encoded)
        if evidence_bytes > MAX_EVIDENCE_BYTES:
            raise ValueError("project aggregate evidence limit exceeded")
        document = json.loads(encoded)
        digest = hashlib.sha256(raw).hexdigest()
        if document.get("schema") != 1 or document.get("sha256") != digest or document.get("language") != language:
            raise ValueError("source helper identity mismatch")
        files.append({"path": relative, "sha256": digest, "language": language, "evidence": document})
        for function in document["functions"]:
            if not function.get("top_level") and function["name"] != "<anonymous>":
                definition = {"path": relative, "sha256": digest, "start_byte": function["start_byte"]}
                definitions.setdefault(function["name"], []).append(definition)
                module = str(Path(relative).with_suffix("")).replace("/", ".")
                definitions.setdefault(module + "." + function["name"], []).append(definition)
            for statement in function["statements"]:
                for feature in statement["features"]:
                    if feature["kind"] == "script-call":
                        links.append(
                            {
                                "path": relative,
                                "sha256": digest,
                                "function_start_byte": function["start_byte"],
                                "start_byte": feature["start_byte"],
                                "end_byte": feature["end_byte"],
                                "call": feature["value"],
                            }
                        )
    for link in links:
        link["candidates"] = definitions.get(link["call"], [])
        link["resolution"] = "name-candidate" if link["candidates"] else "unresolved"
    identity = [{"path": file["path"], "sha256": file["sha256"]} for file in files]
    return {
        "schema": 1,
        "kind": "capathy.project",
        "sha256": hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
        "byte_length": total,
        "files": files,
        "call_links": links,
        "skipped": skipped,
        "limitations": [
            "Call targets are syntactic observations; candidate names do not prove cross-file resolution, data flow, or runtime behavior.",
            "No imports, build scripts, source files, or samples are executed.",
        ],
    }


def _source_paths(root, deadline):
    pending, visited = [root], 0
    while pending:
        if time.monotonic() >= deadline:
            raise ValueError("project analysis timed out")
        directory = pending.pop()
        entries = []
        with os.scandir(directory) as iterator:
            for entry in iterator:
                visited += 1
                if visited > 100000:
                    raise ValueError("project traversal entry limit exceeded")
                if time.monotonic() >= deadline:
                    raise ValueError("project analysis timed out")
                entries.append(entry)
        for entry in sorted(entries, key=lambda item: item.name):
            if time.monotonic() >= deadline:
                raise ValueError("project analysis timed out")
            if entry.name.startswith("."):
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in EXCLUDED:
                    pending.append(Path(entry.path))
            elif entry.is_symlink() or entry.is_file(follow_symlinks=False):
                yield Path(entry.path)
