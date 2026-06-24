"""Pinned public corpus acquisition and capability evaluation without sample execution."""

import hashlib
import json
import os
import re
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from capathy.evidence import read_sample
from capathy.process import run_bounded, tool_environment
from capathy.runtime import manifest, verify_runtime

REPOSITORY = "https://github.com/mandiant/capa-testfiles"


def load_manifest(path):
    document = json.loads(Path(path).read_text())
    samples = document.get("samples", [])
    if document.get("schema") != 1 or document.get("repository") != REPOSITORY or not 1 <= len(samples) <= 100:
        raise ValueError("invalid corpus manifest")
    ids = set()
    for sample in samples:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", sample.get("id", "")) or sample["id"] in ids:
            raise ValueError("invalid corpus sample identity")
        ids.add(sample["id"])
        if not re.fullmatch(r"[0-9a-f]{64}", sample.get("sha256", "")) or not re.fullmatch(
            r"[0-9a-f]{40}", sample.get("revision", "")
        ):
            raise ValueError("corpus samples require pinned SHA-256 and revision")
        name = sample.get("path", "")
        if not name or name.startswith("/") or ".." in Path(name).parts or "\\" in name or len(name) > 256:
            raise ValueError("unsafe corpus path")
        if sample.get("format") not in ("pe", "elf", "dotnet"):
            raise ValueError("unsupported corpus format")
        expected = sample.get("expect")
        if (
            not isinstance(expected, dict)
            or not expected
            or len(expected) > 100
            or any(not isinstance(key, str) or type(value) is not bool for key, value in expected.items())
        ):
            raise ValueError("capability expectations must be explicit booleans")
        if sample.get("label") not in ("malware-lab", "malware", "benign", "unclassified") or not sample.get(
            "provenance"
        ):
            raise ValueError("corpus label provenance required")
    return document


def fetch_sample(sample, cache):
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / sample["sha256"]
    if target.exists():
        if hashlib.sha256(read_sample(target)).hexdigest() != sample["sha256"]:
            raise ValueError("cached sample checksum mismatch")
        target.chmod(0o600)
        return target
    url = (
        "https://raw.githubusercontent.com/mandiant/capa-testfiles/"
        + sample["revision"]
        + "/"
        + urllib.parse.quote(sample["path"], safe="/")
    )
    with tempfile.NamedTemporaryFile(dir=cache, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            digest, count = hashlib.sha256(), 0
            with urllib.request.urlopen(url, timeout=30) as response:
                while chunk := response.read(65536):
                    count += len(chunk)
                    if count > 16 << 20:
                        raise ValueError("corpus sample exceeds 16 MiB")
                    stream.write(chunk)
                    digest.update(chunk)
            stream.close()
            if digest.hexdigest() != sample["sha256"]:
                raise ValueError("downloaded sample checksum mismatch")
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    target.chmod(0o600)
    return target


def score(expected, matched):
    result = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for capability, positive in expected.items():
        observed = capability in matched
        result["tp" if positive and observed else "fn" if positive else "fp" if observed else "tn"] += 1
    return result


def evaluate(manifest_path, rules, *, cache=None, timeout=120):
    import sys

    document = load_manifest(manifest_path)
    root = verify_runtime()
    runtime_revision = manifest()["runtime_revision"]
    rules = Path(rules).resolve()
    revision = run_bounded(["git", "-C", str(rules), "rev-parse", "HEAD"], timeout=10).decode().strip()
    if revision != document.get("rules_revision"):
        raise ValueError("rules revision does not match corpus manifest")
    if run_bounded(["git", "-C", str(rules), "status", "--porcelain"], timeout=10).strip():
        raise ValueError("evaluation requires a clean rules checkout")
    cache = (
        Path(cache)
        if cache
        else Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "capathy/samples"
    )
    records, totals = [], {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for sample in document["samples"]:
        path = fetch_sample(sample, cache)
        encoded = run_bounded(
            [sys.executable, "-m", "capa.main", "-j", "-f", sample["format"], "-r", str(rules), str(path)],
            timeout=timeout,
            env=tool_environment({"PYTHONPATH": str(root), "CAPA_SAVE_WORKSPACE": "0"}),
        )
        result = json.loads(encoded)
        if result["meta"]["sample"]["sha256"] != sample["sha256"]:
            raise ValueError("evaluated sample identity mismatch")
        counts = score(sample["expect"], result["rules"])
        for key, value in counts.items():
            totals[key] += value
        records.append(
            {
                "id": sample["id"],
                "sha256": sample["sha256"],
                "label": sample["label"],
                "provenance": sample["provenance"],
                "expected": sample["expect"],
                "observed": {name: name in result["rules"] for name in sample["expect"]},
                "counts": counts,
                "matched_rules": sorted(result["rules"]),
            }
        )
    return {
        "schema": 1,
        "kind": "capathy.corpus-evaluation",
        "manifest_sha256": hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest(),
        "rules_revision": revision,
        "runtime_revision": runtime_revision,
        "samples": records,
        "counts": totals,
        "passed": totals["fp"] == totals["fn"] == 0,
        "limitations": "Pilot capability regression only; not malware classification accuracy or proof of generalization.",
    }
