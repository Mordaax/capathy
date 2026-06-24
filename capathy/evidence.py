"""Export complete static observations independently of existing rule matches."""

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from capathy.process import run_bounded, tool_environment
from capathy.runtime import verify_runtime

MAX_INPUT = 16 << 20
MAX_FEATURES = 100_000


def read_sample(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT:
        raise ValueError("sample must be a regular non-symlink file of at most 16 MiB")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("sample changed while opening")
        data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError("sample exceeds 16 MiB")
    return data


def collect_features(extractor, input_format, byte_length):
    """Traverse every scope, retaining address kinds and the original feature model."""
    import capa.version
    from capa.features.extractors.base_extractor import ScriptStaticFeatureExtractor
    from capa.features.freeze import Address
    from capa.features.freeze.features import feature_from_capa

    features, functions = [], []
    seen = set()

    def location(address):
        return Address.from_capa(address).model_dump(mode="json")

    def add(items, scope, function=None, basic_block=None, statement=None):
        for feature, address in items:
            if len(features) >= MAX_FEATURES:
                raise ValueError("feature count exceeds 100000")
            frozen = feature_from_capa(feature).model_dump(mode="json", by_alias=True, exclude_none=True)
            value = feature.value
            if not isinstance(value, (str, int, float)) or isinstance(value, bool):
                value = json.dumps(frozen, sort_keys=True, separators=(",", ":"))
            record = {
                "kind": feature.get_name_str(),
                "value": value,
                "scope": scope,
                "address": location(address),
                "feature": frozen,
            }
            if function is not None:
                record["function"] = location(function)
            if basic_block is not None:
                record["basic_block"] = location(basic_block)
            if statement is not None:
                record["statement"] = statement
            identity = json.dumps(record, sort_keys=True)
            if identity not in seen:
                seen.add(identity)
                features.append(record)

    add(extractor.extract_global_features(), "global")
    add(extractor.extract_file_features(), "file")
    for function in extractor.get_functions():
        functions.append({"address": location(function.address)})
        add(extractor.extract_function_features(function), "function", function.address)
        if isinstance(extractor, ScriptStaticFeatureExtractor):
            for statement in extractor.get_statements(function):
                add(
                    extractor.extract_statement_features(function, statement),
                    "statement",
                    function.address,
                    statement={"address": location(statement.address), "ordinal": statement.ordinal},
                )
            continue
        for block in extractor.get_basic_blocks(function):
            add(extractor.extract_basic_block_features(function, block), "basic block", function.address, block.address)
            for instruction in extractor.get_instructions(function, block):
                add(
                    extractor.extract_insn_features(function, block, instruction),
                    "instruction",
                    function.address,
                    block.address,
                )
    hashes = extractor.get_sample_hashes()
    result = {
        "schema": 1,
        "kind": "capathy.features",
        "sample": {"sha256": hashes.sha256, "byte_length": byte_length},
        "analysis": {
            "format": input_format,
            "capa_version": capa.version.__version__,
            "extractor": type(extractor).__name__,
            "complete": True,
        },
        "functions": functions,
        "features": features,
        "diagnostics": getattr(extractor, "document", {}).get("diagnostics", [])
        if getattr(extractor, "document", None)
        else [],
    }

    if isinstance(extractor, ScriptStaticFeatureExtractor):
        result["script"] = extractor.document
    return result


def export_features(path, *, input_format="auto", backend="auto", timeout=120):
    """Run the pinned extractor in a bounded worker with no model credentials."""
    raw = read_sample(path)
    root = verify_runtime()
    runtime_revision = run_bounded(["git", "-C", str(root), "rev-parse", "HEAD"], timeout=10).decode().strip()
    project = Path(__file__).resolve().parents[1]
    extra = {"PYTHONPATH": os.pathsep.join((str(root), str(project))), "CAPA_SAVE_WORKSPACE": "0"}
    helper = project / "native/script/bin/capa-script-extractor"
    if helper.is_file():
        extra["CAPA_SCRIPT_EXTRACTOR"] = os.environ.get("CAPA_SCRIPT_EXTRACTOR", str(helper))
    encoded = run_bounded(
        [
            sys.executable,
            "-m",
            "capathy.worker",
            "export-features",
            str(Path(path).resolve()),
            "--format",
            input_format,
            "--backend",
            backend,
        ],
        timeout=timeout,
        env=tool_environment(extra),
    )
    document = json.loads(encoded)
    if document.get("sample", {}).get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("sample changed during feature extraction")
    document["analysis"]["runtime_revision"] = runtime_revision
    return document
