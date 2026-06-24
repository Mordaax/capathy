"""Full export includes observations that no existing rule has matched."""

import json
from pathlib import Path

from capa.features.address import NO_ADDRESS, AbsoluteVirtualAddress
from capa.features.common import Format, String
from capa.features.extractors.base_extractor import SampleHashes
from capa.features.extractors.null import (
    BasicBlockFeatures,
    FunctionFeatures,
    InstructionFeatures,
    NullStaticFeatureExtractor,
)
from capa.features.insn import API

from capathy.evidence import collect_features


def test_unmatched_features_exported_with_scope_and_provenance():
    address = AbsoluteVirtualAddress(0x401000)
    extractor = NullStaticFeatureExtractor(
        base_address=address,
        sample_hashes=SampleHashes.from_bytes(b"fixture"),
        global_features=[Format("elf")],
        file_features=[(NO_ADDRESS, String("unmatched-file-string"))],
        functions={
            address: FunctionFeatures(
                features=[],
                basic_blocks={
                    address: BasicBlockFeatures(
                        features=[],
                        instructions={address: InstructionFeatures(features=[(address, API("unmatched_function"))])},
                    )
                },
            )
        },
    )
    document = collect_features(extractor, "elf", 7)
    assert document["kind"] == "capathy.features" and document["schema"] == 1
    assert not document.get("rules")
    observed = next(item for item in document["features"] if item["kind"] == "api")
    assert observed["value"] == "unmatched_function"
    assert observed["scope"] == "instruction"
    assert observed["function"] == {"type": "absolute", "value": 0x401000}
    assert observed["address"] == {"type": "absolute", "value": 0x401000}
    assert any(item["value"] == "unmatched-file-string" for item in document["features"])
    assert document["sample"]["sha256"] == extractor.get_sample_hashes().sha256


def test_added_languages_match_real_capa_rules(tmp_path, monkeypatch):
    import os
    import subprocess
    import sys

    from capathy.evidence import export_features
    from capathy.runtime import verify_runtime

    helper = str(Path(__file__).resolve().parents[1] / "native/script/bin/capa-script-extractor")
    for language, suffix, code, call in [
        ("javascript", ".js", 'function f() { fetch("url"); }', "fetch"),
        ("typescript", ".ts", "function f(u: string): void { fetch(u); }", "fetch"),
        ("c", ".c", 'int main(void) { puts("hello"); return 0; }', "puts"),
        ("cpp", ".cpp", 'int main() { std::puts("hello"); return 0; }', "std::puts"),
    ]:
        sample = tmp_path / (language + suffix)
        sample.write_text(code)
        document = export_features(sample)
        from capathy.runtime import manifest

        assert document["analysis"]["runtime_revision"] == manifest()["runtime_revision"]
        assert any(f["kind"] == "script-call" and f["value"] == call for f in document["features"])
        rule = tmp_path / (language + ".yml")
        rule.write_text(f"""rule:
  meta:
    name: source call {language}
    authors: [test]
    scopes:
      static: statement
      dynamic: unsupported
  features:
    - and:
      - format: {language}
      - script-call: {call}
""")
        env = dict(os.environ, PYTHONPATH=str(verify_runtime()), CAPA_SCRIPT_EXTRACTOR=helper)
        result = subprocess.run(
            [sys.executable, "-m", "capa.main", "-j", "-r", str(rule), str(sample)],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert f"source call {language}" in json.loads(result.stdout)["rules"]
