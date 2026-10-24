# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Exercise the native helper and the capa adapter without running sample source."""

import os
import sys
import hashlib
from pathlib import Path

import pytest

from capa.rules import Rule, RuleSet
from capa.features.script import ScriptCall
from capa.capabilities.static import find_static_capabilities
from capa.features.extractors.script.protocol import MAX_INPUT
from capa.features.extractors.script.extractor import TreeSitterScriptExtractor, _run

ROOT = Path(__file__).resolve().parents[1]
HELPER = Path(os.environ.get("CAPA_SCRIPT_EXTRACTOR", ROOT / "native/script/bin/capa-script-extractor"))


def test_helper_output_bounded():
    with pytest.raises(ValueError, match="output limit"):
        _run([sys.executable, "-c", "import sys; sys.stdout.write('x'*1000000)"], b"", 100, 5)


def test_helper_timeout():
    with pytest.raises(ValueError, match="timed out"):
        _run([sys.executable, "-c", "import time; time.sleep(10)"], b"", 100, 0.05)


def test_helper_error_does_not_expose_source():
    with pytest.raises(ValueError, match="exit status 2") as error:
        _run([sys.executable, "-c", "import sys; sys.stderr.write('PRIVATE SOURCE'); sys.exit(2)"], b"", 100, 5)
    assert "PRIVATE" not in str(error.value)


def test_reject_large_source_before_launch(tmp_path):
    sample = tmp_path / "big.ps1"
    with sample.open("wb") as output:
        output.truncate(MAX_INPUT + 1)
    with pytest.raises(ValueError, match="input limit"):
        TreeSitterScriptExtractor.from_path(sample, "powershell", helper="/does/not/exist")


def test_reject_binary_source_before_launch(tmp_path):
    sample = tmp_path / "fake.ps1"
    sample.write_bytes(b"MZ" + b"x" * 100)
    with pytest.raises(ValueError, match="binary input"):
        TreeSitterScriptExtractor.from_path(sample, "powershell", helper="/does/not/exist")


@pytest.mark.skipif(not HELPER.is_file(), reason="build native script helper first")
@pytest.mark.parametrize(
    "language,extension,call",
    [("powershell", "ps1", "invoke-webrequest"), ("python", "py", "requests.get"), ("bash", "sh", "curl")],
)
def test_native_language_rule_match_and_roundtrip(language, extension, call):
    from capa import loader
    from capa.render import proto
    from capa.render import result_document as rdoc
    from capa.features import freeze

    source = ROOT / f"examples/scripts/request.{extension}"
    extractor = TreeSitterScriptExtractor.from_path(source, language, helper=str(HELPER))
    features = [
        feature
        for fh in extractor.get_functions()
        for sh in extractor.get_statements(fh)
        for feature, _ in extractor.extract_statement_features(fh, sh)
    ]
    assert ScriptCall(call) in features
    assert extractor.get_sample_hashes().sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    rules = RuleSet([
        Rule.from_yaml(
            (
                ROOT / f"examples/script-rules/communication/http/client/issue-web-request-from-{language}-source.yml"
            ).read_text()
        )
    ])
    capabilities = find_static_capabilities(rules, extractor, disable_progress=True)
    assert len(capabilities.matches) == 1
    restored = freeze.load(freeze.dump(extractor))
    assert (
        find_static_capabilities(rules, restored, disable_progress=True).matches.keys() == capabilities.matches.keys()
    )
    meta = loader.collect_metadata([], source, language, [ROOT / "examples/script-rules"], extractor, capabilities)
    meta.analysis.layout = loader.compute_layout(rules, extractor, capabilities.matches)
    document = rdoc.ResultDocument.from_capa(meta, rules, capabilities.matches)
    assert rdoc.ResultDocument.model_validate_json(document.model_dump_json()).meta.analysis.script["schema"] == 1
    assert proto.doc_from_pb2(proto.doc_to_pb2(document)).model_dump() == document.model_dump()


@pytest.mark.skipif(not HELPER.is_file(), reason="build native script helper first")
def test_python_source_is_never_executed(tmp_path):
    marker = tmp_path / "executed"
    sample = tmp_path / "untrusted.py"
    sample.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    TreeSitterScriptExtractor.from_path(sample, "python", helper=str(HELPER))
    assert not marker.exists()


def test_binary_magic_wins_over_script_extension(tmp_path):
    from capa.helpers import get_auto_format

    sample = tmp_path / "fake.ps1"
    sample.write_bytes(b"\x7fELF" + bytes(256))
    assert get_auto_format(sample) == "elf"


def test_script_extension_auto_detection(tmp_path):
    from capa.helpers import get_auto_format

    sample = tmp_path / "plain.PS1"
    sample.write_text("Write-Host 'hello'")
    assert get_auto_format(sample) == "powershell"


def test_auto_detection_does_not_read_entire_source(tmp_path, monkeypatch):
    from capa.helpers import get_auto_format

    sample = tmp_path / "large.ps1"
    sample.write_text("Write-Host 'hello'")

    def forbidden_read_bytes(self):
        raise AssertionError("format detection must read only a bounded header")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    assert get_auto_format(sample) == "powershell"


def test_helper_version_provenance_is_preserved(tmp_path, monkeypatch):
    import json

    from test_script_protocol import document

    import capa.features.extractors.script.extractor as module

    sample = tmp_path / "sample.ps1"
    sample.write_bytes(b"foo")
    evidence = document()
    evidence["extractor_version"] = "0.2.0"

    def fake_run(command, raw, limit, timeout):
        return json.dumps(
            {"version": "0.2.0", "schema": 1, "languages": ["powershell"]} if command[-1] == "--version" else evidence
        ).encode()

    monkeypatch.setattr(module, "_run", fake_run)
    extracted = module.TreeSitterScriptExtractor.from_path(sample, "powershell", helper="configured-helper")
    assert extracted.document["extractor_version"] == "0.2.0"
    from test_script_capabilities import rule

    from capa import loader

    rules = RuleSet([rule("one call", "statement", "    - script-call: foo")])
    matches = find_static_capabilities(rules, extracted, disable_progress=True)
    meta = loader.collect_metadata([], sample, "powershell", [], extracted, matches)
    assert meta.analysis.script["extractor_version"] == "0.2.0"
