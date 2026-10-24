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


import hashlib

from capa.rules import Rule, RuleSet
from capa.capabilities.static import find_static_capabilities
from capa.features.extractors.script.extractor import TreeSitterScriptExtractor


def rule(name, scope, features):
    return Rule.from_yaml(
        f"rule:\n  meta:\n    name: {name}\n    scopes:\n      static: {scope}\n      dynamic: unsupported\n  features:\n{features}\n"
    )


def extractor():
    raw = b"foo; bar"
    statements = []
    for offset, name in [(0, "foo"), (5, "bar")]:
        statements.append({
            "start_byte": offset,
            "end_byte": offset + 3,
            "ordinal": 0,
            "features": [
                {
                    "kind": "script-call",
                    "value": name,
                    "basis": "direct",
                    "source_node": "command",
                    "start_byte": offset,
                    "end_byte": offset + 3,
                }
            ],
        })
    return TreeSitterScriptExtractor(
        raw,
        "powershell",
        {
            "schema": 1,
            "language": "powershell",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "byte_length": len(raw),
            "functions": [
                {
                    "name": "<top-level>",
                    "start_byte": 0,
                    "end_byte": len(raw),
                    "top_level": True,
                    "statements": statements,
                }
            ],
            "diagnostics": [],
        },
    )


def test_statement_locality_and_rollup():
    rules = RuleSet([
        rule("same statement", "statement", "    - and:\n      - script-call: foo\n      - script-call: bar"),
        rule("one call", "statement", "    - script-call: foo"),
        rule("same function", "function", "    - and:\n      - script-call: foo\n      - script-call: bar"),
        rule("file rollup", "file", "    - match: one call"),
        rule("nested statement", "function", "    - statement:\n      - script-call: foo"),
    ])
    matches = find_static_capabilities(rules, extractor(), disable_progress=True).matches
    assert "same statement" not in matches
    assert set(matches) >= {"one call", "same function", "file rollup", "nested statement"}
    assert int(matches["one call"][0][0]) == 0


def test_freeze_preserves_statements_and_matches():
    from capa.features import freeze
    from capa.features.extractors.base_extractor import ScriptStaticFeatureExtractor

    source = extractor()
    restored = freeze.load(freeze.dump(source))
    assert isinstance(restored, ScriptStaticFeatureExtractor)
    assert restored.document == source.document
    rules = RuleSet([rule("one call", "statement", "    - script-call: foo")])
    actual = find_static_capabilities(rules, restored, disable_progress=True)
    expected = find_static_capabilities(rules, source, disable_progress=True)
    assert set(actual.matches) == set(expected.matches)
    assert actual.matches["one call"][0][0] == expected.matches["one call"][0][0]


def test_coincident_statement_offsets_do_not_merge_evidence():
    source = extractor()
    first, second = source.document["functions"][0]["statements"]
    second.update(start_byte=0, end_byte=3, ordinal=1)
    second["features"][0].update(start_byte=0, end_byte=3)
    source = TreeSitterScriptExtractor(b"foo; bar", "powershell", source.document)
    rules = RuleSet([
        rule("same statement", "statement", "    - and:\n      - script-call: foo\n      - script-call: bar"),
        rule("same function", "function", "    - and:\n      - script-call: foo\n      - script-call: bar"),
    ])
    matches = find_static_capabilities(rules, source, disable_progress=True).matches
    assert "same statement" not in matches
    assert "same function" in matches
