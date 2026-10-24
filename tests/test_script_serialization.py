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

import pytest
from pydantic import TypeAdapter

from capa.features.script import ScriptCall, ScriptVariable, ScriptStructure
from capa.features.freeze.features import Feature, feature_from_capa


@pytest.mark.parametrize(
    "feature",
    [
        ScriptCall("curl", "call"),
        ScriptVariable("u", "read", "input"),
        ScriptVariable("u", "write"),
        ScriptStructure("pipeline"),
    ],
)
def test_script_feature_json_roundtrip(feature):
    frozen = feature_from_capa(feature)
    restored = TypeAdapter(Feature).validate_json(frozen.model_dump_json(by_alias=True)).to_capa()
    assert restored == feature
    assert restored.description == feature.description


def test_statement_scope_proto_roundtrip():
    from capa.rules import Scope
    from capa.render.proto import scope_to_pb2, scope_from_pb2

    assert scope_from_pb2(scope_to_pb2(Scope.STATEMENT)) == Scope.STATEMENT


@pytest.mark.parametrize(
    "feature",
    [
        ScriptCall("curl", "call"),
        ScriptVariable("u", "read", "input"),
        ScriptVariable("u", "write"),
        ScriptStructure("pipeline"),
    ],
)
def test_script_feature_proto_roundtrip(feature):
    from capa.render.proto import feature_to_pb2, feature_from_pb2

    frozen = feature_from_capa(feature)
    restored = feature_from_pb2(feature_to_pb2(frozen)).to_capa()
    assert restored == feature
    assert restored.description == feature.description


@pytest.mark.parametrize("script", [None, {"schema": 1, "language": "powershell", "diagnostics": [], "functions": []}])
def test_static_analysis_proto_metadata_roundtrip(script):
    from capa.render.proto import static_analysis_to_pb2, static_analysis_from_pb2
    from capa.features.freeze import Address
    from capa.features.address import NO_ADDRESS, FileOffsetAddress
    from capa.render.result_document import StaticLayout, FunctionLayout, StaticAnalysis, StaticFeatureCounts

    analysis = StaticAnalysis(
        format="powershell" if script else "pe",
        arch="unknown",
        os="unknown",
        extractor="test",
        rules=(),
        base_address=Address.from_capa(NO_ADDRESS),
        layout=StaticLayout(
            functions=(
                FunctionLayout(
                    address=Address.from_capa(FileOffsetAddress(0)),
                    matched_basic_blocks=(),
                    matched_statements=(Address.from_capa(FileOffsetAddress(12)),) if script else None,
                ),
            )
        ),
        feature_counts=StaticFeatureCounts(file=0, functions=()),
        library_functions=(),
        script=script,
    )
    restored = static_analysis_from_pb2(static_analysis_to_pb2(analysis))
    assert restored == analysis


def test_script_layout_unmatched_function_proto_roundtrip():
    from capa import loader
    from capa.rules import Rule, RuleSet
    from capa.render.proto import static_analysis_to_pb2, static_analysis_from_pb2
    from capa.features.freeze import Address
    from capa.features.address import NO_ADDRESS, FileOffsetAddress
    from capa.render.result_document import StaticAnalysis, StaticFeatureCounts
    from capa.features.extractors.null import ScriptFunctionFeatures, NullScriptFeatureExtractor
    from capa.features.extractors.base_extractor import SampleHashes

    extractor = NullScriptFeatureExtractor(
        base_address=NO_ADDRESS,
        sample_hashes=SampleHashes.from_bytes(b"function harmless {}"),
        global_features=[],
        file_features=[],
        functions={
            FileOffsetAddress(0): ScriptFunctionFeatures(features=[], basic_blocks={}, statements={}),
        },
        document={},
    )
    rules = RuleSet([
        Rule.from_yaml("""rule:
  meta:
    name: never matches
    scopes:
      static: statement
      dynamic: unsupported
  features:
    - and:
      - format: powershell
      - script-call: invoke-webrequest
""")
    ])
    analysis = StaticAnalysis(
        format="powershell",
        arch="unknown",
        os="unknown",
        extractor="test",
        rules=(),
        base_address=Address.from_capa(NO_ADDRESS),
        layout=loader.compute_static_layout(rules, extractor, {}),
        feature_counts=StaticFeatureCounts(file=0, functions=()),
        library_functions=(),
        script={},
    )
    assert static_analysis_from_pb2(static_analysis_to_pb2(analysis)) == analysis


def test_same_offset_statements_render_their_own_dependency_evidence():
    from capa.rules import Rule, RuleSet
    from capa.features.address import NO_ADDRESS, FileOffsetAddress
    from capa.capabilities.static import find_static_capabilities
    from capa.render.result_document import Match
    from capa.features.extractors.null import StatementFeatures, ScriptFunctionFeatures, NullScriptFeatureExtractor
    from capa.features.extractors.base_extractor import SampleHashes

    def make_rule(name, features):
        return Rule.from_yaml(f"""rule:
  meta:
    name: {name}
    scopes:
      static: statement
      dynamic: unsupported
  features:
{features}
""")

    rules = RuleSet([
        make_rule("dependency", "    - or:\n      - script-call: x\n      - script-call: y"),
        make_rule("parent", "    - and:\n      - script-call: foo\n      - match: dependency"),
    ])
    zero = FileOffsetAddress(0)
    extractor = NullScriptFeatureExtractor(
        base_address=NO_ADDRESS,
        sample_hashes=SampleHashes.from_bytes(b"foo x y"),
        global_features=[],
        file_features=[],
        functions={
            zero: ScriptFunctionFeatures(
                features=[],
                basic_blocks={},
                statements={
                    (zero, 0): StatementFeatures(
                        features=[(zero, ScriptCall("foo")), (FileOffsetAddress(4), ScriptCall("x"))]
                    ),
                    (zero, 1): StatementFeatures(features=[(FileOffsetAddress(6), ScriptCall("y"))]),
                },
            )
        },
        document={},
    )
    capabilities = find_static_capabilities(rules, extractor, disable_progress=True)
    assert len(capabilities.matches["parent"]) == 1
    result = Match.from_capa(rules, capabilities.matches, capabilities.matches["parent"][0][1])
    dependency = next(
        child
        for child in result.children
        if getattr(getattr(child.node, "feature", None), "match", None) == "dependency"
    )
    branches = dependency.children[0].children
    assert [(branch.node.feature.script_call, branch.success) for branch in branches] == [("x", True), ("y", False)]
    assert branches[0].locations[0].value == 4
