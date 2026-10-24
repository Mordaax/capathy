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

from capa.rules import Rule, RuleSet
from scripts.lint import Context, InvalidStaticScope, MissingExampleOffset, ScriptFeaturesMissingFormat


def check(features, scope="statement"):
    rule = Rule.from_yaml(f"""rule:
  meta:
    name: test script
    scopes:
      static: {scope}
      dynamic: unsupported
  features:
{features}
""")
    rules = RuleSet([rule])
    ctx = Context(samples={}, rules=rules, is_thorough=False)
    return ctx, rule


def test_lint_accepts_statement_scope_and_requires_offset():
    ctx, rule = check("    - script-call: curl")
    assert not InvalidStaticScope().check_rule(ctx, rule)
    rule.meta["examples"] = ["abcd"]
    assert MissingExampleOffset().check_rule(ctx, rule)
    rule.meta["examples"] = ["abcd:0x0"]
    assert not MissingExampleOffset().check_rule(ctx, rule)


@pytest.mark.parametrize(
    ("features", "violation"),
    [
        ("    - script-call: curl", True),
        ("    - and:\n      - format: bash\n      - script-call: curl", False),
        ("    - and:\n      - format: pe\n      - script-call: curl", True),
        ("    - or:\n      - format: bash\n      - script-call: curl", True),
        (
            "    - or:\n      - and:\n        - format: bash\n        - script-call: curl\n      - string: binary branch",
            False,
        ),
        (
            "    - and:\n      - string: anchor\n      - not:\n        - and:\n          - format: bash\n          - script-call: curl",
            True,
        ),
        ("    - and:\n      - format: bash\n      - not:\n        - script-call: curl", False),
    ],
)
def test_lint_requires_format_in_each_script_branch(features, violation):
    ctx, rule = check(features, scope="function")
    assert ScriptFeaturesMissingFormat().check_rule(ctx, rule) == violation


def test_lint_preserves_outer_format_for_extracted_statement_subscope():
    ctx, rule = check(
        "    - and:\n      - format: bash\n      - statement:\n        - script-call: curl", scope="function"
    )
    assert not ScriptFeaturesMissingFormat().check_rule(ctx, rule)


def test_lint_rejects_unprotected_extracted_statement_subscope():
    ctx, rule = check("    - statement:\n      - script-call: curl", scope="function")
    assert ScriptFeaturesMissingFormat().check_rule(ctx, rule)


@pytest.mark.parametrize(
    "scope,features",
    [
        ("statement", "    - string: curl"),
        ("function", "    - statement:\n      - string: curl"),
    ],
)
def test_lint_requires_format_for_string_only_script_statement(scope, features):
    ctx, rule = check(features, scope)
    assert ScriptFeaturesMissingFormat().check_rule(ctx, rule)
