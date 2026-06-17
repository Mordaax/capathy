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

from capa.rules import Rule, Scope, RuleSet, InvalidRule, is_subscope_compatible
from capa.features.script import ScriptCall, ScriptVariable, ScriptStructure


def rule(scope, features):
    return Rule.from_yaml(f"""rule:
  meta:
    name: test script
    scopes:
      static: {scope}
      dynamic: unsupported
  features:
{features}
""")


def test_statement_scope_is_sibling_of_binary_scopes():
    parsed = rule("statement", "    - and:\n      - format: powershell\n      - script-call: invoke-webrequest")
    assert parsed.scopes.static == Scope.STATEMENT
    assert len(RuleSet([parsed]).statement_rules) == 1
    function = rule(
        "function", "    - statement:\n      - script-call: invoke-webrequest\n      - script-variable/read: u"
    )
    assert len(RuleSet([function]).statement_rules) == 1
    for scope in (Scope.BASIC_BLOCK, Scope.INSTRUCTION):
        assert not is_subscope_compatible(Scope.STATEMENT, scope)
        assert not is_subscope_compatible(scope, Scope.STATEMENT)
    for key in ("instruction", "basic block"):
        with pytest.raises(InvalidRule):
            rule("statement", f"    - {key}:\n      - number: 1")
    with pytest.raises(InvalidRule):
        rule("instruction", "    - script-call: invoke-webrequest")


def test_script_feature_value_and_access_semantics():
    assert ScriptVariable("x", "read") != ScriptVariable("x", "write")
    assert len({ScriptVariable("x", "read"), ScriptVariable("x", "write")}) == 2
    assert ScriptVariable("x", "read").get_name_str() == "script-variable/read"
    assert ScriptCall("curl") == ScriptCall("curl", description="example")
    with pytest.raises(ValueError):
        ScriptVariable("x", "invoke")
    with pytest.raises(ValueError):
        ScriptStructure("guessed")


def test_script_count_feature():
    parsed = rule("statement", "    - count(script-call(curl)): 2 or more")
    assert parsed.scopes.static == Scope.STATEMENT
