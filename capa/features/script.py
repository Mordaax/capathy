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

"""Features extracted conservatively from script source."""

from typing import Literal, Optional

from capa.features.common import Feature


class ScriptCall(Feature):
    def __init__(self, value: str, description: Optional[str] = None):
        super().__init__(value, description=description)
        self.name = "script-call"


class ScriptVariable(Feature):
    def __init__(self, value: str, access: Literal["read", "write"], description: Optional[str] = None):
        if access not in ("read", "write"):
            raise ValueError(f"invalid script variable access: {access}")
        super().__init__(value, description=description)
        self.name = "script-variable"
        self.access = access

    def __hash__(self):
        return hash((self.name, self.value, self.access))

    def __eq__(self, other):
        return isinstance(other, ScriptVariable) and self.value == other.value and self.access == other.access

    def get_name_str(self) -> str:
        return f"{self.name}/{self.access}"


class ScriptStructure(Feature):
    def __init__(self, value: str, description: Optional[str] = None):
        if value not in {
            "assignment",
            "pipeline",
            "branch",
            "loop",
            "try",
            "redirection",
            "command-substitution",
            "function-definition",
        }:
            raise ValueError(f"invalid script structure: {value}")
        super().__init__(value, description=description)
        self.name = "script-structure"
