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


"""Strict validation of schema 1 native script evidence."""

import hashlib
from typing import Any, TypeGuard

MAX_INPUT = 16 * 1024 * 1024
MAX_OUTPUT = 32 * 1024 * 1024
LANGUAGES = ("powershell", "python", "bash", "javascript", "typescript", "c", "cpp")
STRUCTURES = {
    "assignment",
    "pipeline",
    "branch",
    "loop",
    "try",
    "redirection",
    "command-substitution",
    "function-definition",
}


def _integer(value: Any) -> TypeGuard[int]:
    return type(value) is int and value >= 0


def _span(item: dict, lower: int, upper: int) -> tuple[int, int]:
    start, end = item.get("start_byte"), item.get("end_byte")
    if not _integer(start) or not _integer(end) or not lower <= start < end <= upper:
        raise ValueError("invalid source interval")
    return start, end


def validate_document(data: Any, raw: bytes, language: str) -> dict:
    """Validate the complete document before converting any evidence to features."""
    if len(raw) > MAX_INPUT:
        raise ValueError("script exceeds 16 MiB input limit")
    if not isinstance(data, dict) or type(data.get("schema")) is not int or data["schema"] != 1:
        raise ValueError("unsupported script evidence schema")
    if language not in LANGUAGES or data.get("language") != language:
        raise ValueError("script evidence language mismatch")
    if not _integer(data.get("byte_length")) or data["byte_length"] != len(raw):
        raise ValueError("script evidence byte length mismatch")
    if data.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("script evidence SHA-256 mismatch")
    functions, diagnostics = data.get("functions"), data.get("diagnostics")
    if not isinstance(functions, list) or len(functions) > 100_000:
        raise ValueError("invalid functions")
    if not isinstance(diagnostics, list) or len(diagnostics) > 100_000:
        raise ValueError("invalid diagnostics")
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, dict):
            raise ValueError("invalid diagnostic")
        start, end = diagnostic.get("start_byte"), diagnostic.get("end_byte")
        if not _integer(start) or not _integer(end) or not 0 <= start <= end <= len(raw):
            raise ValueError("invalid diagnostic interval")
        if not isinstance(diagnostic.get("code"), str) or not isinstance(diagnostic.get("message"), str):
            raise ValueError("missing diagnostic metadata")
    top_level_count = 0
    function_addresses = set()
    statement_ids = set()
    count = 0
    for function in functions:
        if not isinstance(function, dict):
            raise ValueError("invalid function")
        start, end = _span(function, 0, len(raw))
        if start in function_addresses:
            raise ValueError("duplicate function address")
        function_addresses.add(start)
        if not isinstance(function.get("name"), str) or type(function.get("top_level")) is not bool:
            raise ValueError("missing function metadata")
        if function["top_level"]:
            top_level_count += 1
            if top_level_count > 1:
                raise ValueError("multiple top-level regions")
        statements = function.get("statements")
        if not isinstance(statements, list):
            raise ValueError("invalid statements")
        if function["top_level"] and (
            not statements or not isinstance(statements[0], dict) or statements[0].get("start_byte") != start
        ):
            raise ValueError("invalid top-level region")
        for statement in statements:
            if not isinstance(statement, dict):
                raise ValueError("invalid statement")
            ss, se = _span(statement, start, end)
            ordinal = statement.get("ordinal")
            if not _integer(ordinal) or (ss, ordinal) in statement_ids:
                raise ValueError("invalid or duplicate statement identity")
            statement_ids.add((ss, ordinal))
            features = statement.get("features")
            if not isinstance(features, list):
                raise ValueError("invalid features")
            count += len(features) + 1
            if count > 500_000:
                raise ValueError("script evidence count limit exceeded")
            for feature in features:
                if not isinstance(feature, dict):
                    raise ValueError("invalid feature")
                _span(feature, ss, se)
                if feature.get("basis") not in ("direct", "static-alias"):
                    raise ValueError("unsupported feature basis")
                if not isinstance(feature.get("source_node"), str) or not feature["source_node"]:
                    raise ValueError("missing feature provenance")
                kind, value = feature.get("kind"), feature.get("value")
                if kind not in ("script-call", "script-variable", "script-structure", "string", "number"):
                    raise ValueError("unsupported script feature")
                if kind == "number":
                    if type(value) is not int:
                        raise ValueError("invalid numeric feature")
                elif not isinstance(value, str) or len(value) > MAX_INPUT:
                    raise ValueError("invalid feature value")
                if kind == "script-variable" and feature.get("access") not in ("read", "write"):
                    raise ValueError("invalid variable access")
                if kind == "script-structure" and value not in STRUCTURES:
                    raise ValueError("invalid structure")
    return data
