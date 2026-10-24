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

import pytest

from capa.features.extractors.script.protocol import validate_document


def document():
    return {
        "schema": 1,
        "language": "powershell",
        "sha256": hashlib.sha256(b"foo").hexdigest(),
        "byte_length": 3,
        "functions": [
            {
                "start_byte": 0,
                "end_byte": 3,
                "name": "<top-level>",
                "top_level": True,
                "statements": [
                    {
                        "start_byte": 0,
                        "end_byte": 3,
                        "ordinal": 0,
                        "features": [
                            {
                                "kind": "script-call",
                                "value": "foo",
                                "basis": "direct",
                                "source_node": "command",
                                "start_byte": 0,
                                "end_byte": 3,
                            }
                        ],
                    }
                ],
            }
        ],
        "diagnostics": [],
    }


def test_valid_document():
    assert validate_document(document(), b"foo", "powershell")["schema"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(schema=2),
        lambda d: d.update(sha256="0" * 64),
        lambda d: d.update(language="bash"),
        lambda d: d.update(byte_length=True),
        lambda d: d["functions"][0]["statements"].append(d["functions"][0]["statements"][0]),
        lambda d: d["functions"][0]["statements"][0]["features"][0].update(end_byte=4),
        lambda d: d["functions"][0]["statements"][0]["features"][0].update(basis="guessed"),
        lambda d: d["functions"][0]["statements"][0]["features"][0].update(kind="api"),
    ],
)
def test_reject_invalid_evidence(mutation):
    data = document()
    mutation(data)
    with pytest.raises(ValueError):
        validate_document(data, b"foo", "powershell")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d["functions"][0].update(top_level="yes"),
        lambda d: d["functions"][0]["statements"][0].update(end_byte=0),
        lambda d: d["diagnostics"].append({"code": "error", "message": "uncertain", "start_byte": 0, "end_byte": 4}),
    ],
)
def test_reject_invalid_structure_and_diagnostics(mutation):
    data = document()
    mutation(data)
    with pytest.raises(ValueError):
        validate_document(data, b"foo", "powershell")
