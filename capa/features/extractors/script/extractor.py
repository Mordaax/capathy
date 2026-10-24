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


"""Adapt bounded native script evidence to capa without executing source."""

import os
import json
import shutil
import tempfile
import threading
import subprocess
from pathlib import Path

from capa.features.insn import Number
from capa.features.common import Format, String, Feature
from capa.features.script import ScriptCall, ScriptVariable, ScriptStructure
from capa.features.address import NO_ADDRESS, FileOffsetAddress
from capa.features.extractors.base_extractor import (
    SampleHashes,
    FunctionHandle,
    StatementHandle,
    ScriptStaticFeatureExtractor,
)
from capa.features.extractors.script.protocol import LANGUAGES, MAX_INPUT, MAX_OUTPUT, validate_document


def _run(command: list[str], raw: bytes, limit: int, timeout: float) -> bytes:
    """Bound both output pipes while retaining a fixed argument vector."""
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    with tempfile.TemporaryFile() as source:
        source.write(raw)
        source.seek(0)
        try:
            process = subprocess.Popen(command, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            raise ValueError(f"cannot start script helper: {e}") from e

        def consume(pipe, destination, cap):
            try:
                while chunk := pipe.read(65536):
                    if len(destination) + len(chunk) > cap:
                        overflow.set()
                        process.kill()
                        break
                    destination.extend(chunk)
            finally:
                pipe.close()

        threads = [
            threading.Thread(target=consume, args=(process.stdout, buffers[0], limit), daemon=True),
            threading.Thread(target=consume, args=(process.stderr, buffers[1], 65536), daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as e:
            process.kill()
            process.wait()
            raise ValueError("script helper timed out") from e
        finally:
            for thread in threads:
                thread.join(timeout=1)
        if overflow.is_set():
            raise ValueError("script helper output limit exceeded")
        if any(thread.is_alive() for thread in threads):
            raise ValueError("script helper did not close its output pipes")
        if process.returncode:
            # Source text and helper stderr may be private; do not echo it.
            raise ValueError(f"script helper failed with exit status {process.returncode}")
    return bytes(buffers[0])


def _decode(raw: bytes):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key in script evidence")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=unique_pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as e:
        raise ValueError("invalid script helper JSON") from e


class TreeSitterScriptExtractor(ScriptStaticFeatureExtractor):
    """Read schema 1 evidence and expose source-local capa features."""

    def __init__(self, raw: bytes, language: str, document: dict):
        self.document = validate_document(document, raw, language)
        self.language = language
        super().__init__(SampleHashes.from_bytes(raw))

    @classmethod
    def from_path(cls, path: Path, language: str, helper: str | None = None, timeout: float = 30):
        if language not in LANGUAGES:
            raise ValueError("unsupported script language")
        with path.open("rb") as stream:
            raw = stream.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("script exceeds 16 MiB input limit")
        if raw.startswith((b"MZ", b"\x7fELF")):
            raise ValueError("binary input cannot be analyzed as script source")
        executable = helper or os.environ.get("CAPA_SCRIPT_EXTRACTOR") or shutil.which("capa-script-extractor")
        if not executable:
            raise ValueError("script helper missing: build native/script and set CAPA_SCRIPT_EXTRACTOR")
        version = _decode(_run([executable, "--version"], b"", 65536, min(timeout, 5)))
        if (
            not isinstance(version, dict)
            or type(version.get("schema")) is not int
            or version.get("schema") != 1
            or not isinstance(version.get("version"), str)
            or not isinstance(version.get("languages"), list)
            or language not in version["languages"]
        ):
            raise ValueError("incompatible script helper protocol")
        data = _decode(_run([executable, "analyze", "--language", language], raw, MAX_OUTPUT, timeout))
        extractor = cls(raw, language, data)
        reported_version = extractor.document.get("extractor_version")
        if reported_version is not None and reported_version != version["version"]:
            raise ValueError("script helper version does not match evidence provenance")
        extractor.document["extractor_version"] = version["version"]
        return extractor

    def get_base_address(self):
        return NO_ADDRESS

    def extract_global_features(self):
        yield Format(self.language), NO_ADDRESS

    def extract_file_features(self):
        return iter(())

    def get_functions(self):
        for function in self.document["functions"]:
            yield FunctionHandle(FileOffsetAddress(function["start_byte"]), function)

    def extract_function_features(self, fh):
        return iter(())

    def get_statements(self, fh):
        for statement in fh.inner["statements"]:
            yield StatementHandle(FileOffsetAddress(statement["start_byte"]), statement, statement["ordinal"])

    def extract_statement_features(self, fh, sh):
        for feature in sh.inner["features"]:
            kind, value = feature["kind"], feature["value"]
            converted: Feature
            if kind == "script-call":
                converted = ScriptCall(value)
            elif kind == "script-variable":
                converted = ScriptVariable(value, access=feature["access"])
            elif kind == "script-structure":
                converted = ScriptStructure(value)
            elif kind == "string":
                converted = String(value)
            elif kind == "number":
                converted = Number(value)
            else:
                raise ValueError("unsupported script feature")
            yield converted, FileOffsetAddress(feature["start_byte"])
