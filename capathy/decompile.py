"""Optional pinned external Ghidra installation and static ELF decompilation."""

import hashlib
import json
import os
import re
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from capathy.evidence import read_sample
from capathy.process import run_bounded, tool_environment

RELEASE = "ghidra_12.2_PUBLIC"
ARCHIVE = RELEASE + "_20261016.zip"
DIGEST = "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"
URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/" + ARCHIVE


def cache_root():
    return Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "capathy/tools"


def setup_ghidra():
    cache = cache_root()
    target = cache / RELEASE
    if target.is_dir() and (target / ".capathy-sha256").read_text().strip() == DIGEST:
        return target
    archive = cache / "ghidra-download" / ARCHIVE
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        temporary_archive = None
        try:
            with tempfile.NamedTemporaryFile(dir=archive.parent, delete=False) as out:
                temporary_archive = Path(out.name)
                with urllib.request.urlopen(URL, timeout=60) as response:
                    count = 0
                    digest = hashlib.sha256()
                    while chunk := response.read(1 << 20):
                        count += len(chunk)
                        if count > 600 << 20:
                            raise ValueError("Ghidra download exceeds size limit")
                        out.write(chunk)
                        digest.update(chunk)
            if digest.hexdigest() != DIGEST:
                raise ValueError("Ghidra archive checksum mismatch")
            temporary_archive.replace(archive)
        finally:
            if temporary_archive is not None:
                temporary_archive.unlink(missing_ok=True)
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    if digest.hexdigest() != DIGEST:
        raise ValueError("Ghidra archive checksum mismatch; remove the corrupt cached archive and retry")
    with tempfile.TemporaryDirectory(dir=cache) as temporary:
        with zipfile.ZipFile(archive) as zipped:
            if sum(item.file_size for item in zipped.infolist()) > 2 << 30:
                raise ValueError("Ghidra archive expansion limit exceeded")
            for item in zipped.infolist():
                parts = Path(item.filename).parts
                if (
                    not parts
                    or parts[0] != RELEASE
                    or ".." in parts
                    or Path(item.filename).is_absolute()
                    or (item.external_attr >> 16) & 0o170000 == 0o120000
                ):
                    raise ValueError("unsafe Ghidra archive member")
            zipped.extractall(temporary)
            for item in zipped.infolist():
                if not item.is_dir() and (item.external_attr >> 16) & 0o111:
                    member = Path(temporary) / item.filename
                    member.chmod(member.stat().st_mode | 0o100)
        extracted = Path(temporary) / RELEASE
        # ZIP extraction does not restore Unix executable bits.
        for script in (extracted / "support").iterdir():
            if script.is_file() and script.suffix != ".bat":
                script.chmod(script.stat().st_mode | 0o100)
        (extracted / ".capathy-sha256").write_text(DIGEST + "\n")
        if target.exists():
            raise ValueError("unverified Ghidra installation already exists")
        shutil.move(str(extracted), target)
    return target


def validate_report(document, digest):
    if (
        document.get("schema") != 1
        or document.get("kind") != "capathy.decompilation"
        or document.get("sha256") != digest
    ):
        raise ValueError("decompiler report identity mismatch")
    if document.get("analysis_timed_out") is True:
        raise ValueError("Ghidra analysis timed out")
    functions = document.get("functions")
    if not isinstance(functions, list) or len(functions) > 500:
        raise ValueError("invalid decompiler function list")
    seen = set()
    for function in functions:
        address = function.get("address", "")
        if not re.fullmatch(r"[0-9a-fA-F]{1,16}", address) or address in seen:
            raise ValueError("invalid or duplicate decompiler address")
        seen.add(address)
        if not isinstance(function.get("pseudocode"), str) or len(function["pseudocode"]) > 200_000:
            raise ValueError("invalid decompiler pseudocode")
        calls = function.get("calls")
        if (
            not isinstance(calls, list)
            or len(calls) > 10000
            or any(not re.fullmatch(r"[0-9a-fA-F]{1,16}", call) for call in calls)
        ):
            raise ValueError("invalid decompiler call addresses")
    return document


def decompile(path, *, ghidra_home=None, max_functions=100, timeout=240):
    raw = read_sample(path)
    if raw[:4] != b"\x7fELF":
        raise ValueError("decompilation currently accepts ELF files")
    if not 1 <= max_functions <= 500:
        raise ValueError("max-functions must be between 1 and 500")
    digest = hashlib.sha256(raw).hexdigest()
    home = Path(ghidra_home) if ghidra_home else cache_root() / RELEASE
    executable = home / "support/analyzeHeadless"
    if not executable.is_file():
        raise ValueError("Ghidra is missing; run capathy setup-ghidra")
    with tempfile.TemporaryDirectory(prefix="capathy-ghidra-") as temporary:
        temporary = Path(temporary)
        sample = temporary / "sample.elf"
        sample.write_bytes(raw)
        sample.chmod(0o600)
        report = temporary / "decompilation.json"
        run_bounded(
            [
                str(executable.resolve()),
                str(temporary),
                "analysis",
                "-import",
                str(sample),
                "-scriptPath",
                str(Path(__file__).parent / "ghidra"),
                "-postScript",
                "ExportEvidence.java",
                str(report),
                digest,
                str(max_functions),
                "-analysisTimeoutPerFile",
                "120",
                "-max-cpu",
                "2",
                "-deleteProject",
            ],
            timeout=timeout,
            env=tool_environment({"GHIDRA_INSTALL_DIR": str(home)}),
        )
        if not report.is_file() or report.stat().st_size > 32 << 20:
            raise ValueError("missing or oversized Ghidra report")
        document = validate_report(json.loads(report.read_text()), digest)
        document["tool"] = tool_identity(home)
        document["context_only"] = True
        return document


def tool_identity(home):
    properties = Path(home) / "Ghidra/application.properties"
    if not properties.is_file() or properties.stat().st_size > 65536:
        raise ValueError("Ghidra installation identity is missing")
    values = {}
    for line in properties.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    version, release = values.get("application.version"), values.get("application.release.name")
    if not version or not release:
        raise ValueError("Ghidra installation identity is incomplete")
    return f"Ghidra {version} ({release})"
