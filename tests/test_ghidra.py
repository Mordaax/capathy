import pytest

from capathy.decompile import validate_report


def test_decompiler_checks_sample_and_addresses():
    doc = {
        "schema": 1,
        "kind": "capathy.decompilation",
        "sha256": "a" * 64,
        "functions": [{"address": "00401000", "name": "entry", "pseudocode": "return;", "calls": []}],
    }
    assert validate_report(doc, "a" * 64) == doc
    with pytest.raises(ValueError):
        validate_report(doc, "b" * 64)
    doc["functions"][0]["address"] = "invalid"
    with pytest.raises(ValueError):
        validate_report(doc, "a" * 64)


def test_installer_restores_native_executables_and_checks_hash(tmp_path, monkeypatch):
    import hashlib
    import zipfile

    import capathy.decompile as module

    monkeypatch.setattr(module, "cache_root", lambda: tmp_path)
    archive = tmp_path / "ghidra-download" / module.ARCHIVE
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as zipped:
        for name in ["support/analyzeHeadless", "Ghidra/Features/Decompiler/os/linux_x86_64/decompile"]:
            info = zipfile.ZipInfo(module.RELEASE + "/" + name)
            info.external_attr = 0o100755 << 16
            zipped.writestr(info, "test fixture")
    monkeypatch.setattr(module, "DIGEST", hashlib.sha256(archive.read_bytes()).hexdigest())
    installation = module.setup_ghidra()
    assert (installation / "Ghidra/Features/Decompiler/os/linux_x86_64/decompile").stat().st_mode & 0o100


def test_timed_out_analysis_is_rejected():
    doc = {
        "schema": 1,
        "kind": "capathy.decompilation",
        "sha256": "a" * 64,
        "analysis_timed_out": True,
        "functions": [],
    }
    with pytest.raises(ValueError, match="analysis timed out"):
        validate_report(doc, "a" * 64)


def test_custom_ghidra_identity(tmp_path):
    from capathy.decompile import tool_identity

    properties = tmp_path / "Ghidra/application.properties"
    properties.parent.mkdir()
    properties.write_text("application.version=11.4\napplication.release.name=CUSTOM\n")
    assert tool_identity(tmp_path) == "Ghidra 11.4 (CUSTOM)"


def test_interrupted_download_does_not_poison_cache(tmp_path, monkeypatch):
    import hashlib
    import io
    import zipfile

    import capathy.decompile as module

    monkeypatch.setattr(module, "cache_root", lambda: tmp_path)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zipped:
        zipped.writestr(module.RELEASE + "/support/analyzeHeadless", "fixture")
    data = buffer.getvalue()
    monkeypatch.setattr(module, "DIGEST", hashlib.sha256(data).hexdigest())

    class Interrupted(io.BytesIO):
        def read(self, size=-1):
            raise OSError("connection interrupted")

    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *args, **kwargs: Interrupted(b"partial"))
    with pytest.raises(OSError):
        module.setup_ghidra()
    assert not (tmp_path / "ghidra-download" / module.ARCHIVE).exists()
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(data))
    assert module.setup_ghidra().is_dir()
