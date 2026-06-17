"""Runtime setup stays external and refuses an unpinned or modified engine."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from capathy import runtime
from capathy.__main__ import main


def test_integration_bundle_has_only_patch_and_new_adapter_sources():
    config = runtime.manifest()
    assert config["schema"] == 1
    assert len(config["revision"]) == len(config["runtime_revision"]) == 40
    assert len(runtime.integration_digest()) == 64
    assert len(config["overlay"]) == 4
    assert not (Path(__file__).parents[1] / "capa" / "main.py").exists()


def test_missing_runtime_does_not_download_on_analysis(tmp_path, monkeypatch):
    monkeypatch.setenv("CAPATHY_CAPA_ROOT", str(tmp_path / "missing"))
    assert main(["analyze", "--version"]) == 1
    assert not (tmp_path / "missing").exists()


def test_modified_bundle_is_rejected(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle"
    shutil.copytree(runtime.BUNDLE, bundle)
    config = json.loads((bundle / "manifest.json").read_text())
    (bundle / config["patch"]).write_text("tampered")
    monkeypatch.setattr(runtime, "BUNDLE", bundle)
    with pytest.raises(ValueError, match="patch hash"):
        runtime.integration_digest()


def test_different_integration_revision_is_rejected(tmp_path):
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@localhost",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "unrelated",
        ],
        check=True,
    )
    with pytest.raises(ValueError, match="pinned integration revision"):
        runtime.verify_runtime(tmp_path)


def test_existing_runtime_is_reused_only_after_verification(monkeypatch):
    root = runtime.verify_runtime()
    original_git = runtime._git
    commands = []

    def record_git(directory, *arguments, **kwargs):
        commands.append(arguments[0])
        return original_git(directory, *arguments, **kwargs)

    monkeypatch.setattr(runtime, "_git", record_git)
    assert runtime.prepare_runtime() == root
    assert not ({"fetch", "apply", "commit"} & set(commands))


@pytest.fixture
def copied_runtime(tmp_path):
    source = runtime.verify_runtime()
    destination = tmp_path / "runtime"
    subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(source), str(destination)], check=True)
    assert runtime.verify_runtime(destination) == destination
    return destination


def test_modified_engine_is_rejected(copied_runtime):
    (copied_runtime / "capa/main.py").write_text("raise RuntimeError('modified engine')\n")
    with pytest.raises(ValueError, match="modified tracked files"):
        runtime.verify_runtime(copied_runtime)


def test_untracked_engine_code_is_rejected(copied_runtime):
    (copied_runtime / "unexpected.py").write_text("raise RuntimeError('unexpected code')\n")
    with pytest.raises(ValueError, match="untracked files"):
        runtime.verify_runtime(copied_runtime)
