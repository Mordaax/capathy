"""Prepare an external, pinned capa checkout without vendoring it in Capathy."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

BUNDLE = Path(__file__).parent / "integrations" / "capa"
COMMIT_MESSAGE = "Apply Capathy script integration"


def manifest():
    return json.loads((BUNDLE / "manifest.json").read_text())


def integration_digest():
    """Verify the distributed integration files and derive their cache identity."""
    config = manifest()
    patch = BUNDLE / config["patch"]
    if hashlib.sha256(patch.read_bytes()).hexdigest() != config["patch_sha256"]:
        raise ValueError("capa integration patch hash mismatch")
    for name, expected in config["overlay"].items():
        if hashlib.sha256((BUNDLE / "overlay" / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"capa integration overlay hash mismatch: {name}")
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def runtime_path():
    """Return the external runtime directory selected by configuration."""
    if os.environ.get("CAPATHY_CAPA_ROOT"):
        return Path(os.environ["CAPATHY_CAPA_ROOT"]).expanduser().resolve()
    cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    config = manifest()
    return cache / "capathy" / f"capa-{config['revision'][:12]}-{integration_digest()[:12]}"


def _git(root, *arguments, **kwargs):
    environment = dict(kwargs.pop("env", os.environ))
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        environment.pop(key, None)
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(["git", "-C", str(root), *arguments], check=True, timeout=120, env=environment, **kwargs)


def verify_runtime(root=None):
    """Require an exact, clean integration commit before importing capa."""
    config = manifest()
    integration_digest()
    root = root or runtime_path()
    if not (root / ".git").is_dir():
        raise ValueError("capa runtime is missing; run: python -m capathy setup")
    revision = _git(root, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    if revision != config["runtime_revision"]:
        raise ValueError("capa runtime does not match the pinned integration revision")
    status = _git(root, "status", "--porcelain", "--untracked-files=no", capture_output=True, text=True).stdout
    if status:
        raise ValueError("capa runtime contains modified tracked files; use a fresh runtime directory")
    # Reject untracked Python/code files that could shadow the pinned engine.
    untracked = _git(root, "ls-files", "--others", "--exclude-standard", capture_output=True, text=True).stdout
    if untracked:
        raise ValueError("capa runtime contains untracked files; use a fresh runtime directory")
    return root


def prepare_runtime(source=None):
    """Fetch the pinned upstream revision, apply the patch, and commit deterministically."""
    config = manifest()
    integration_digest()
    root = runtime_path()
    if root.exists():
        return verify_runtime(root)
    root.parent.mkdir(parents=True, exist_ok=True)
    # Build in a unique sibling directory, then atomically publish the completed checkout.
    temporary = Path(tempfile.mkdtemp(prefix=root.name + "-", dir=root.parent))
    try:
        _git(temporary, "init", "--quiet")
        _git(temporary, "remote", "add", "origin", source or config["repository"])
        _git(temporary, "fetch", "--quiet", "--depth=1", "--no-tags", "origin", config["revision"])
        _git(temporary, "checkout", "--quiet", "--detach", config["revision"])
        _git(temporary, "apply", "--check", str((BUNDLE / config["patch"]).resolve()))
        _git(temporary, "apply", str((BUNDLE / config["patch"]).resolve()))
        for name in config["overlay"]:
            destination = temporary / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(BUNDLE / "overlay" / name, destination)
        _git(temporary, "add", "--", "capa", "scripts/lint.py")
        environment = dict(
            os.environ,
            GIT_AUTHOR_NAME="Capathy",
            GIT_AUTHOR_EMAIL="capathy@localhost",
            GIT_COMMITTER_NAME="Capathy",
            GIT_COMMITTER_EMAIL="capathy@localhost",
            GIT_AUTHOR_DATE=config["commit_date"],
            GIT_COMMITTER_DATE=config["commit_date"],
        )
        _git(
            temporary,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            COMMIT_MESSAGE,
            env=environment,
        )
        revision = _git(temporary, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
        expected = config["runtime_revision"]
        if revision != expected:
            raise ValueError(f"prepared runtime revision mismatch: {revision}")
        temporary.rename(root)
        return root
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
