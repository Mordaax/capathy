import hashlib

import pytest

from capathy.corpus import fetch_sample, load_manifest, score


def test_hash_checked_cache_and_confusion_metrics(tmp_path):
    digest = hashlib.sha256(b"sample").hexdigest()
    entry = {
        "id": "example",
        "sha256": digest,
        "path": "example.elf_",
        "revision": "a" * 40,
        "label": "unclassified",
        "expect": {"capability": True},
    }
    (tmp_path / digest).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="checksum"):
        fetch_sample(entry, tmp_path)
    result = score({"a": True, "b": False, "c": True, "d": False}, {"a", "b"})
    assert result == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}


def test_unpinned_corpus_rejected(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"schema":1,"samples":[]}')
    with pytest.raises(ValueError):
        load_manifest(path)
