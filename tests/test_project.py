import pytest

from capathy.project import analyze_project


def test_project_links_are_candidates_and_symlinks_are_omitted(tmp_path):
    (tmp_path / "lib.py").write_text("def work():\n print('hello')\n")
    (tmp_path / "main.py").write_text("from lib import work\nwork()\n")
    (tmp_path / "escape.py").symlink_to(tmp_path / "main.py")
    report = analyze_project(tmp_path)
    assert {file["path"] for file in report["files"]} == {"lib.py", "main.py"}
    link = next(link for link in report["call_links"] if link["call"] == "lib.work")
    assert link["resolution"] == "name-candidate"
    assert link["candidates"][0]["path"] == "lib.py"
    assert any(item["reason"] == "symlink" for item in report["skipped"])
    with pytest.raises(ValueError, match="file count"):
        analyze_project(tmp_path, max_files=1)


def test_ignored_tree_still_obeys_deadline(tmp_path, monkeypatch):
    import capathy.project as module

    (tmp_path / "ignored.txt").write_text("not source")
    times = iter([0, 100, 100, 100, 100])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times, 100))
    with pytest.raises(ValueError, match="timed out"):
        analyze_project(tmp_path, timeout=1)


def test_project_evidence_has_aggregate_limit(tmp_path, monkeypatch):
    import capathy.project as module

    (tmp_path / "source.py").write_text("print('hello')\n")
    monkeypatch.setattr(module, "MAX_EVIDENCE_BYTES", 16, raising=False)
    with pytest.raises(ValueError, match="evidence limit"):
        analyze_project(tmp_path)
