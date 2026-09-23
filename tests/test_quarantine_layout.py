"""Quarantine keeps the path, ignores itself from git, and keeps a record.

Through 0.2.1 `a/note.md` and `b/note.md` both became `_janitor/quarantine/note.md`, the
second one renamed with an mtime; nothing wrote an ignore rule, so a tracked note moved
there was still a tracked secret; and no record said where anything came from.
"""

import json
from pathlib import Path

from janitor.apply import QUARANTINE_IGNORE
from janitor.scan import scan_vault

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"


def _vault(tmp_path: Path) -> Path:
    for rel in ("a/note.md", "b/note.md", "c/deep/er/note.md"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(f"# {rel}\n\nkey {KEY}\n".encode("utf-8"))
    (tmp_path / "fine.md").write_bytes(b"# Fine\n\nbody\n")
    return tmp_path


def test_quarantine_preserves_the_relative_path(tmp_path: Path):
    vault = _vault(tmp_path)
    rows = {r["path"]: r for r in scan_vault(vault, offline=True, apply=True)}
    for rel in ("a/note.md", "b/note.md", "c/deep/er/note.md"):
        assert rows[rel]["action"] == "quarantine"
        assert rows[rel]["applied"] == f"quarantine:_janitor/quarantine/{rel}"
        assert not (vault / rel).exists()
        moved = vault / "_janitor" / "quarantine" / rel
        assert moved.read_bytes().endswith(f"# {rel}\n\nkey {KEY}\n".encode("utf-8"))
    assert rows["fine.md"]["applied"] == "frontmatter"


def test_quarantine_writes_a_gitignore_once(tmp_path: Path):
    vault = _vault(tmp_path)
    scan_vault(vault, offline=True, apply=True)
    ignore = vault / "_janitor" / "quarantine" / ".gitignore"
    assert ignore.read_bytes() == QUARANTINE_IGNORE.encode("utf-8")
    assert ignore.read_text(encoding="utf-8").rstrip().endswith("\n*")
    ignore.write_bytes(b"# edited by the operator\n*\n")
    (vault / "d.md").write_bytes(f"# D\n\nkey {KEY}\n".encode("utf-8"))
    scan_vault(vault / "d.md", offline=True, apply=True)
    assert ignore.read_bytes() == b"# edited by the operator\n*\n"  # written on first move only


def test_quarantine_appends_a_manifest_line_per_move(tmp_path: Path):
    vault = _vault(tmp_path)
    scan_vault(vault, offline=True, apply=True)
    manifest = vault / "_janitor" / "quarantine" / "manifest.jsonl"
    lines = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
    assert sorted(line["from"] for line in lines) == ["a/note.md", "b/note.md", "c/deep/er/note.md"]
    for line in lines:
        assert line["to"] == f"_janitor/quarantine/{line['from']}"
        assert line["reason"] == "local redaction hit: KEY"
        assert line["triggers"] == ["local:KEY"]
        assert line["at"].endswith("Z")


def test_quarantine_collision_gets_a_counter_not_an_mtime(tmp_path: Path):
    vault = _vault(tmp_path)
    scan_vault(vault / "a" / "note.md", offline=True, apply=True)  # single-file mode: root is a/
    assert (vault / "a" / "_janitor" / "quarantine" / "note.md").exists()
    (vault / "a" / "note.md").write_bytes(f"# again\n\nkey {KEY}\n".encode("utf-8"))
    scan_vault(vault / "a" / "note.md", offline=True, apply=True)
    (vault / "a" / "note.md").write_bytes(f"# third\n\nkey {KEY}\n".encode("utf-8"))
    scan_vault(vault / "a" / "note.md", offline=True, apply=True)
    names = sorted(p.name for p in (vault / "a" / "_janitor" / "quarantine").glob("*.md"))
    assert names == ["note-2.md", "note-3.md", "note.md"]


def test_quarantined_notes_and_their_folders_are_never_rescanned(tmp_path: Path):
    vault = _vault(tmp_path)
    scan_vault(vault, offline=True, apply=True)
    rows = scan_vault(vault, offline=True)
    assert {r["path"] for r in rows} == {"fine.md"}
    rows = scan_vault(vault / "_janitor" / "quarantine" / "a", offline=True)
    assert {r["action"] for r in rows} <= {"skip_janitor"} and not any("bucket" in r for r in rows)
