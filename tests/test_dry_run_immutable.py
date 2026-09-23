"""Dry run is the default, and a dry run changes nothing on disk.

This is the tool's primary safety property. Every file in a vault is hashed before and
after a full dry run, in every dry-run shape the CLI offers, and the tree must be
byte-for-byte unchanged, with no files added or removed and mtimes untouched.
"""

import hashlib
import os
from pathlib import Path

import pytest

from janitor import cli
from janitor import scan as scan_module
from janitor.client import FixtureClient
from janitor.scan import scan_vault

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "notes"


def snapshot(root: Path) -> dict[str, tuple[str, int, int]]:
    """path -> (sha256, size, mtime_ns) for every file under root."""
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            st = p.stat()
            out[p.relative_to(root).as_posix()] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_size, st.st_mtime_ns)
    return out


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    """A copy of the fixture vault plus the tricky shapes: CRLF, BOM, no final newline, a secret."""
    for src in FIXTURES.rglob("*.md"):
        dst = tmp_path / src.relative_to(FIXTURES)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
    (tmp_path / "crlf.md").write_bytes(b"---\r\ntitle: CRLF\r\n---\r\n# CRLF\r\n\r\nbody \xe2\x80\x94 \xf0\x9f\x8c\xb1\r\n")
    (tmp_path / "bom.md").write_bytes(b"\xef\xbb\xbf# BOM\n\nbody\n")
    (tmp_path / "no-newline.md").write_bytes(b"# No newline\n\nbody without final newline")
    (tmp_path / "leak.md").write_bytes(b"# Leak\n\nsk-abcdefghijklmnopqrstuvwxyz012345\n")
    (tmp_path / "_Inbox").mkdir()
    (tmp_path / "_Inbox" / "x.md").write_bytes(b"# Near miss\n\nbody\n")
    return tmp_path


class Recording(FixtureClient):
    def __init__(self):
        self.states = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


def test_offline_dry_run_changes_nothing(vault: Path):
    before = snapshot(vault)
    rows = scan_vault(vault, offline=True)
    assert any(r.get("action") == "quarantine" for r in rows)  # a dry run still *reports* quarantine
    assert snapshot(vault) == before
    assert not (vault / "_janitor").exists()


def test_live_shaped_dry_run_changes_nothing(vault: Path, monkeypatch):
    """Same code path a live run takes (offline=False, recording client), no apply.

    The questions build needs the SDK, which the documented ".[dev]" install leaves out.
    This test is about disk immutability, so the build is neutralised rather than skipped.
    """
    monkeypatch.setattr(scan_module, "build_questions", lambda taxonomy: {})
    before = snapshot(vault)
    rec = Recording()
    scan_vault(vault, client=rec, offline=False, include_sensitive=True, denylist=["Ada"])
    assert rec.states  # the live path was exercised
    assert snapshot(vault) == before


def test_cli_dry_run_shapes_change_nothing(vault: Path, capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    before = snapshot(vault)
    for args in (["--offline"], ["--offline", "--json"], ["--plan"], ["--offline", "--include-sensitive", "--sensitive-paths", "family,_inbox"]):
        assert cli.main([str(vault), *args]) == 0
        capsys.readouterr()
        assert snapshot(vault) == before, args


def test_refused_live_run_changes_nothing(vault: Path, monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "not-a-real-key")
    monkeypatch.setattr(cli, "confirm", lambda prompt: False)
    monkeypatch.setattr(scan_module, "build_questions", lambda taxonomy: {})
    before = snapshot(vault)
    with pytest.raises(SystemExit):
        cli.main([str(vault)])
    assert snapshot(vault) == before


def test_snapshot_detects_a_change(vault: Path):
    """The instrument itself: prove it would notice a single changed byte or mtime."""
    before = snapshot(vault)
    target = vault / "bom.md"
    data = target.read_bytes()
    target.write_bytes(data)  # same bytes, new mtime
    assert snapshot(vault) != before
    os.utime(target, ns=(before["bom.md"][2], before["bom.md"][2]))
    assert snapshot(vault) == before
    target.write_bytes(data + b"x")
    assert snapshot(vault) != before
