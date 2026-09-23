"""Naming a single file inside a sensitive folder must not bypass the sensitive-path rules.

In 0.1.0 `jev-janitor vault/family/mom.md` sent the body and the family siblings' titles
with no --include-sensitive, because a single file has no vault-relative folders. The
check now looks at the file's own folders (locally; the absolute path never leaves).
"""

import json
from pathlib import Path

import pytest

from janitor import cli
from janitor.client import FixtureClient
from janitor.scan import plan_vault, preflight_summary, scan_vault


class RecordingClient(FixtureClient):
    def __init__(self) -> None:
        self.states: list[dict] = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    (tmp_path / "family").mkdir()
    (tmp_path / "family" / "mom.md").write_text("# Mom Zebra Diagnosis\n\nFAMILY-BODY-SENTINEL\n", encoding="utf-8")
    (tmp_path / "family" / "dad.md").write_text("# Dad Okapi Ledger\n\nbody\n", encoding="utf-8")
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "x.md").write_text("# Ordinary\n\nbody\n", encoding="utf-8")
    return tmp_path


def test_single_file_in_sensitive_folder_is_skipped(vault: Path):
    client = RecordingClient()
    rows = scan_vault(vault / "family" / "mom.md", client=client, offline=True)
    assert rows == [{"kind": "skip", "path": "mom.md", "skipped": "sensitive_path", "action": "skip_sensitive"}]
    assert client.states == []


def test_single_file_with_include_sensitive_sends_body_but_no_sibling_titles(vault: Path):
    client = RecordingClient()
    rows = scan_vault(vault / "family" / "mom.md", client=client, offline=True, include_sensitive=True)
    assert rows[0]["path"] == "mom.md" and "bucket" in rows[0]
    assert len(client.states) == 1
    assert client.states[0]["other_note_titles"] == []
    assert "Okapi" not in json.dumps(client.states)


def test_single_file_in_ordinary_folder_still_scans_with_siblings(vault: Path):
    (vault / "notes" / "y.md").write_text("# Sibling Y\n\nbody\n", encoding="utf-8")
    client = RecordingClient()
    scan_vault(vault / "notes" / "x.md", client=client, offline=True)
    assert client.states[0]["other_note_titles"] == ["Sibling Y"]


def test_single_file_preflight_names_the_folder(vault: Path):
    root, entries = plan_vault(vault / "family" / "mom.md")
    assert entries[0].status == "skip_sensitive"
    assert "sensitive path part 'family'" in entries[0].rule
    text = preflight_summary(root, entries)
    assert "0 of 1 notes" in text and "family" in text


def test_single_file_cli_plan_shows_skip(vault: Path, capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert cli.main([str(vault / "family" / "mom.md"), "--plan"]) == 0
    out = capsys.readouterr().out
    assert "0 of 1 notes" in out and "sensitive path part 'family'" in out


def test_custom_sensitive_parts_apply_in_single_file_mode(vault: Path):
    (vault / "clients").mkdir()
    (vault / "clients" / "acme.md").write_text("# Acme\n\nbody\n", encoding="utf-8")
    rows = scan_vault(vault / "clients" / "acme.md", offline=True, sensitive_parts=("clients",))
    assert rows[0]["action"] == "skip_sensitive"
    rows = scan_vault(vault / "family" / "mom.md", offline=True, sensitive_parts=("clients",))
    assert "bucket" in rows[0]  # 'family' is not in the custom list; the list replaces the default
