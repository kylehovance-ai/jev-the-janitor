"""Every field that leaves is redacted, and its hits are the note's own.

An outside review of 0.4.6's send path found three fields that left as written while the
README said "after local redaction": the vault-relative path, the frontmatter key names and
(through the index's early cut) the tail of a sibling title. A denylisted name in a filename
went out with the title masked and the path in the clear; a key in a folder name never
quarantined. The records path's field names skipped the denylist. And a single file named
inside a hidden folder was scanned, when the same folder under a directory scan is skipped.

Every credential-shaped string here is assembled at runtime from pieces.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from janitor.client import FixtureClient
from janitor.records import field_name_problem, load_records
from janitor.scan import build_state, scan_vault
from janitor.plan import plan_vault


def j(*parts: str) -> str:
    return "".join(parts)


AKIA = j("AK", "IA", "IOSFODNN7EXAMPLE")


class Recording(FixtureClient):
    def __init__(self) -> None:
        self.states: list[dict] = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


# --- finding 1: the path -------------------------------------------------------------------

def test_a_denylisted_name_in_the_filename_leaves_neither_as_title_nor_as_path(tmp_path: Path):
    """No frontmatter title and no H1: the title falls back to the filename stem, which was
    redacted, while the path carried the same name in the clear."""
    _write(tmp_path, {"Meetings/1-1 with Jane Doe.md": "no title here, just a body\n"})
    rec = Recording()
    rows = scan_vault(tmp_path, client=rec, offline=True, denylist=["Jane Doe"])
    [state] = rec.states
    assert state["path"] == "Meetings/1-1 with [NAME].md"
    assert "Jane" not in json.dumps(state)
    assert "NAME" in rows[0]["redacted_own"]


def test_a_denylisted_folder_name_is_redacted_per_segment_with_separators_kept(tmp_path: Path):
    _write(tmp_path, {"clients/Jane Doe/2026/plan.md": "# Plan\n\nordinary body\n"})
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True, denylist=["Jane Doe"])
    [state] = rec.states
    assert state["path"] == "clients/[NAME]/2026/plan.md"


def test_a_key_in_a_folder_name_quarantines_and_the_note_is_never_sent(tmp_path: Path):
    _write(tmp_path, {f"clients/{AKIA}/note.md": "# T\n\nordinary body\n"})
    rec = Recording()
    rows = scan_vault(tmp_path, client=rec, offline=True)
    assert rec.states == []  # decided locally on its own hit
    [row] = rows
    assert row["action"] == "quarantine" and "KEY" in row["redacted_own"]
    assert AKIA not in row["title_sent"]  # the row's own `path` is local, for the operator


def test_a_ten_digit_run_in_a_filename_is_a_phone_to_the_redactor_which_is_the_safe_direction(tmp_path: Path):
    """A Unix timestamp in a filename (`export-1695400000.md`) reads as a phone number, as it
    would in a title. That over-redacts an identifier; PHONE does not quarantine, so the cost
    is one masked token in the path. Stated here so it is known rather than discovered."""
    _write(tmp_path, {"logs/export-1695400000.md": "# Export\n\nordinary body\n"})
    rec = Recording()
    rows = scan_vault(tmp_path, client=rec, offline=True)
    [state] = rec.states
    assert state["path"] == "logs/export-[PHONE].md"
    assert rows[0]["action"] == "frontmatter"


def test_the_row_keeps_the_real_relative_path_for_the_operator(tmp_path: Path):
    """The report and the stamp are local; only the sent state is redacted."""
    _write(tmp_path, {"Meetings/1-1 with Jane Doe.md": "# Meeting\n\nbody\n"})
    rows = scan_vault(tmp_path, client=Recording(), offline=True, denylist=["Jane Doe"])
    assert rows[0]["path"] == "Meetings/1-1 with Jane Doe.md"


# --- finding 3: frontmatter key names ---------------------------------------------------------

def test_frontmatter_key_names_are_redacted_and_count_as_own_hits(tmp_path: Path):
    _write(tmp_path, {"a.md": "---\nJonathan Smith: attended\njane@acme.com: cc\ntags: [x]\n---\n# T\n\nordinary body\n"})
    rec = Recording()
    rows = scan_vault(tmp_path, client=rec, offline=True, denylist=["Jonathan Smith"])
    [state] = rec.states
    assert state["frontmatter_keys"] == ["[NAME]", "[EMAIL]", "tags"]
    assert set(rows[0]["redacted_own"]) >= {"NAME", "EMAIL"}


def test_a_key_shaped_frontmatter_key_name_quarantines(tmp_path: Path):
    _write(tmp_path, {"a.md": f"---\n{AKIA}: true\n---\n# T\n\nordinary body\n"})
    rec = Recording()
    rows = scan_vault(tmp_path, client=rec, offline=True)
    assert rec.states == [] and rows[0]["action"] == "quarantine"


def test_build_state_reports_path_and_key_hits_as_own_not_as_a_neighbours(tmp_path: Path):
    from janitor.frontmatter import load_note

    p = tmp_path / "Jane Doe.md"
    p.write_text("---\nJane Doe: yes\n---\nbody\n", encoding="utf-8")
    note = load_note(p)
    state, hits, own = build_state(note, ["sibling with Jane Doe"], ["Jane Doe"], rel_path="x/Jane Doe.md")
    assert state["path"] == "x/[NAME].md" and state["frontmatter_keys"] == ["[NAME]"]
    assert own == ["NAME"] and hits == ["NAME"]
    state, hits, own = build_state(note, ["sibling with Jane Doe"], ["Jane Doe"], rel_path="plain.md")
    # the filename stem is not the title here (no H1 -> stem "Jane Doe" IS the title), so own still hits
    assert "NAME" in own


# --- finding 4: records field names under the denylist ---------------------------------------

def test_records_field_names_are_checked_against_the_denylist(tmp_path: Path):
    assert field_name_problem("john_smith") is None
    assert field_name_problem("john_smith", ["john"]) == "has a name the redactor would redact; field names are sent"
    p = tmp_path / "r.jsonl"
    p.write_text(json.dumps({"id": "1", "sent": {"john_smith": "x"}}) + "\n", encoding="utf-8")
    assert load_records(p)[0].sent == {"john_smith": "x"}
    with pytest.raises(ValueError, match="line 1: field 1 has a name the redactor would redact"):
        load_records(p, ["john"])


# --- finding 15: a single file under a hidden folder ----------------------------------------

def test_a_single_file_named_inside_a_hidden_folder_is_skipped_like_the_folder_scan_skips_it(tmp_path: Path):
    _write(tmp_path, {".trash/x.md": "# Hidden\n\nordinary body\n", "keep.md": "# Keep\n\nbody\n"})
    _, entries = plan_vault(tmp_path / ".trash" / "x.md")
    assert [e.status for e in entries] == ["skip_hidden"]
    assert ".trash" in entries[0].rule
    rec = Recording()
    rows = scan_vault(tmp_path / ".trash" / "x.md", client=rec, offline=True)
    assert rec.states == [] and all(r.get("kind") != "vote" for r in rows)
    # The same file under the directory scan was always skipped; the two now agree.
    _, entries = plan_vault(tmp_path)
    assert {e.rel: e.status for e in entries} == {".trash/x.md": "skip_hidden", "keep.md": "scan"}


def test_hidden_folders_above_the_vault_root_marker_do_not_count(tmp_path: Path):
    """`~/.vaults/MyVault/.obsidian`: `.vaults` is where the vault was mounted, not a hidden
    folder inside it. With the marker, only segments from the root down are tested."""
    _write(tmp_path, {".vaults/MyVault/.obsidian/app.json": "{}", ".vaults/MyVault/notes/a.md": "# A\n\nbody\n"})
    _, entries = plan_vault(tmp_path / ".vaults" / "MyVault" / "notes" / "a.md")
    assert [e.status for e in entries] == ["scan"]
    _, entries = plan_vault(tmp_path / ".vaults" / "MyVault" / "notes")
    assert [e.status for e in entries] == ["scan"]


def test_a_hidden_directory_named_directly_is_scanned_as_named(tmp_path: Path):
    """You named it; skipping everything would be a green run that judged nothing."""
    _write(tmp_path, {".drafts/a.md": "# A\n\nbody\n"})
    _, entries = plan_vault(tmp_path / ".drafts")
    assert [e.status for e in entries] == ["scan"]
