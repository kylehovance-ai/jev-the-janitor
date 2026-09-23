"""The one-pass index: every scanned note read once, nothing skipped ever opened.

Duplicate detection, sibling titles, graph facts and the lock bit all come from here.
"""

from datetime import date
from pathlib import Path

import pytest

from janitor import frontmatter as fm
from janitor.index import build_index, is_empty_body, note_age_days, parse_links
from janitor.scan import scan_vault

TODAY = date(2026, 9, 22)


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    files = {
        "notes/alpha.md": "---\ndate: 2026-09-20\naliases: [Alpha One, 'Ada Lovelace']\n---\n# Alpha\n\nSee [[bravo]] and [[projects/plan|the plan]] and [[nowhere]].\n![[diagram.png]]\n",
        "notes/bravo.md": "# Bravo\n\nBack to [[alpha]] and [[alpha#heading]].\n",
        "notes/charlie.md": "# Charlie\n\nSame words as delta.\n",
        "notes/delta.md": "# Delta\n\nSame words as delta.\n",
        "notes/empty.md": "# Only a heading\n\n## and another\n",
        "notes/locked.md": "---\njanitor:\n  locked: true\n  bucket: durable_memory\n---\n# Locked\n\nbody\n",
        "projects/plan.md": "# Plan\n\n" + " ".join(f"[[link{i}]]" for i in range(10)) + "\n",
        "projects/nobody-links-here.md": "---\ncreated: 2025-01-01\n---\n# Lonely\n\nbody\n",
        "family/mom.md": "# Mom\n\n[[alpha]] private link\n",
        ".obsidian/workspace.md": "# hidden\n\n[[alpha]]\n",
        "_janitor/quarantine/held.md": "# held\n\n[[alpha]]\n",
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


def test_index_reads_scanned_notes_once_and_never_opens_skipped_ones(vault: Path, monkeypatch):
    opened: list[str] = []
    real = fm.load_note

    def spy(path):
        opened.append(path.name)
        return real(path)

    monkeypatch.setattr("janitor.index.load_note", spy)
    index = build_index(vault, today=TODAY)
    assert sorted(opened) == sorted(["alpha.md", "bravo.md", "charlie.md", "delta.md", "empty.md", "locked.md", "plan.md", "nobody-links-here.md"])
    assert len(opened) == len(set(opened))  # once each
    assert index.notes["family/mom.md"].note is None and index.notes["family/mom.md"].size > 0
    assert index.notes[".obsidian/workspace.md"].note is None
    assert index.notes["_janitor/quarantine/held.md"].note is None


def test_exact_duplicates_are_vault_wide_and_first_wins(vault: Path):
    index = build_index(vault, today=TODAY)
    assert index.exact_duplicate_of("notes/charlie.md") is None
    assert index.exact_duplicate_of("notes/delta.md") == "notes/charlie.md"
    rows = {r["path"]: r for r in scan_vault(vault, offline=True)}
    assert rows["notes/delta.md"]["exact_duplicate_of"] == "notes/charlie.md"


def test_sibling_titles_come_from_the_folder_pool(vault: Path):
    index = build_index(vault, today=TODAY)
    assert index.sibling_titles("notes/alpha.md", 80) == ["Bravo", "Charlie", "Delta", "Only a heading", "Locked"]
    assert index.sibling_titles("notes/alpha.md", 2) == ["Bravo", "Charlie"]
    assert index.sibling_titles("projects/plan.md", 80) == ["Lonely"]


def test_links_resolve_by_basename_and_by_path(vault: Path):
    index = build_index(vault, today=TODAY)
    alpha = index.notes["notes/alpha.md"]
    assert alpha.links_out == ["notes/bravo.md", "projects/plan.md"]
    assert alpha.unresolved == 1  # [[nowhere]]
    assert alpha.embeds == 1
    assert index.notes["notes/bravo.md"].links_out == ["notes/alpha.md", "notes/alpha.md"]


def test_in_degree_counts_links_from_scanned_notes_only(vault: Path):
    """family/, .obsidian/ and _janitor/ all link to alpha; none of them is read, so none counts."""
    index = build_index(vault, today=TODAY)
    assert index.notes["notes/alpha.md"].in_links == 2  # bravo, twice
    assert index.notes["notes/bravo.md"].in_links == 1
    assert index.notes["projects/plan.md"].in_links == 1
    assert index.notes["projects/nobody-links-here.md"].in_links == 0
    # with --include-sensitive the family note is read and its link counts; its name stays local
    index = build_index(vault, include_sensitive=True, today=TODAY)
    assert index.notes["notes/alpha.md"].in_links == 3


def test_facts_are_numbers_and_name_no_target(vault: Path):
    index = build_index(vault, today=TODAY)
    f = index.facts("notes/alpha.md")
    assert f["words"] == 10 and f["headings"] == 1  # whitespace tokens of the raw markdown, heading included
    assert f["out_links"] == 3 and f["in_links"] == 2 and f["embeds"] == 1 and f["unresolved_links"] == 1
    assert f["age_days"] == 1  # created 2026-09-20, TODAY 2026-09-22: two days, band 1. mtime does not shorten it
    assert f["is_moc"] is False and f["is_orphan"] is False
    assert all(not isinstance(v, str) for v in f.values())
    plan = index.facts("projects/plan.md")
    assert plan["is_moc"] is True  # 10 links, 11 words
    lonely = index.facts("projects/nobody-links-here.md")
    assert lonely["in_links"] == 0 and lonely["is_orphan"] is True  # created 2025-01-01: old enough, whatever the mtime says


def test_orphan_needs_age(tmp_path: Path):
    p = tmp_path / "old.md"
    p.write_text("# Old\n\nbody\n", encoding="utf-8")
    (tmp_path / "linker.md").write_text("# Linker\n\n[[elsewhere]]\n", encoding="utf-8")  # one note links out, so the graph is not sparse
    index = build_index(tmp_path, today=date(2027, 1, 1))  # a year from the mtime
    assert index.facts("old.md")["age_days"] > 30
    assert index.facts("old.md")["is_orphan"] is True


def test_single_file_target_has_unknown_in_degree(vault: Path):
    index = build_index(vault / "notes" / "alpha.md", today=TODAY)
    f = index.facts("alpha.md")
    assert f["in_links"] is None and f["is_orphan"] is None
    assert f["out_links"] == 3


def test_empty_and_locked_and_aliases_are_read_from_the_index(vault: Path):
    index = build_index(vault, today=TODAY)
    assert index.notes["notes/empty.md"].empty is True
    assert index.notes["notes/alpha.md"].empty is False
    assert index.notes["notes/locked.md"].locked is True
    assert index.notes["notes/alpha.md"].locked is False
    assert index.notes["notes/alpha.md"].aliases == ["Alpha One", "Ada Lovelace"]


def test_undecodable_note_is_a_finding_in_the_index_not_a_crash(tmp_path: Path):
    (tmp_path / "bad.md").write_bytes(b"# caf\xe9\n")
    (tmp_path / "ok.md").write_text("# Ok\n\n[[bad]]\n", encoding="utf-8")
    index = build_index(tmp_path, today=TODAY)
    assert index.notes["bad.md"].undecodable.startswith("not valid UTF-8 at byte 5") and index.notes["bad.md"].note is None
    assert index.notes["bad.md"].error is None  # a fact about the vault, not a read failure
    assert index.notes["ok.md"].links_out == ["bad.md"]  # the link still resolves to a file that exists


@pytest.mark.parametrize("body,empty", [("", True), ("\n\n", True), ("# H\n\n## H2\n", True), ("# H\n\ntext\n", False), ("- item\n", False)])
def test_is_empty_body(body, empty):
    assert is_empty_body(body) is empty


def test_parse_links_handles_every_shape():
    targets, embeds = parse_links("[[a]] [[b|alias]] [[c#h]] ![[img.png]] [t](d.md) [u](sub/e.md#x) [v](https://x.y/z.md) ![i](f.md)")
    assert targets == ["a", "b", "c", "d", "sub/e", "https://x.y/z", "f"]  # img.png is an asset, not a note
    assert embeds == 2


def test_note_age_is_creation_age_not_last_touched():
    import time

    assert note_age_days({"date": "2026-09-01"}, time.time(), today=TODAY) == 21  # written now, created 21 days ago: 21
    assert note_age_days({"date": "2026-09-01"}, 0.0, today=TODAY) == 21  # mtime is ignored when a creation date parses
    assert note_age_days({"created": "2023-01-01", "modified": "2026-09-21"}, time.time(), today=TODAY) == (TODAY - date(2023, 1, 1)).days
    assert note_age_days({"created": "2024-06-01", "date": "2023-06-01"}, 0.0, today=TODAY) == (TODAY - date(2023, 6, 1)).days  # earliest wins
    assert note_age_days({"created": "not a date"}, 0.0, today=TODAY) == (TODAY - date(1970, 1, 1)).days  # mtime only as fallback
