"""Age is creation age. On a freshly cloned vault every mtime is now; orphans must still be findable.

A reviewer's matrix on v0.3.0, where every row read age 0 and is_orphan could never fire:
    created 2023, written now       -> must be old
    created 2023 + modified 2023    -> must be old
    date 2024 only                  -> must be old
    no frontmatter dates            -> mtime is all there is: 0 on a fresh clone, and that is honest
"""

from datetime import date
from pathlib import Path

from janitor.index import build_index
from janitor.journal import STATE_VERSION

TODAY = date(2026, 9, 22)


def _write(vault: Path, rel: str, header: str) -> None:
    p = vault / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"---\n{header}---\n# {rel}\n\nbody of {rel}\n" if header else f"# {rel}\n\nbody of {rel}\n", encoding="utf-8")


def test_freshly_written_files_with_creation_dates_are_old_and_orphan_eligible(tmp_path: Path):
    _write(tmp_path, "a.md", "created: 2023-03-01\n")
    _write(tmp_path, "b.md", "created: 2023-03-01\nmodified: 2023-04-01\n")
    _write(tmp_path, "c.md", "date: 2024-01-15\n")
    _write(tmp_path, "d.md", "")
    (tmp_path / "linker.md").write_text("---\ncreated: 2023-03-01\n---\n# linker\n\n[[elsewhere]]\n", encoding="utf-8")  # one note links out, so the graph is not sparse
    index = build_index(tmp_path, today=TODAY)
    ages = {rel: index.notes[rel].age_days for rel in ("a.md", "b.md", "c.md", "d.md")}
    assert ages["a.md"] == (TODAY - date(2023, 3, 1)).days
    assert ages["b.md"] == (TODAY - date(2023, 3, 1)).days  # modified does not shorten it
    assert ages["c.md"] == (TODAY - date(2024, 1, 15)).days
    assert ages["d.md"] == 0  # no date anywhere; mtime is now, and nothing is invented
    facts = {rel: index.facts(rel) for rel in ages}
    assert facts["a.md"]["is_orphan"] is True and facts["b.md"]["is_orphan"] is True and facts["c.md"]["is_orphan"] is True
    assert facts["d.md"]["is_orphan"] is False  # too young to call, by the only evidence there is
    assert facts["a.md"]["age_days"] == 1000 and facts["c.md"]["age_days"] == 365  # banded


def test_editing_a_note_does_not_make_it_younger(tmp_path: Path):
    _write(tmp_path, "old.md", "created: 2022-01-01\n")
    before = build_index(tmp_path, today=TODAY).notes["old.md"].age_days
    (tmp_path / "old.md").write_text("---\ncreated: 2022-01-01\nmodified: 2026-09-22\n---\n# old\n\nedited today\n", encoding="utf-8")
    after = build_index(tmp_path, today=TODAY).notes["old.md"].age_days
    assert before == after == (TODAY - date(2022, 1, 1)).days


def test_state_version_is_at_least_seven():
    assert STATE_VERSION >= 7  # 7 made age creation age; later bumps are later changes
