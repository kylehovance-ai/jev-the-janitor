"""A note with no creation date in its frontmatter has an age that resets on a clone. Say so.

Measured on a real vault: 54% of notes have no parseable creation stamp, so
for them the creation-age fix changes nothing, because the data to fix it with is not in
the notes. That is a fact about the vault, and the report has the numbers to state it.
"""

import json
from pathlib import Path

from janitor import cli
from janitor.index import age_source, build_index
from janitor.scan import prepare_vault, scan_vault
from janitor.bill import build_bill, render_bill


def _vault(tmp_path: Path) -> Path:
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "dated.md").write_text("---\ncreated: 2024-01-01\n---\n# Dated\n\nbody one\n", encoding="utf-8")
    (vault / "dated2.md").write_text("---\ndate: 2024-02-02\n---\n# Dated two\n\nbody two\n", encoding="utf-8")
    (vault / "touched.md").write_text("---\nmodified: 2024-03-03\n---\n# Touched\n\nbody three\n", encoding="utf-8")
    (vault / "bare.md").write_text("# Bare\n\nbody four\n", encoding="utf-8")
    (vault / "bad-date.md").write_text("---\ncreated: yesterday-ish\n---\n# Bad\n\nbody five\n", encoding="utf-8")
    return vault


def test_age_source_per_note():
    assert age_source({"created": "2024-01-01"}) == "frontmatter"
    assert age_source({"date": "2024-01-01T10:00:00"}) == "frontmatter"
    assert age_source({"modified": "2024-01-01"}) == "mtime"  # a touch stamp is not a creation stamp
    assert age_source({}) == "mtime" and age_source({"created": "soon"}) == "mtime"


def test_index_rows_and_bill_carry_the_source(tmp_path: Path):
    vault = _vault(tmp_path)
    index = build_index(vault)
    assert {rel: index.notes[rel].age_source for rel in index.notes} == {
        "dated.md": "frontmatter", "dated2.md": "frontmatter", "touched.md": "mtime", "bare.md": "mtime", "bad-date.md": "mtime"}
    rows = {r["path"]: r for r in scan_vault(vault, offline=True)}
    assert rows["dated.md"]["age_source"] == "frontmatter" and rows["bare.md"]["age_source"] == "mtime"
    _, plan, items, _ = prepare_vault(vault)
    bill = build_bill(plan, items)
    assert (bill.dated, bill.age_from_mtime) == (2, 3)
    text = render_bill(bill, live=False)
    assert "age: 3 of 5 readable notes (60%) have no creation date in their frontmatter" in text
    assert "resets if this vault is moved, cloned, restored or re-synced" in text


def test_a_stamp_dated_note_is_counted_as_dated_everywhere(tmp_path: Path, capsys):
    """0.5.3. Since 0.5.2 a third source exists: the date the janitor's stamp recorded. Through 0.5.2
    the bill and the map counted only mtime and frontmatter, so such a note was in neither count and
    "X of N readable notes" undercounted N. One of each kind must read "1 of 3"."""
    from janitor.map import build_map
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "dated.md").write_text("---\ncreated: 2024-01-01\n---\n# Dated\n\nbody one\n", encoding="utf-8")
    (vault / "bare.md").write_text("# Bare\n\nbody two\n", encoding="utf-8")
    (vault / "stamped.md").write_text("---\njanitor:\n  bucket: junk\n  created_from_mtime: 2024-05-05\n---\n# Stamped\n\nbody three\n", encoding="utf-8")
    index = build_index(vault)
    assert {rel: index.notes[rel].age_source for rel in index.notes} == {"dated.md": "frontmatter", "bare.md": "mtime", "stamped.md": "stamp"}
    _, plan, items, _ = prepare_vault(vault)
    bill = build_bill(plan, items)
    assert (bill.dated, bill.stamp_dated, bill.age_from_mtime) == (1, 1, 1)
    text = render_bill(bill, live=False)
    assert "age: 1 of 3 readable notes (33%) have no creation date in their frontmatter" in text  # 0.5.2: "1 of 2 (50%)"
    assert "(1 other undated note(s) carry the date the janitor recorded at their first stamp, which does not reset)" in text
    assert cli.main([str(vault), "--offline", "--json"]) == 0
    out, err = capsys.readouterr()
    assert "findings: 1 of 3 judged notes (33%) have no creation date in their frontmatter" in err
    rows = json.loads(out)
    assert {r["path"]: r["age_source"] for r in rows if r.get("kind") == "vote"} == {"dated.md": "frontmatter", "bare.md": "mtime", "stamped.md": "stamp"}
    totals = build_map(index, rows)["totals"]
    assert (totals["dated"], totals["stamp_dated"], totals["age_from_mtime"]) == (1, 1, 1)


def test_cli_states_the_finding_at_the_end_and_in_json(tmp_path: Path, capsys):
    vault = _vault(tmp_path)
    assert cli.main([str(vault), "--offline"]) == 0
    err = capsys.readouterr().err
    assert "findings: 3 of 5 judged notes (60%) have no creation date in their frontmatter" in err
    assert cli.main([str(vault), "--offline", "--json"]) == 0
    rows = {r["path"]: r for r in json.loads(capsys.readouterr().out)}
    assert sum(1 for r in rows.values() if r.get("age_source") == "mtime") == 3


def test_a_fully_dated_vault_says_nothing(tmp_path: Path, capsys):
    vault = tmp_path / "v"
    vault.mkdir()
    (vault / "a.md").write_text("---\ncreated: 2024-01-01\n---\n# A\n\nbody\n", encoding="utf-8")
    assert cli.main([str(vault), "--offline"]) == 0
    err = capsys.readouterr().err
    assert "no creation date" not in err
