"""Exact-body duplicates are detected locally by hash, never by asking Jev.

Live calibration showed five notes with byte-identical bodies and date-differing titles
scoring 0.13 to 0.17 on the title-based duplicate noul. That was the model answering the
question it was given. The hash answers the question we actually had.
"""

from pathlib import Path

from janitor.scan import body_digest, scan_vault


def test_body_digest_normalizes_line_endings_and_outer_whitespace():
    assert body_digest("a\nb\n") == body_digest("a\r\nb\r\n") == body_digest("\n a\nb \n\n".replace(" a", "a").replace("b ", "b"))
    assert body_digest("a\nb") != body_digest("a\nc")


def test_exact_duplicates_point_at_first_occurrence(tmp_path: Path):
    body = "_No messages collected this cycle. Digest runs against an empty source._\n"
    for day in ("01", "02", "03"):
        (tmp_path / f"2026-01-{day}-inbound.md").write_text(f"# Inbound 2026-01-{day}\n\n{body}", encoding="utf-8")
    (tmp_path / "other.md").write_text("# Other\n\nsomething else\n", encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, offline=True)}
    # Bodies differ only in the dated H1, which is the title. Content is identical: duplicates.
    assert rows["2026-01-01-inbound.md"]["exact_duplicate_of"] is None
    assert rows["2026-01-02-inbound.md"]["exact_duplicate_of"] == "2026-01-01-inbound.md"
    assert rows["2026-01-03-inbound.md"]["exact_duplicate_of"] == "2026-01-01-inbound.md"

    # Identical content under frontmatter titles joins the same group.
    for day in ("04", "05"):
        (tmp_path / f"2026-01-{day}-inbound.md").write_text(f"---\ntitle: Inbound 2026-01-{day}\n---\n{body}", encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, offline=True)}
    assert rows["2026-01-04-inbound.md"]["exact_duplicate_of"] == "2026-01-01-inbound.md"
    assert rows["2026-01-05-inbound.md"]["exact_duplicate_of"] == "2026-01-01-inbound.md"
    assert rows["other.md"]["exact_duplicate_of"] is None


def test_heading_only_notes_are_not_all_duplicates(tmp_path: Path):
    (tmp_path / "a.md").write_text("# Alpha\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("# Bravo\n", encoding="utf-8")
    (tmp_path / "c.md").write_text("# Charlie\n\nreal text\n", encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, offline=True)}
    # Two empty-content notes do collapse together; that is correct, both are empty.
    assert rows["b.md"]["exact_duplicate_of"] == "a.md"
    assert rows["c.md"]["exact_duplicate_of"] is None


def test_crlf_copy_is_an_exact_duplicate(tmp_path: Path):
    (tmp_path / "a.md").write_bytes(b"# T\n\nsame body\n")
    (tmp_path / "b.md").write_bytes(b"# T\r\n\r\nsame body\r\n")
    rows = {r["path"]: r for r in scan_vault(tmp_path, offline=True)}
    assert rows["b.md"]["exact_duplicate_of"] == "a.md"
