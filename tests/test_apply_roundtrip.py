"""``--apply`` must never change a single body byte, on any platform, in any codepage.

Acceptance test for the Windows-encoding class of bug: a note with an emoji, curly quotes and
an em-dash used to be truncated to zero bytes by ``write_text`` under cp1252.
"""

from pathlib import Path

import frontmatter
import pytest

from janitor.apply import split_frontmatter
from janitor.scan import scan_vault

TRICKY = "  indented — “quoted” \U0001F331 café\n\n\ntrailing spaces  \n"

CASES = {
    "no-frontmatter.md": "\n# Heading\n" + TRICKY,
    "with-frontmatter.md": "---\ntitle: Existing — title\ntags: [a, b]\n---\n" + TRICKY,
    "crlf.md": ("---\ntitle: CRLF note\n---\n# Heading\n" + TRICKY).replace("\n", "\r\n"),
    "no-final-newline.md": "# Heading\nbody without newline at end \U0001F331",
    "bom.md": "﻿---\ntitle: BOM\n---\n# Heading\nbody\n",
}


def _body_bytes(text: str) -> bytes:
    """The bytes after the original frontmatter block, if any."""
    _, body = split_frontmatter(text.removeprefix("﻿"))
    return body.encode("utf-8")


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    for name, text in CASES.items():
        (tmp_path / name).write_bytes(text.encode("utf-8"))
    return tmp_path


def test_apply_preserves_every_body_byte(vault: Path):
    originals = {name: (vault / name).read_bytes() for name in CASES}
    rows = scan_vault(vault, offline=True, apply=True)
    assert {row["path"] for row in rows} == set(CASES)
    assert all(row["applied"] == "frontmatter" for row in rows)

    for name, before in originals.items():
        after = (vault / name).read_bytes()
        assert after, f"{name} was truncated"
        expected_body = _body_bytes(before.decode("utf-8"))
        assert after.endswith(expected_body), f"{name}: body bytes changed"
        assert after != before, f"{name}: no frontmatter was written"
        assert after.startswith(b"\xef\xbb\xbf") == before.startswith(b"\xef\xbb\xbf"), f"{name}: BOM changed"

        post = frontmatter.loads(after.decode("utf-8").removeprefix("﻿"))
        assert post.metadata["janitor"]["bucket"]
        assert post.metadata["janitor"]["action"] == "frontmatter"

    assert not list(vault.glob("*.janitor-tmp"))


def test_apply_keeps_existing_metadata(vault: Path):
    scan_vault(vault / "with-frontmatter.md", offline=True, apply=True)
    post = frontmatter.load(vault / "with-frontmatter.md", encoding="utf-8")
    assert post.metadata["title"] == "Existing — title"
    assert post.metadata["tags"] == ["a", "b"]
    assert "janitor" in post.metadata


def test_apply_keeps_crlf(vault: Path):
    scan_vault(vault / "crlf.md", offline=True, apply=True)
    data = (vault / "crlf.md").read_bytes()
    assert b"\r\n" in data
    assert b"\n" not in data.replace(b"\r\n", b"")


def test_apply_twice_still_preserves_body(vault: Path):
    target = vault / "no-frontmatter.md"
    scan_vault(target, offline=True, apply=True)
    scan_vault(target, offline=True, apply=True)
    assert target.read_bytes().endswith(_body_bytes(CASES["no-frontmatter.md"]))
    post = frontmatter.load(target, encoding="utf-8")
    assert list(post.metadata) == ["janitor"]


def test_apply_refuses_undecodable_note(tmp_path: Path):
    """A note that is not valid UTF-8 becomes an error row, is never sent, and is left untouched."""
    bad = tmp_path / "latin1.md"
    bad.write_bytes(b"# caf\xe9\nbody\n")
    (tmp_path / "ok.md").write_bytes(b"# Ok\n\nbody\n")
    before = bad.read_bytes()
    rows = {r["path"]: r for r in scan_vault(tmp_path, offline=True, apply=True)}
    # A file that is not UTF-8 is a fact about the vault, not a failure of the run: a finding on a
    # skip row (never sent, never retried), not an error row (retried on --resume).
    assert rows["latin1.md"]["kind"] == "skip" and rows["latin1.md"]["skipped"] == "undecodable"
    assert rows["latin1.md"]["findings"] == ["undecodable"] and "not valid UTF-8" in rows["latin1.md"]["detail"]
    assert rows["ok.md"]["kind"] == "vote"  # the run continued
    assert bad.read_bytes() == before
    assert not list(tmp_path.glob("*.janitor-tmp"))
