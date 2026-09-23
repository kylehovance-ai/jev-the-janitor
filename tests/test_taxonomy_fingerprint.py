"""Every vote is stamped with a fingerprint of the taxonomy wording that produced it.

Votes move when the YAML wording changes. Without the fingerprint a historical stamp
cannot be interpreted after any edit.
"""

import hashlib
from pathlib import Path

import frontmatter

from janitor.scan import scan_vault
from janitor.schema import DEFAULT_TAXONOMY, taxonomy_fingerprint


def test_fingerprint_is_short_sha256_of_normalized_text():
    text = DEFAULT_TAXONOMY.read_text(encoding="utf-8").replace("\r\n", "\n")
    expected = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    assert taxonomy_fingerprint() == expected
    assert taxonomy_fingerprint(DEFAULT_TAXONOMY) == expected


def test_fingerprint_ignores_line_ending_style(tmp_path: Path):
    """A CRLF checkout (git autocrlf on Windows) must stamp the same fingerprint as LF."""
    lf = tmp_path / "lf.yaml"
    crlf = tmp_path / "crlf.yaml"
    text = DEFAULT_TAXONOMY.read_text(encoding="utf-8").replace("\r\n", "\n")
    lf.write_bytes(text.encode("utf-8"))
    crlf.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    assert lf.read_bytes() != crlf.read_bytes()
    assert taxonomy_fingerprint(lf) == taxonomy_fingerprint(crlf) == taxonomy_fingerprint()


def test_fingerprint_changes_when_wording_changes(tmp_path: Path):
    edited = tmp_path / "vault_memory.yaml"
    edited.write_text(DEFAULT_TAXONOMY.read_text(encoding="utf-8").replace("Scratch,", "Scratch or"), encoding="utf-8")
    assert taxonomy_fingerprint(edited) != taxonomy_fingerprint()


def test_rows_and_stamp_carry_fingerprint(tmp_path: Path):
    note = tmp_path / "note.md"
    note.write_text("# A standing fact\n\nThe shed key hangs by the door.\n", encoding="utf-8")
    rows = scan_vault(note, offline=True, apply=True)
    fp = taxonomy_fingerprint()
    assert rows[0]["taxonomy"] == fp
    post = frontmatter.load(note, encoding="utf-8")
    assert post.metadata["janitor"]["taxonomy"] == fp


def test_custom_taxonomy_fingerprint_is_stamped(tmp_path: Path):
    custom = tmp_path / "custom.yaml"
    custom.write_bytes(DEFAULT_TAXONOMY.read_bytes() + b"\n# local tweak\n")
    note = tmp_path / "note.md"
    note.write_text("# A standing fact\n\nbody\n", encoding="utf-8")
    rows = scan_vault(note, offline=True, apply=True, taxonomy_path=custom)
    assert rows[0]["taxonomy"] == taxonomy_fingerprint(custom)
    assert rows[0]["taxonomy"] != taxonomy_fingerprint()
