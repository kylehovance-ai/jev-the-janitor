"""``--apply`` regenerates the ``janitor:`` block and nothing else in the header.

Through 0.2.1 the whole header went through ``yaml.safe_dump``, a YAML 1.1 interpreter, not
a formatter: ``draft: no`` came back as ``false``, ``port: 0777`` as ``511``, ``country: NO``
as ``false``; comments and quoting style were gone. ``draft: no`` is ordinary Obsidian
frontmatter. Every other header line now comes back as written, in its original order.
"""

from pathlib import Path

import frontmatter

from janitor.apply import splice_janitor_block
from janitor.scan import scan_vault

HEADER = (
    'title: "Quoted — title"\n'
    "draft: no\n"
    "published: yes\n"
    "country: NO\n"
    "port: 0777\n"
    "date: 2026-09-18\n"
    "# a comment, kept where it was\n"
    "aliases: ['one', \"two\"]\n"
    "tags:\n"
    "  - a\n"
    "  - b\n"
)


def test_apply_keeps_every_other_header_line_as_written(tmp_path: Path):
    note = tmp_path / "n.md"
    note.write_bytes(("---\n" + HEADER + "---\n# H\n\nbody\n").encode("utf-8"))
    scan_vault(note, offline=True, apply=True)
    after = note.read_bytes().decode("utf-8")
    assert after.startswith("---\n" + HEADER + "janitor:\n")
    assert after.endswith("\n---\n# H\n\nbody\n")
    assert after.count("janitor:") == 1
    post = frontmatter.loads(after)  # what a YAML reader sees is unchanged too
    assert post.metadata["draft"] is False and post.metadata["port"] == 511
    assert post.metadata["janitor"]["action"] == "frontmatter"


def test_apply_replaces_an_existing_janitor_block_in_place(tmp_path: Path):
    note = tmp_path / "n.md"
    note.write_bytes(
        b"---\ntitle: T\njanitor:\n  bucket: stale\n  at: whenever\n\n# comment after the block\nafter: kept as-is\n---\nbody\n"
    )
    scan_vault(note, offline=True, apply=True)
    after = note.read_bytes().decode("utf-8")
    assert after.startswith("---\ntitle: T\njanitor:\n  bucket: ")
    assert "stale" not in after and "whenever" not in after
    assert after.count("janitor:") == 1
    assert after.endswith("\n\n# comment after the block\nafter: kept as-is\n---\nbody\n")
    post = frontmatter.loads(after)
    assert list(post.metadata) == ["title", "janitor", "after"]


def test_apply_keeps_header_lines_under_crlf(tmp_path: Path):
    note = tmp_path / "n.md"
    note.write_bytes(b"---\r\ndraft: no\r\nport: 0777\r\n---\r\nbody\r\n")
    scan_vault(note, offline=True, apply=True)
    after = note.read_bytes()
    assert after.startswith(b"---\r\ndraft: no\r\nport: 0777\r\njanitor:\r\n")
    assert b"\n" not in after.replace(b"\r\n", b"")


def test_splice_with_no_header_is_the_block_alone():
    assert splice_janitor_block(None, "janitor:\n  a: 1") == "janitor:\n  a: 1"


def test_splice_keeps_a_flow_style_block_to_one_line():
    header = "title: T\njanitor: {bucket: old}\nafter: x"
    assert splice_janitor_block(header, "janitor:\n  bucket: new") == "title: T\njanitor:\n  bucket: new\nafter: x"


def test_splice_does_not_split_on_unicode_line_separators():
    header = "note: line one still line one\ntags: [a]"
    out = splice_janitor_block(header, "janitor:\n  a: 1")
    assert out == header + "\njanitor:\n  a: 1"
