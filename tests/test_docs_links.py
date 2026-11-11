"""0.5.9: every relative link in the root markdown files and in docs/ resolves.

The README's detail moved into docs/, one file per section, so a link that used to be an anchor
on one page is now a path and an anchor on another. A link whose file is missing, or whose
#anchor names no heading in its target, fails here and names itself. Anchors are GitHub's
heading slugs: lowercase, spaces to hyphens, punctuation and backticks dropped.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").glob("*.md"))
FENCE = re.compile(r"^```.*?^```[^\n]*$", re.M | re.S)
CODE_SPAN = re.compile(r"`[^`\n]*`")
LINK = re.compile(r"!?\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$", re.M)


def _without_code(text: str) -> str:
    return CODE_SPAN.sub("", FENCE.sub("", text))


def slug(heading: str) -> str:
    """GitHub's anchor for a heading's text."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # a link in a heading contributes its text
    text = re.sub(r"[^\w\- ]", "", text.lower())  # punctuation and backticks dropped; letters, digits, _ and - kept
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    out: set[str] = set()
    for m in HEADING.finditer(FENCE.sub("", path.read_text(encoding="utf-8"))):
        base = slug(m.group(2))
        n = seen.get(base, 0)
        seen[base] = n + 1
        out.add(base if n == 0 else f"{base}-{n}")  # GitHub numbers a repeated heading from -1
    return out


def links(path: Path) -> list[str]:
    return [m.group(1) for m in LINK.finditer(_without_code(path.read_text(encoding="utf-8")))]


def test_the_slug_rules_match_githubs_on_the_headings_this_repo_uses():
    assert slug("What `--apply` guarantees") == "what---apply-guarantees"
    assert slug("Pre-flight: see the membrane before you cross it") == "pre-flight-see-the-membrane-before-you-cross-it"
    assert slug("A vault profile: `janitor.toml`") == "a-vault-profile-janitortoml"
    assert slug("Records in, rows out: `jev-records`") == "records-in-rows-out-jev-records"
    assert slug("See a brain scan") == "see-a-brain-scan"


def test_the_files_checked_include_the_readme_and_every_docs_page():
    names = {p.relative_to(ROOT).as_posix() for p in FILES}
    assert {"README.md", "AGENTS.md", "SECURITY.md", "POLICY.md", "CONTRIBUTING.md"} <= names
    assert {f"docs/{p.name}" for p in (ROOT / "docs").glob("*.md")} <= names and len(names) >= 16


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_every_relative_link_and_anchor_resolves(path: Path):
    broken = []
    for target in links(path):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):  # https:, mailto: and the like are not files
            continue
        file_part, _, anchor = target.partition("#")
        dest = (path.parent / file_part).resolve() if file_part else path
        if not dest.exists():
            broken.append((target, "no such file"))
            continue
        if anchor:
            if dest.suffix != ".md":
                broken.append((target, "an anchor into a file that is not markdown"))
            elif anchor not in anchors(dest):
                broken.append((target, f"no heading with slug {anchor!r} in {dest.relative_to(ROOT).as_posix()}"))
    assert not broken, broken


def test_the_readme_links_every_docs_page_and_some_anchors_are_checked():
    readme_links = links(ROOT / "README.md")
    for page in sorted((ROOT / "docs").glob("*.md")):
        assert f"docs/{page.name}" in readme_links, page.name
    anchored = [t for p in FILES for t in links(p) if "#" in t and not re.match(r"^[a-z]+:", t)]
    assert len(anchored) >= 4, anchored  # the check above is not vacuous
