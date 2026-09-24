"""Read markdown notes without sending raw vault bodies.

One parser for reading and for writing. ``split_frontmatter`` here is what ``load_note``
reads with and what ``apply.stamp`` writes with. Through 0.2.0 the reader was
python-frontmatter and the writer was this regex, and the two disagreed on a note that
starts with a UTF-8 BOM: the writer stripped it, the reader did not, so the reader saw no
frontmatter at all, reported no keys, and put the whole YAML header at the top of the
excerpt. Frontmatter values left the machine. Two parsers is one too many.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

MAX_EXCERPT = 16000  # default for --excerpt-chars; 0 means whole notes.
# 16,000 reads 93.6% of a real 18,712-note vault in full (1,200 read 17%) while using about
# 20% of the API's 32,768-token ceiling. Measured 2026-09-21; see README calibration notes.
# The API refuses calls over 32,768 input tokens (measured 2026-09-21: 176,000 chars of prose
# passed, 180,000 failed). Dense text tokenizes worse than prose, and the questions and
# sibling titles ride along, so the hard guard leaves a wide margin.
HARD_EXCERPT_CAP = 60_000  # 120,000 produced 27 max_tokens_exceeded refusals on a real vault:
# dense text tokenises nearer 2.5 chars/token than prose, so 120k chars can exceed 32,768 tokens.
MAX_TITLES = 80

BOM = "﻿"
# Opening fence at start of file, YAML, closing fence; the closing fence may end the file.
FRONTMATTER_RE = re.compile(r"\A-{3,}[ \t]*\r?\n(.*?)(?:\r?\n)?^-{3,}[ \t]*(?:\r?\n|\Z)", re.S | re.M)


def parse_frontmatter(text: str) -> tuple[dict, str, str | None]:
    """Return (metadata, body, error). ``body`` is the exact remainder after the fences.

    ``text`` must already have its BOM removed; the fence has to be the first character.
    A header between fences that YAML cannot parse, or that parses to something other than
    a mapping, is a fact about the note, not a failure of the run: ``error`` says what is
    wrong, ``metadata`` is empty (no key can be named), and ``body`` is everything after the
    closing fence, so the unreadable header text itself never leaves the machine.
    """
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}, text, None
    body = text[m.end():]
    try:
        meta = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError as exc:
        return {}, body, _yaml_error_message(exc)
    if not isinstance(meta, dict):
        return {}, body, f"frontmatter is a {type(meta).__name__}, not a mapping"
    return meta, body, None


def _yaml_error_message(exc: yaml.YAMLError) -> str:
    """The structural part of a parser error, never the quoted source.

    str(exc) on a PyYAML error includes the snippet it choked on, which is raw frontmatter,
    and this string goes on the row and into the journal outside the vault. A broken header
    is exactly where a malformed secret would be. So: the problem phrase (a fixed string in
    PyYAML), the line and column, and nothing else; the owner knows which line to open
    without it being copied anywhere. What remains is run through the redactor as a belt,
    because a few problem phrases quote a token from the source (an undefined alias name).
    """
    from janitor.redact import redact  # local import: redact has no deps on us

    parts: list[str] = []
    problem = getattr(exc, "problem", None)
    context = getattr(exc, "context", None)
    if context:
        parts.append(str(context))
    if problem:
        parts.append(str(problem))
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    if mark is not None:
        # File line numbers: the opening fence is line 1 of the file, so header line 0 is file line 2.
        parts.append(f"line {mark.line + 2} column {mark.column + 1}")
    message = ", ".join(parts) if parts else type(exc).__name__
    # A quoted token in a PyYAML phrase is always copied from the source ("found undefined
    # alias 'x'", "found unknown escape character 'q'"): drop it, whatever it is.
    message = re.sub(r"'[^']*'|\"[^\"]*\"", "'...'", message)
    return "YAML: " + redact(message).text[:160]


def split_frontmatter(text: str) -> tuple[dict, str]:
    """The writer's parser: (metadata, body), or a refusal. A header we cannot read is one we must not rewrite."""
    meta, body, error = parse_frontmatter(text)
    if error:
        raise ValueError(f"frontmatter is unreadable; refusing to rewrite it ({error})")
    return meta, body


@dataclass
class Note:
    path: Path
    title: str
    body: str
    excerpt: str
    keys: list[str]
    existing: dict
    frontmatter_error: str | None = None  # the header between the fences is not readable YAML; a finding


def note_title(path: Path, meta: dict, body: str) -> str:
    """The frontmatter title, else the first H1, else the filename stem with its separators
    turned into spaces. A stem the redactor would change is kept as written instead: the
    separator swap turned `ghp_<36>` into `ghp <36>`, which no pattern matches, so through
    0.4.6 (and 0.4.7's first cut) a token-shaped filename without a title or H1 became a
    title that left in the clear, in every sibling's list and, without local triage, as the
    note's own. Kept whole, the title is redacted to `[KEY]` like any other."""
    from janitor.redact import redact  # local import: redact has no deps on us

    if isinstance(meta.get("title"), str) and meta["title"].strip():
        return meta["title"].strip()
    for line in body.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    if redact(path.stem).hits:
        return path.stem
    return path.stem.replace("-", " ").replace("_", " ")


def load_note(path: Path) -> Note:
    # Strict UTF-8 on purpose: a note we cannot decode is never sent (index.py reports it).
    text = path.read_bytes().decode("utf-8").removeprefix(BOM)
    meta, body, error = parse_frontmatter(text)
    # Line endings are normalised for reading only (the writer re-reads the bytes), so a CRLF
    # note hashes to the same cache key as its LF twin, as it did under the previous reader.
    body = body.replace("\r\n", "\n")
    title = note_title(path, meta, body)
    excerpt = body.strip()[:MAX_EXCERPT]  # raw head, local use only; the outgoing excerpt is redacted first, then cut (scan.build_state)
    keys = sorted(str(k) for k in meta.keys())
    return Note(
        path=path,
        title=title,
        body=body,
        excerpt=excerpt,
        keys=keys,
        existing=dict(meta),
        frontmatter_error=error,
    )


_TITLE_TOKENS = re.compile(r"[a-z0-9]+")


def title_tokens(text: str) -> set[str]:
    return set(_TITLE_TOKENS.findall(text.lower()))


def rank_by_overlap(own_title: str | None, candidates: list[str], cap: int) -> list[str]:
    """The ``cap`` candidate titles closest to ``own_title`` by token overlap, ties in the
    given order. One function for both scan paths: through 0.4.7 a single-file scan took the
    alphabetical first ``cap`` while a directory scan ranked by overlap, so with 81 siblings
    the single-file scan dropped the one near-duplicate title the directory scan kept."""
    own = title_tokens(own_title or "")
    scored: list[tuple[float, int, str]] = []
    for i, title in enumerate(candidates):
        theirs = title_tokens(title)
        overlap = len(own & theirs) / len(own | theirs) if own and theirs else 0.0
        scored.append((-overlap, i, title))
    scored.sort()
    return [t for _, _, t in scored[:cap]]


def collect_titles(root: Path, current: Path, sensitive_parts: tuple[str, ...] | None = None,
                   own_title: str | None = None) -> list[str]:
    """Titles of the other notes in ``current``'s own folder, for duplicate detection: every
    candidate is read, then the MAX_TITLES closest by overlap with ``own_title`` are returned,
    the same ranking as a directory scan (rank_by_overlap).

    Privacy contract: this list leaves the machine as ``other_note_titles``. It therefore
    never includes a note on a sensitive path (``family/``, ``private/`` ...) or anything
    under ``_janitor/``, regardless of ``--include-sensitive``. A path leaks structure; a
    title leaks meaning. Scope is the note's folder, not the vault, which is also what
    makes the list useful: duplicates live next to each other.
    """
    from janitor.policy import HIGH_PRECISION_SECRETS
    from janitor.redact import path_is_sensitive, redact  # local import: redact has no deps on us

    titles: list[str] = []
    for path in sorted(current.parent.glob("*.md")):
        if path == current:
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = path
        if any(part.startswith(".") for part in rel.parts):
            continue
        if "_janitor" in rel.parts or path_is_sensitive(rel.as_posix(), sensitive_parts):
            continue
        try:
            note = load_note(path)
        except Exception:
            continue
        if any(h in HIGH_PRECISION_SECRETS for h in redact(note.title).hits):
            continue  # its own hit quarantines it; it is never sibling context (index.build_index does the same)
        titles.append(note.title)
    return rank_by_overlap(own_title, titles, MAX_TITLES)
