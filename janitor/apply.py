"""Write janitor frontmatter. Never deletes notes, never rewrites a body.

The body is spliced back byte-for-byte: no whitespace stripping, no newline translation,
no re-encoding. The header is spliced too: every line of the existing YAML block is kept as
written, and only the top-level ``janitor:`` block is regenerated (replaced in place, or
appended). Through 0.2.1 the whole header went through ``yaml.safe_dump``, which is a YAML
1.1 interpreter and not a formatter: ``draft: no`` came back as ``false``, ``port: 0777`` as
``511``, and comments and quoting did not come back at all. Writes go to a temp file and
are swapped in with ``os.replace`` so a failure mid-write cannot leave a truncated note
behind (Windows codepage defaults have done exactly that before).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from janitor.client import Vote
from janitor.frontmatter import BOM as _BOM
from janitor.frontmatter import FRONTMATTER_RE
from janitor.frontmatter import split_frontmatter  # noqa: F401  re-exported: the reader and the writer share one parser
from janitor.policy import Action, bucket_margin

# A top-level `janitor:` key at column 0. Its block runs to the next column-0 line that is
# not blank and not indented (a column-0 comment ends it too, and is kept).
_JANITOR_KEY = re.compile(r"^janitor\s*:")


def splice_janitor_block(header: str | None, block: str) -> str:
    """Return the header text with ``block`` as its only ``janitor:`` block.

    ``header`` is the text between the fences (``None`` when the note had no frontmatter);
    ``block`` is the rendered ``janitor:`` mapping. Every other line comes back untouched,
    in its original order, quoting and spelling. Blank lines after the old block are left
    where they were: they separate it from what follows, and that is not ours.
    """
    if header is None:
        return block
    lines = re.split(r"\r?\n", header)  # not splitlines(): it also splits on U+0085 and U+2028 inside a value
    new_lines = block.split("\n")
    start = next((i for i, line in enumerate(lines) if _JANITOR_KEY.match(line)), None)
    if start is None:
        return "\n".join(lines + new_lines)
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or lines[end][0] in " \t"):
        end += 1
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    return "\n".join(lines[:start] + new_lines + lines[end:])


def render_janitor_block(janitor: dict) -> str:
    return yaml.safe_dump({"janitor": janitor}, allow_unicode=True, sort_keys=False, default_flow_style=False).rstrip("\n")


def stamp(note_path: Path, vote: Vote, action: Action, taxonomy: str | None = None) -> bool:
    """Write the janitor block. Returns True if the file changed on disk.

    A re-run that reaches the same conclusion does not touch the note. ``at`` used to be
    rewritten unconditionally, so a second scan dirtied every note in git even where nothing
    moved. The confidence tolerance is the measured call-to-call noise floor (0.05); a vote
    that wanders inside it is the same vote.
    """
    raw = note_path.read_bytes()
    text = raw.decode("utf-8")  # strict on purpose: a note we cannot decode is a note we do not touch
    bom = text.startswith(_BOM)
    if bom:
        text = text[len(_BOM):]
    m = FRONTMATTER_RE.match(text)
    if m:
        meta = yaml.safe_load(m.group(1)) or {}
        if not isinstance(meta, dict):
            raise ValueError("frontmatter is not a mapping; refusing to rewrite it")
        header: str | None = m.group(1)
        body = text[m.end():]
    else:
        meta, header, body = {}, None, text
    newline = "\r\n" if "\r\n" in text else "\n"

    previous = dict(meta.get("janitor") or {})
    janitor = dict(previous)
    # A near-tie is not a decision. Stamping the model's pick as `bucket` let anything that
    # groups notes by `janitor.bucket` read a 0.36-vs-0.34 coin flip as settled.
    janitor.update(
        {
            "bucket": "needs_review" if action.review else vote.bucket,
            "persist": round(vote.persist, 3),
            "confidence": round(vote.bucket_confidence, 3),
            "bucket_margin": bucket_margin(vote.bucket_probabilities),
            "contains_secret": round(vote.contains_secret, 3),
            "safe_to_leave_in_git": round(vote.safe_to_leave_in_git, 3),
            "action": action.name,
            "reason": action.reason,
            "model": vote.model,
            "taxonomy": taxonomy,
        }
    )
    if action.review:
        janitor["suggested_bucket"] = vote.bucket
    else:
        janitor.pop("suggested_bucket", None)

    if not _changed(previous, janitor):
        return False
    janitor["at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    block = splice_janitor_block(header, render_janitor_block(janitor)).replace("\n", newline)
    out = (_BOM if bom else "") + f"---{newline}{block}{newline}---{newline}{body}"
    tmp = note_path.with_name(note_path.name + ".janitor-tmp")
    tmp.write_bytes(out.encode("utf-8"))
    os.replace(tmp, note_path)
    return True


# Scores wander between identical calls; 0.05 is the measured floor (README calibration).
_NOISE = 0.05
_SCORES = ("persist", "confidence", "bucket_margin", "contains_secret", "safe_to_leave_in_git")


def _changed(previous: dict, current: dict) -> bool:
    if not previous:
        return True
    keys = set(previous) | set(current)
    for key in keys - {"at"}:
        old, new = previous.get(key), current.get(key)
        if key in _SCORES and isinstance(old, (int, float)) and isinstance(new, (int, float)):
            if abs(float(old) - float(new)) > _NOISE:
                return True
            continue
        if old != new:
            return True
    return False


QUARANTINE_IGNORE = (
    "# Written by jev-janitor. A quarantined note still contains whatever got it here;\n"
    "# nothing under this folder should reach a public repository. The note's old path is\n"
    "# still in your git history if it was ever committed there.\n"
    "*\n"
)


def quarantine(note_path: Path, vault_root: Path, *, reason: str = "", triggers: list[str] | None = None) -> Path:
    """Move a note, unchanged, to ``_janitor/quarantine/<its vault-relative path>``.

    The relative path is kept, so ``a/note.md`` and ``b/note.md`` stay distinct and the
    note is findable by where it came from. A destination that already exists (an earlier
    run moved a note of the same path) gets a ``-2``, ``-3`` suffix, not an mtime. The
    first move writes ``_janitor/quarantine/.gitignore`` containing ``*``, and every move
    appends one line to ``_janitor/quarantine/manifest.jsonl``: original path, destination,
    reason, time. Through 0.2.1 the path was flattened to the file name, nothing was
    ignored, and no record was kept.
    """
    rel = note_path.relative_to(vault_root)
    qdir = vault_root / "_janitor" / "quarantine"
    dest = qdir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    n = 1
    while dest.exists():
        n += 1
        dest = dest.with_name(f"{rel.stem}-{n}{rel.suffix}")
    ignore = qdir / ".gitignore"
    if not ignore.exists():
        ignore.write_bytes(QUARANTINE_IGNORE.encode("utf-8"))
    note_path.rename(dest)
    line = {
        "from": rel.as_posix(),
        "to": dest.relative_to(vault_root).as_posix(),
        "reason": reason,
        "triggers": list(triggers or []),  # e.g. ["local:KEY"], ["contains_secret"]; see policy.decide
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with (qdir / "manifest.jsonl").open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(line, ensure_ascii=False) + "\n")
    return dest
