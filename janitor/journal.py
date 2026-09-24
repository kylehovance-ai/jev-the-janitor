"""The run journal: one JSON line per finished note, appended as the run goes.

Progress, checkpoint, resume, retry and cache are properties of this file, not separate
features. This module is step 1: writing, reading, and the cache key. Resume is step 2.

The journal records what was decided, never what was sent: no excerpt, no sibling titles.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import platform
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = 1

# Bump when anything that shapes the outgoing state changes: build_state, redaction, the
# instruction strings in schema.py, the excerpt cap. A cached vote from another state
# version is not the same measurement. test_journal pins the digest below so the bump is
# a deliberate act, not something that is forgotten.
STATE_VERSION = 13  # 13: 0.4.7: a password inside a URL is redacted; so are the path and the frontmatter key names; sibling titles are cut after redaction; ASIA ids, PGP and unterminated key blocks, keys after JSON escapes, padded AWS secrets, cards after a leading digit group, denylist entries across whitespace, and more phone shapes are caught. 0.4.6 sent every one of these.
# 12: Telegram tokens redacted after a bare colon and inside Bot API URLs (0.4.1 sent them)
# 11: 16 more credential formats redacted (Telegram, Stripe, GitHub gho_/ghu_/ghs_/ghr_, GOCSPX-, Slack/Discord webhooks, xapp-, SendGrid, npm, GitLab, Hugging Face), and the key line is case-sensitive
# 10: CARD requires a payment-network first digit (2-6)
# 9: CARD requires a card shape, and is_orphan is unknown on a vault that barely links
# 8: denylist matches whole words, PHONE ignores order/invoice numbers, sibling titles are the closest by overlap and cut at 80 chars
# 7: age_days became creation age (earliest created/date; mtime only as a fallback), not last-touched
# 6: graph facts (counts, age, is_moc, is_orphan) and redacted aliases joined the state
# 5: default cap 1,200 -> 16,000 and hard guard 120,000 -> 60,000
# 4: the excerpt cap became a per-run parameter (--excerpt-chars)


def state_sources_digest() -> str:
    """Hash of the source that determines what leaves the machine."""
    from janitor import frontmatter, index, records, redact, scan, schema

    parts = [
        inspect.getsource(scan.build_state),
        inspect.getsource(records.build_record_state),  # what leaves for a record (jev-records), since 0.4.4
        inspect.getsource(redact),
        inspect.getsource(schema.build_questions),
        inspect.getsource(schema.question_payloads),  # the wire form of the questions is built here since 0.4.3
        str(frontmatter.MAX_EXCERPT),
        str(frontmatter.HARD_EXCERPT_CAP),
        # The graph facts are state too. The age fix in 0.3.1 changed a sent value without
        # tripping this wire, because only build_state was watched; now the facts are.
        inspect.getsource(index.VaultIndex.facts),
        inspect.getsource(index.note_age_days),
        inspect.getsource(index.banded_words),
        inspect.getsource(index.banded_age),
        str(index.AGE_BANDS),
    ]
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:16]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def vault_id(root: Path) -> str:
    return hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:16]


def cache_dir() -> Path:
    override = os.environ.get("JEV_JANITOR_CACHE_DIR")
    if override:
        return Path(override)
    if platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "jev-janitor"


def journal_dir_for(root: Path, where: str | None) -> Path | None:
    """Resolve --journal: None/'default' -> cache dir; 'vault' -> <root>/_janitor/runs; 'off' -> None; else a path."""
    if where in (None, "", "default"):
        return cache_dir() / "journals" / vault_id(root)
    if where == "off":
        return None
    if where == "vault":
        return root / "_janitor" / "runs"
    return Path(where)


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def cache_key(state: dict[str, Any], taxonomy: str, model_requested: str | None) -> str:
    """Hash exactly what would be sent, plus the wording, the state version and the model asked for."""
    material = canonical(state) + "\n" + taxonomy + "\n" + str(STATE_VERSION) + "\n" + (model_requested or "jev-latest")
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def denylist_digest(denylist: list[str] | None) -> str | None:
    if not denylist:
        return None
    terms = sorted({t.strip().lower() for t in denylist if t.strip()})
    return hashlib.sha256("\n".join(terms).encode("utf-8")).hexdigest()[:16]


class Journal:
    """Append-only JSONL. Header on open, one line per row, footer on close."""

    def __init__(self, path: Path, header: dict[str, Any], *, fsync: bool = False) -> None:
        self.path = path
        self.fsync = fsync
        self.rows = 0
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8", newline="\n")  # noqa: SIM115 - long-lived handle
        self._write({"kind": "run", "schema": SCHEMA, **header})

    def _write(self, obj: dict[str, Any]) -> None:
        self._fh.write(canonical(obj) + "\n")
        self._fh.flush()
        if self.fsync:
            os.fsync(self._fh.fileno())

    def append(self, row: dict[str, Any]) -> None:
        self._write(row)
        self.rows += 1

    def close(self, footer: dict[str, Any]) -> None:
        if self._fh.closed:
            return
        self._write({"kind": "end", "at": now(), **footer})
        self._fh.close()

    @staticmethod
    def new_path(directory: Path, run_id: str) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        return directory / f"run-{stamp}-{run_id}.jsonl"


def new_run_id() -> str:
    return uuid.uuid4().hex[:8]


def read_journal_ends(path: Path) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """The header (first line) and the end footer (last complete line, if it is one), reading
    neither the body nor the whole file: --resume selects among every journal of a vault."""
    with open(path, "rb") as fh:
        first = fh.readline()
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - 65_536))
        tail = fh.read()
    header: dict[str, Any] | None = None
    try:
        obj = json.loads(first.decode("utf-8"))
        if isinstance(obj, dict) and obj.get("kind") == "run":
            header = obj
    except (ValueError, UnicodeDecodeError):
        header = None
    footer: dict[str, Any] | None = None
    if tail.endswith(b"\n"):  # a torn last line is not a footer
        last = tail.rstrip(b"\n").rsplit(b"\n", 1)[-1]
        try:
            obj = json.loads(last.decode("utf-8"))
            if isinstance(obj, dict) and obj.get("kind") == "end":
                footer = obj
        except (ValueError, UnicodeDecodeError):
            footer = None
    return header, footer


def read_journal(path: Path) -> tuple[dict[str, Any] | None, list[dict[str, Any]], bool]:
    """Return (header, rows, torn). A torn or unparsable last line is dropped, never fatal."""
    header: dict[str, Any] | None = None
    rows: list[dict[str, Any]] = []
    torn = False
    data = path.read_text(encoding="utf-8")
    lines = data.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    elif lines:
        torn = True  # no trailing newline: the last write did not complete
        lines.pop()
    for i, line in enumerate(lines):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            if i == len(lines) - 1:
                torn = True
                break
            raise
        if obj.get("kind") == "run" and header is None:
            header = obj
        else:
            rows.append(obj)
    return header, rows, torn
