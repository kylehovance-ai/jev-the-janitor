"""What changed between two scans, from their journals alone. Nothing is re-sent.

A journal row is a decision: bucket, confidence, action, duplicate pointer, findings, the
taxonomy fingerprint and model that produced it. Two journals are enough to say what moved
in the brain between them, and the journal never stores an excerpt, so neither does this.
The diff is the second scan's product: the first scan is a map, the second is a delta.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from janitor.journal import read_journal


@dataclass
class Snapshot:
    path: Path
    header: dict[str, Any]
    rows: dict[str, dict[str, Any]]  # latest row per note path; vote, skip and error rows alike

    @property
    def taxonomy(self) -> str:
        return str(self.header.get("taxonomy", "?"))

    @property
    def model(self) -> str:
        return str(self.header.get("model_requested", "?"))

    @property
    def started(self) -> str:
        return str(self.header.get("started", "?"))


def load_snapshot(path: Path) -> Snapshot:
    header, rows, _ = read_journal(path)
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        p = row.get("path")
        if p and row.get("kind") in ("vote", "skip", "error"):
            latest[p] = row
    return Snapshot(path=path, header=header or {}, rows=latest)


def _in_review(row: dict[str, Any]) -> bool:
    """Routed to a person for a label. A quarantined note is listed under quarantine, not here."""
    return (row.get("kind") == "vote" and row.get("action") != "quarantine"
            and (row.get("bucket") == "needs_review" or bool(row.get("suggested_bucket"))))


@dataclass
class ScanDiff:
    before: Snapshot
    after: Snapshot
    unchanged: int = 0
    new: list[str] = field(default_factory=list)
    gone: list[str] = field(default_factory=list)
    bucket_changed: list[dict[str, Any]] = field(default_factory=list)  # path, old, new, taxonomy/model on each side
    into_review: list[dict[str, Any]] = field(default_factory=list)
    out_of_review: list[dict[str, Any]] = field(default_factory=list)
    quarantined: list[dict[str, Any]] = field(default_factory=list)  # quarantine now, was not before
    released: list[str] = field(default_factory=list)  # was quarantine, is not now
    new_duplicates: list[dict[str, Any]] = field(default_factory=list)  # exact_duplicate_of appeared or changed
    crossed_cap: list[dict[str, Any]] = field(default_factory=list)  # truncated flipped
    findings_before: Counter = field(default_factory=Counter)
    findings_after: Counter = field(default_factory=Counter)
    findings_fixed: list[str] = field(default_factory=list)  # had a finding before, none now
    findings_new: list[str] = field(default_factory=list)
    locked_since: list[str] = field(default_factory=list)
    unlocked_since: list[str] = field(default_factory=list)
    errors_after: list[str] = field(default_factory=list)

    @property
    def wording_changed(self) -> bool:
        return self.before.taxonomy != self.after.taxonomy

    @property
    def model_changed(self) -> bool:
        return self.before.model != self.after.model


def _findings(row: dict[str, Any]) -> list[str]:
    return list(row.get("findings") or [])


def diff_snapshots(before: Snapshot, after: Snapshot) -> ScanDiff:
    d = ScanDiff(before=before, after=after)
    paths_b, paths_a = set(before.rows), set(after.rows)
    d.new = sorted(paths_a - paths_b)
    d.gone = sorted(paths_b - paths_a)
    for p in sorted(paths_a & paths_b):
        b, a = before.rows[p], after.rows[p]
        moved = False
        for f in _findings(b):
            d.findings_before[f] += 1
        for f in _findings(a):
            d.findings_after[f] += 1
        if _findings(b) and not _findings(a):
            d.findings_fixed.append(p)
            moved = True
        if _findings(a) and not _findings(b):
            d.findings_new.append(p)
            moved = True
        if a.get("kind") == "error":
            d.errors_after.append(p)
        b_locked, a_locked = b.get("skipped") == "locked", a.get("skipped") == "locked"
        if a_locked and not b_locked:
            d.locked_since.append(p)
            moved = True
        if b_locked and not a_locked:
            d.unlocked_since.append(p)
            moved = True
        if b.get("kind") == "vote" and a.get("kind") == "vote":
            if b.get("bucket") != a.get("bucket"):
                d.bucket_changed.append({
                    "path": p, "before": b.get("bucket"), "after": a.get("bucket"),
                    "confidence_before": b.get("confidence"), "confidence_after": a.get("confidence"),
                    "judge_before": b.get("judge", "jev"), "judge_after": a.get("judge", "jev"),
                })
                moved = True
            if _in_review(a) and not _in_review(b):
                d.into_review.append({"path": p, "was": b.get("bucket"), "suggested": a.get("suggested_bucket"), "confidence": a.get("confidence")})
                moved = True
            if _in_review(b) and not _in_review(a):
                d.out_of_review.append({"path": p, "was_suggested": b.get("suggested_bucket"), "now": a.get("bucket"), "confidence": a.get("confidence")})
                moved = True
            if a.get("exact_duplicate_of") and a.get("exact_duplicate_of") != b.get("exact_duplicate_of"):
                d.new_duplicates.append({"path": p, "of": a["exact_duplicate_of"]})
                moved = True
            if bool(a.get("truncated")) != bool(b.get("truncated")):
                d.crossed_cap.append({"path": p, "truncated": bool(a.get("truncated"))})
                moved = True
        if a.get("action") == "quarantine" and b.get("action") != "quarantine":
            d.quarantined.append({"path": p, "reason": a.get("reason"), "applied": a.get("applied")})
            moved = True
        if b.get("action") == "quarantine" and a.get("action") != "quarantine":
            d.released.append(p)
            moved = True
        if not moved:
            d.unchanged += 1
    for p in d.new:
        # A note that arrived since the first scan is judged by the second scan's row alone.
        # Through 0.4.0 only its findings and errors were read, so a new note holding a
        # credential was listed as "new" and never as quarantined, and a synthetic test corpus's five
        # planted new duplicate pairs came back as bare paths. What a "what changed" report
        # most needs to say about an arrival is what the scan decided about it.
        a = after.rows[p]
        for f in _findings(a):
            d.findings_after[f] += 1
            d.findings_new.append(p)
        if a.get("kind") == "error":
            d.errors_after.append(p)
        if a.get("action") == "quarantine":
            d.quarantined.append({"path": p, "reason": a.get("reason"), "applied": a.get("applied"), "new": True})
        elif _in_review(a):
            d.into_review.append({"path": p, "was": None, "suggested": a.get("suggested_bucket"), "confidence": a.get("confidence"), "new": True})
        if a.get("exact_duplicate_of"):
            d.new_duplicates.append({"path": p, "of": a["exact_duplicate_of"], "new": True})
        if a.get("skipped") == "locked":
            d.locked_since.append(p)
    for p in d.gone:
        for f in _findings(before.rows[p]):
            d.findings_before[f] += 1
    return d


def _fp(s: str) -> str:
    return s[:12]


def render_diff(d: ScanDiff, *, limit: int = 40) -> str:
    """A delta a person can read. Every list is capped at ``limit`` lines; --json has them all."""
    b, a = d.before, d.after
    lines = [
        f"scan diff: {b.path.name} ({b.started}, taxonomy {_fp(b.taxonomy)}, model {b.model})",
        f"        -> {a.path.name} ({a.started}, taxonomy {_fp(a.taxonomy)}, model {a.model})",
    ]
    if d.wording_changed:
        lines.append("  NOTE: the taxonomy wording changed between these runs; bucket changes below may be the wording, not the notes")
    if d.model_changed:
        lines.append("  NOTE: a different model answered the second run; treat label changes as a different measurement")
    both = len(set(b.rows) & set(a.rows))
    # "unchanged" read as "not edited"; the journals hold decisions, not bodies, so the same
    # decision on an edited note is all this can see.
    lines.append(f"  notes: {both:,} in both ({d.unchanged:,} with the same decision), {len(d.new):,} new, {len(d.gone):,} gone")

    def section(title: str, items: list, fmt) -> None:
        if not items:
            return
        lines.append(f"  {title} ({len(items):,}):")
        for it in items[:limit]:
            lines.append("    " + fmt(it))
        if len(items) > limit:
            lines.append(f"    ... and {len(items) - limit:,} more (--json has every row)")

    section("bucket changed", d.bucket_changed,
            lambda c: f"{c['path']:<48} {c['before']} -> {c['after']}  (confidence {c['confidence_before']} -> {c['confidence_after']}, {c['judge_before']} -> {c['judge_after']})")
    def _was(c: dict[str, Any]) -> str:
        return "new note" if c.get("new") else f"was {c['was']}"

    section("into review", d.into_review, lambda c: f"{c['path']:<48} {_was(c)}, suggested {c['suggested']} at {c['confidence']}")
    section("out of review", d.out_of_review, lambda c: f"{c['path']:<48} was suggested {c['was_suggested']}, now {c['now']} at {c['confidence']}")
    section("quarantined since", d.quarantined, lambda c: f"{c['path']:<48} {'new note, ' if c.get('new') else ''}{c['reason']} ({c['applied'] or 'not moved: dry run'})")
    section("released from quarantine", d.released, lambda p: p)
    section("new exact duplicates", d.new_duplicates, lambda c: f"{c['path']:<48} {'new note, ' if c.get('new') else ''}of {c['of']}")
    section("crossed the excerpt cap", d.crossed_cap, lambda c: f"{c['path']:<48} {'now cut at the cap' if c['truncated'] else 'now sent in full'}")
    section("locked since", d.locked_since, lambda p: p)
    section("unlocked since", d.unlocked_since, lambda p: p)
    section("new notes", d.new, lambda p: p)
    section("gone", d.gone, lambda p: p)
    if d.findings_before or d.findings_after:
        keys = sorted(set(d.findings_before) | set(d.findings_after))
        lines.append("  findings: " + ", ".join(f"{k} {d.findings_before[k]:,} -> {d.findings_after[k]:,}" for k in keys))
        section("findings fixed", d.findings_fixed, lambda p: p)
        section("findings new", d.findings_new, lambda p: p)
    section("errors in the second run", d.errors_after, lambda p: p)
    return "\n".join(lines)


def diff_as_rows(d: ScanDiff) -> dict[str, Any]:
    """The whole delta, for --json. No excerpts: the journals hold none."""
    return {
        "before": {"journal": str(d.before.path), "started": d.before.started, "taxonomy": d.before.taxonomy, "model": d.before.model},
        "after": {"journal": str(d.after.path), "started": d.after.started, "taxonomy": d.after.taxonomy, "model": d.after.model},
        "wording_changed": d.wording_changed,
        "model_changed": d.model_changed,
        "unchanged": d.unchanged,
        "new": d.new,
        "gone": d.gone,
        "bucket_changed": d.bucket_changed,
        "into_review": d.into_review,
        "out_of_review": d.out_of_review,
        "quarantined": d.quarantined,
        "released": d.released,
        "new_duplicates": d.new_duplicates,
        "crossed_cap": d.crossed_cap,
        "findings_before": dict(d.findings_before),
        "findings_after": dict(d.findings_after),
        "findings_fixed": d.findings_fixed,
        "findings_new": d.findings_new,
        "locked_since": d.locked_since,
        "unlocked_since": d.unlocked_since,
        "errors_after": d.errors_after,
    }


def list_journals(directory: Path) -> list[Path]:
    """Every run journal in a directory, oldest first (mtime, then name)."""
    if not directory.exists():
        return []
    return sorted(directory.glob("run-*.jsonl"), key=lambda p: (p.stat().st_mtime_ns, p.name))
