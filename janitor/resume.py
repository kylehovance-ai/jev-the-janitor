"""Resume: read a journal back and decide, per note, cached / retry / new.

A cached vote is served only when today's key for the note equals the key on the row.
The key hashes exactly what would be sent plus the wording, the state version and the
requested model, so a taxonomy edit, a denylist edit, a new sibling, a renamed note or a
code change that alters the state all produce zero hits with no extra logic.

Which journal ``--resume`` continues: the newest run that is unfinished (no end footer, or a
footer that says interrupted or aborted) AND not superseded, where a run is superseded once
a newer journal's header says ``resumed_from`` it. Otherwise the newest run. Through 0.4.5
the newest run without a footer (a crashed run) won outright and for ever, so every
``--resume`` after it re-sent and re-billed what later runs had done, while a Ctrl-C wrote
a footer that called the run completed, so ``--resume`` skipped it. "Newest only" would be
wrong the other way: an ``--offline`` run after a live Ctrl-C would win and the live cache
would be lost. The selection reads each journal's first and last line only.

An unfinished run still beats newer finished runs that did NOT resume it. That is deliberate:
an ``--offline`` run after a live Ctrl-C must not win and hide the live cache. Only a run that
says it resumed the unfinished one supersedes it.

The cache is every vote in the selected run and the chain of runs it resumed, keyed by what
was sent, newest row per key wins, local rows excluded: a resume that is itself stopped
part-way must not make the next resume re-send what its ancestor had already done, and a
descendant with different keys (an offline run, another taxonomy) must not hide the live votes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from janitor.journal import read_journal, read_journal_ends

MAX_CHAIN = 100  # resumed_from links followed; a cycle or a runaway chain stops here


@dataclass
class ResumePlan:
    journal: Path
    header: dict[str, Any]
    cached: dict[str, dict[str, Any]] = field(default_factory=dict)  # key -> vote row
    error_paths: set[str] = field(default_factory=set)  # latest row for the path was an error
    completed: bool = False
    reason: str | None = None  # the footer's reason when not completed: interrupted, meter, 402, error-rate, failed:<Type>
    torn: bool = False
    rows_seen: int = 0
    chain: list[str] = field(default_factory=list)  # journal names this run continues, oldest first, excluding itself
    differences: list[str] = field(default_factory=list)  # header fields that differ from today's run

    @property
    def cached_model(self) -> str | None:
        models = {r.get("model") for r in self.cached.values() if r.get("model")}
        return sorted(models)[0] if len(models) == 1 else None


def _finished(footer: dict[str, Any] | None) -> bool:
    return footer is not None and footer.get("kind") == "end" and not footer.get("interrupted") and not footer.get("aborted")


def newest_journal(directory: Path) -> Path | None:
    if not directory.exists():
        return None
    # Order by modification time, then name: two runs started in the same second share a
    # timestamp prefix and would otherwise sort by their random ids.
    candidates = sorted(directory.glob("run-*.jsonl"), key=lambda p: (p.stat().st_mtime_ns, p.name))
    if not candidates:
        return None
    ends = {p: read_journal_ends(p) for p in candidates}
    superseded = {Path(h["resumed_from"]).name for h, _ in ends.values() if h and h.get("resumed_from")}
    for p in reversed(candidates):
        _, footer = ends[p]
        if not _finished(footer) and p.name not in superseded:
            return p
    return candidates[-1]


def resume_chain(journal: Path) -> list[Path]:
    """The journals this one continues, oldest first, ending with ``journal`` itself."""
    chain = [journal]
    seen = {journal.name}
    current = journal
    while len(chain) < MAX_CHAIN:
        header, _ = read_journal_ends(current)
        parent = (header or {}).get("resumed_from")
        if not parent:
            break
        candidate = Path(parent)
        if not candidate.is_absolute():
            # Written relative to the CWD of the run that wrote it (older journals); try that first.
            candidate = (Path.cwd() / candidate) if (Path.cwd() / candidate).exists() else journal.parent / candidate
        if not candidate.exists() or candidate.name in seen:
            break
        chain.append(candidate)
        seen.add(candidate.name)
        current = candidate
    chain.reverse()
    return chain


HEADER_FIELDS = ("taxonomy", "state_version", "model_requested", "excerpt_cap", "denylist", "include_sensitive", "sensitive_parts")


def load_resume(journal: Path, today: dict[str, Any]) -> ResumePlan:
    chain = resume_chain(journal)
    header, rows, torn = read_journal(journal)
    plan = ResumePlan(journal=journal, header=header or {}, torn=torn, chain=[p.name for p in chain[:-1]])
    latest: dict[str, dict[str, Any]] = {}  # newest row per path: decides which errors are retried
    for p in chain:
        selected = p == journal
        _, prows, _ = (header, rows, torn) if selected else read_journal(p)
        for row in prows:
            kind = row.get("kind")
            if kind == "end":
                if selected:
                    plan.completed = _finished(row)
                    plan.reason = None if plan.completed else (row.get("reason") or ("stop" if row.get("aborted") else "interrupted"))
                continue
            if kind in ("vote", "error", "skip"):
                if selected:
                    plan.rows_seen += 1
                latest[row["path"]] = row
            if kind == "vote" and row.get("key") and row.get("judge") != "local":
                # Every vote in the chain, keyed by exactly what was sent, newest wins per KEY: a
                # descendant row with a different key (an offline run, a new taxonomy or cap) must
                # not hide an ancestor's still-valid live vote for the same note.
                plan.cached[row["key"]] = row
    for path, row in latest.items():
        if row["kind"] == "error":
            plan.error_paths.add(path)
    for f in HEADER_FIELDS:
        if header is not None and f in header and header.get(f) != today.get(f):
            plan.differences.append(f"{f}: {header.get(f)!r} -> {today.get(f)!r}")
    return plan


REASONS = {"interrupted": "interrupted", "meter": "stopped by the meter", "402": "stopped by a 402", "error-rate": "stopped by the error rate",
           "stop": "stopped"}


def describe_state(plan: ResumePlan) -> str:
    if plan.completed:
        return "completed"
    reason = plan.reason or "interrupted"
    if reason.startswith("failed:"):
        return f"failed ({reason[7:]})"
    return REASONS.get(reason, reason)


def resume_summary(plan: ResumePlan, *, cached_hits: int, retries: int, fresh: int) -> str:
    h = plan.header
    lines = [f"resuming run {h.get('run', '?')} from {h.get('started', '?')} ({describe_state(plan)} after {plan.rows_seen} notes){'; last line was torn and dropped' if plan.torn else ''}"]
    if plan.chain:
        lines.append(f"  continues {len(plan.chain)} earlier run(s) it resumed; their rows are served too")
    if plan.differences:
        lines.append("  differences from that run (a differing taxonomy, state version, model, cap or denylist means zero cache hits):")
        lines += [f"    {d}" for d in plan.differences]
    else:
        lines.append(f"  taxonomy unchanged ({h.get('taxonomy', '?')})")
    lines.append(f"  {cached_hits} already voted and unchanged: served from the journal, not sent")
    lines.append(f"  {retries} previous errors: will be retried")
    lines.append(f"  {fresh} new or changed: will be sent")
    return "\n".join(lines)
