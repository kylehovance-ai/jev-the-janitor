"""Walk a vault, redact, vote, optionally apply."""

from __future__ import annotations

import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable
from pathlib import Path
from typing import Any

from janitor.apply import quarantine, stamp
from janitor.client import FixtureClient, JanitorClient, TypeSafeJanitorClient, Vote
from janitor.frontmatter import HARD_EXCERPT_CAP, MAX_EXCERPT, MAX_TITLES, collect_titles
from janitor.journal import cache_key, canonical, now
from janitor.index import MAX_TITLE_CHARS, VaultIndex, body_digest, build_index  # noqa: F401  body_digest re-exported
from janitor.plan import PlanEntry, near_misses, plan_vault, rel_folder, root_refusal  # noqa: F401  re-exported
from janitor.policy import Action, bucket_margin, decide
from janitor.redact import DEFAULT_SENSITIVE_PATH_PARTS, redact
from janitor.schema import build_questions, load_taxonomy, taxonomy_fingerprint
from janitor.triage import LocalDecision, local_decision


def effective_cap(excerpt_chars: int) -> int:
    """0 means whole notes, still bounded by the hard guard; anything else is min(cap, guard)."""
    return HARD_EXCERPT_CAP if excerpt_chars <= 0 else min(excerpt_chars, HARD_EXCERPT_CAP)


def build_state(
    note, titles: list[str], denylist: list[str] | None, rel_path: str | None = None, excerpt_chars: int = MAX_EXCERPT,
    facts: dict[str, Any] | None = None, aliases: list[str] | None = None,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Build the state that leaves the machine.

    Returns ``(state, hits, own_hits)``. ``hits`` is everything redaction stripped from
    anything this note sends, including its siblings' titles, and is what the report shows.
    ``own_hits`` is only this note's own title, aliases and body -- the decision to move a
    file must never be caused by what a neighbour's title contained.

    ``rel_path`` is the vault-relative posix path. The absolute ``note.path`` is never sent:
    it would leak the OS username and directory tree. The relative path is redacted like the
    title, one segment at a time with the separators kept, and its hits count as this note's
    own: through 0.4.6 it left as written, so ``Meetings/1-1 with Jane Doe.md`` sent the title
    as ``[NAME]`` and the path in the clear, and a key in a folder name never quarantined.
    Frontmatter key names are redacted the same way; through 0.4.6 they left as written.
    ``excerpt_chars`` is the cap on the
    redacted body (0 = whole note); the excerpt is part of the hashed state, so changing the
    cap changes the cache key exactly for the notes whose sent text changes.

    ``facts`` are the graph facts from the index (word, heading and link counts, age, is_moc,
    is_orphan): numbers only, computed locally, so Jev can be told a note is a map of
    content or an orphan instead of guessing from a preamble. The names of link targets
    never leave. ``aliases`` are the note's frontmatter aliases, the one frontmatter value
    that is sent, redacted exactly like the title; an alias is a second title.
    """
    if rel_path is None:
        rel_path = note.path.name
    # Redact the whole body locally, THEN cut to the cap. 0.1.1 cut first, so a secret that
    # straddled the cap left as a partial string with no token. A larger cap therefore means
    # more text redacted, never less.
    redacted = redact(note.body.strip(), denylist=denylist)
    redacted.text = redacted.text[:effective_cap(excerpt_chars)]
    title = redact(note.title, denylist=denylist)
    alias_results = [redact(a, denylist=denylist) for a in (aliases or [])]
    # Sibling titles leave the machine too. In 0.1.0 they bypassed redaction and the denylist.
    # Their hits join the reported list: a single-file scan could send a redacted sibling
    # title while `redacted` claimed nothing had been stripped. Each is redacted, THEN cut to
    # MAX_TITLE_CHARS: through 0.4.6 the index cut first, so a denylisted name or a key that
    # straddled the cut left as a fragment with no token, the class the body fix in 0.1.2 closed.
    siblings = [redact(t, denylist=denylist) for t in titles]
    titles = [s.text[:MAX_TITLE_CHARS] for s in siblings]
    segments = [redact(seg, denylist=denylist) for seg in rel_path.split("/")]
    keys = [redact(k, denylist=denylist) for k in note.keys]
    state = {
        "title": title.text,
        "path": "/".join(s.text for s in segments),
        "frontmatter_keys": [k.text for k in keys],
        "aliases": [a.text for a in alias_results],
        "excerpt": redacted.text,
        "other_note_titles": titles,
        "graph": dict(facts or {}),
    }
    own = title.hits + redacted.hits + [h for a in alias_results for h in a.hits]
    own += [h for s in segments for h in s.hits] + [h for k in keys for h in k.hits]
    own_hits = sorted(set(own))
    return state, sorted(set(own_hits + [h for s in siblings for h in s.hits])), own_hits


def preflight_summary(
    vault: Path,
    entries: list[PlanEntry],
    *,
    sensitive_parts: tuple[str, ...] | None = None,
    live: bool = True,
    cached: int = 0,
    excerpt_chars: int = MAX_EXCERPT,
    guard_truncated: int = 0,
) -> str:
    """What is about to leave the machine, folder by folder, before it does."""
    to_scan = [e for e in entries if e.status == "scan"]
    skipped = [e for e in entries if e.status != "scan"]
    included = Counter(e.folder for e in to_scan)
    skipped_by = Counter((e.folder, e.rule) for e in skipped)

    where = "will be sent to TypeSafe" if live else "will be judged by the offline fixture client (nothing leaves the machine)"
    sending = len(to_scan) - cached
    served = f" ({cached} served from the journal, not sent)" if cached else ""
    lines = [f"jev-janitor pre-flight: {sending} of {len(entries)} notes under {vault.name}/ {where}{served}"]
    if excerpt_chars == MAX_EXCERPT:
        lines.append(f"  excerpt: the first {MAX_EXCERPT:,} characters of each note after redaction (default)")
    elif excerpt_chars <= 0:
        lines.append(f"  EXCERPT: WHOLE NOTES. Every note is sent in full after redaction (hard guard {HARD_EXCERPT_CAP:,} characters), not the {MAX_EXCERPT:,}-character default.")
    else:
        lines.append(f"  EXCERPT: the first {excerpt_chars:,} characters of each note after redaction, not the {MAX_EXCERPT:,}-character default.")
    if guard_truncated:
        lines.append(f"  WARNING: {guard_truncated} note(s) exceed the {HARD_EXCERPT_CAP:,}-character guard and will be cut there (the API refuses calls over 32,768 tokens).")
    lines.append("  graph facts: word, heading and link counts, age in days, is_moc, is_orphan, and frontmatter aliases redacted like the title ride along; link targets never do")
    lines.append(f"  folders included ({len(included)}):")
    for folder, n in sorted(included.items()):
        lines.append(f"    {folder:<40} {n:>4} notes")
    if not included:
        lines.append("    (none)")
    lines.append(f"  folders skipped ({len(skipped_by)}):")
    for (folder, rule), n in sorted(skipped_by.items()):
        lines.append(f"    {folder:<40} {n:>4} notes   {rule}")
    if not skipped_by:
        lines.append("    (none)")
    misses = near_misses(entries, sensitive_parts)
    if misses:
        lines.append("  WARNING: folders that contain a sensitive name inside a longer word and do NOT match it (matching is by whole words of the folder name):")
        for segment, part in misses:
            lines.append(f"    '{segment}' contains '{part}' but will be scanned. Add it with --sensitive-paths if it should be skipped.")
    return "\n".join(lines)


class ScanAborted(RuntimeError):
    """A stop: the meter, the error-rate stop or a 402. Carries the rows so far.

    ``in_flight`` is set by the run loop before the stop propagates: how many requests had
    already left for the API when the stop was raised and were then completed and recorded.
    The message states that number, because "nothing more is sent" was false through 0.4.5
    (the pool kept sending) and "at most --workers" is not exact either: a worker that has
    just finished one request has usually started the next before the stop lands.
    """

    def __init__(self, message: str, rows: list[dict[str, Any]], in_flight: int | None = None, reason: str = "stop") -> None:
        super().__init__(message)
        self.rows = rows
        self.in_flight = in_flight
        self.reason = reason  # meter, 402, error-rate: named in the journal footer and by --resume

    def __str__(self) -> str:
        base = super().__str__()
        if self.in_flight is None:
            return base
        n = self.in_flight
        return f"{base} Nothing new was sent after the stop; {n} request{'s' if n != 1 else ''} already in flight completed and {'were' if n != 1 else 'was'} recorded."


ERROR_STOP_WINDOW = 50
ERROR_STOP_RATIO = 0.2


class NotSent(Exception):
    """A queued request that was cancelled by a stop before it reached the API: no row, not billed."""


@dataclass
class Prepared:
    """Everything about one note that is decided locally, before any request."""

    rel: str
    path: Path
    state: dict[str, Any] | None = None
    hits: list[str] = field(default_factory=list)  # everything stripped from anything this note sends
    own_hits: list[str] = field(default_factory=list)  # stripped from THIS note's title and body only
    key: str | None = None
    title: str = ""
    exact_duplicate_of: str | None = None
    cached_row: dict[str, Any] | None = None
    error: BaseException | None = None  # a local failure (undecodable note): never sent
    truncated: bool = False  # the sent excerpt is shorter than the redacted body
    guard_truncated: bool = False  # whole-note mode, but the note exceeded the hard guard
    locked: bool = False  # janitor.locked: true; a person decided, so no request and no rewrite
    local: LocalDecision | None = None  # decided by code (triage.py); never sent
    undecodable: str | None = None  # finding: not valid UTF-8; a skip row, never sent, never retried
    frontmatter_error: str | None = None  # finding: header not readable YAML; judged on its body, never restamped
    age_source: str | None = None  # "frontmatter" or "mtime"; an mtime age resets when the vault is cloned, restored or synced


def prepare_vault(
    vault: Path,
    *,
    taxonomy_path: Path | None = None,
    include_sensitive: bool = False,
    sensitive_parts: tuple[str, ...] | None = None,
    denylist: list[str] | None = None,
    model_requested: str = "jev-latest",
    cache: dict[str, dict[str, Any]] | None = None,
    excerpt_chars: int = MAX_EXCERPT,
    index: VaultIndex | None = None,
    local_triage: bool = True,
) -> tuple[Path, list[PlanEntry], list[Prepared], str]:
    """Index, redact, hash. Local only. Returns (root, plan, prepared, taxonomy fingerprint).

    Pass an ``index`` built by the caller to share it with the pre-flight; otherwise one is
    built here. Either way every note is read exactly once, in the index.
    """
    if index is None:
        index = build_index(vault, include_sensitive=include_sensitive, sensitive_parts=sensitive_parts)
    root, plan = index.root, index.plan
    fingerprint = taxonomy_fingerprint(taxonomy_path)
    items: list[Prepared] = []
    for entry in plan:
        if entry.status != "scan":
            continue
        ix = index.notes[entry.rel]
        item = Prepared(rel=entry.rel, path=ix.path)
        if ix.undecodable is not None:
            item.undecodable = ix.undecodable
            items.append(item)
            continue
        if ix.error is not None or ix.note is None:
            item.error = ix.error or RuntimeError("note was not read")
            items.append(item)
            continue
        note = ix.note
        item.frontmatter_error = note.frontmatter_error
        item.age_source = ix.age_source
        try:
            item.exact_duplicate_of = index.exact_duplicate_of(entry.rel)
            if entry.sensitive:
                titles: list[str] = []  # a sensitive note gets no sibling context and gives none
            elif index.single_file:
                titles = collect_titles(root, ix.path, sensitive_parts=sensitive_parts)
            else:
                titles = index.sibling_titles(entry.rel, MAX_TITLES, own_title=note.title)
            item.state, item.hits, item.own_hits = build_state(
                note, titles, denylist, rel_path=entry.rel, excerpt_chars=excerpt_chars,
                facts=index.facts(entry.rel), aliases=ix.aliases,
            )
            item.title = note.title
            item.truncated = len(note.body.strip()) > effective_cap(excerpt_chars)
            item.guard_truncated = excerpt_chars <= 0 and item.truncated
            item.key = cache_key(item.state, fingerprint, model_requested)
            item.locked = ix.locked
            if local_triage and not item.locked:
                item.local = local_decision(ix, index, item.own_hits)
            if cache and item.local is None and not item.locked and item.key in cache and cache[item.key].get("judge") != "local":
                # A local row (an exact duplicate, an empty body, a credential hit) is a fact about
                # the vault on the day it was decided, not a vote: the twin it duplicated may have
                # been edited since. Local decisions cost nothing, so they are never served.
                item.cached_row = cache[item.key]
        except Exception as exc:  # noqa: BLE001 - recorded as an error row, never sent
            item.error = exc
        items.append(item)
    return root, plan, items, fingerprint


def _vote_row(item: Prepared, vote: Vote, action: Action, applied: str | None, fingerprint: str, started: float,
              payload: bool = False) -> dict[str, Any]:
    row = {
        "kind": "vote",
        "judge": "local" if item.local is not None else "jev",
        "path": item.rel,
        "bucket": vote.bucket,
        "persist": round(vote.persist, 3),
        "confidence": round(vote.bucket_confidence, 3),
        "bucket_probabilities": {k: round(v, 3) for k, v in sorted(vote.bucket_probabilities.items(), key=lambda kv: -kv[1])},
        "bucket_margin": bucket_margin(vote.bucket_probabilities),
        "contains_secret": round(vote.contains_secret, 3),
        "looks_like_duplicate": round(vote.looks_like_duplicate, 3),
        "exact_duplicate_of": item.exact_duplicate_of,
        "records_a_decision": round(vote.records_a_decision, 3),
        "is_actionable": round(vote.is_actionable, 3),
        "safe_to_leave_in_git": round(vote.safe_to_leave_in_git, 3),
        "action": action.name,
        "reason": action.reason,
        "redacted": item.hits,
        "redacted_own": item.own_hits,  # the subset that can move this file; see policy.decide
        "quarantine_triggers": action.triggers,
        "title_sent": (item.state or {}).get("title", ""),
        "sibling_titles_sent": len((item.state or {}).get("other_note_titles", [])),
        "excerpt_chars": len(item.state["excerpt"]) if item.state else 0,
        "suggested_bucket": vote.bucket if action.review else None,
        "findings": ["unreadable_frontmatter"] if item.frontmatter_error else [],
        "frontmatter_error": item.frontmatter_error,
        "age_source": item.age_source,
        # The graph facts as sent: numbers only, no text, so they belong on every row and in the
        # journal. Until now they existed only under --show-payload, which made a grader that
        # needed is_orphan or is_moc blame the scanner for the operator's choice of flag.
        "graph": dict((item.state or {}).get("graph") or {}),
        "truncated": item.truncated,
        "applied": applied,
        "model": vote.model,
        "input_tokens": vote.input_tokens,  # what the API counted; compare with the pre-flight estimate
        "payload_chars": len(canonical(item.state)) if item.state else 0,  # what was sent, for the measured chars/token
        "taxonomy": fingerprint,
        "key": item.key,
        "cached": False,
        "at": now(),
        "ms": round((time.perf_counter() - started) * 1000),
    }
    if payload:
        # The exact object that left the machine. Operator-facing only: SECURITY.md tells
        # people to read the excerpt, and until now the report had no excerpt to read.
        # Never journaled -- the journal lives outside the vault, and redacted vault text
        # does not belong outside the vault permanently.
        row["sent"] = item.state
    return row


def meter_check(state: dict[str, Any], spend_limit: float | None, rows: list[dict[str, Any]], unit: str) -> None:
    """Stop the run when the API's own token counts have cost more than the ceiling.

    The pre-flight guards the estimate at the pessimistic anchor; this guards the run at the
    meter, so a vault denser than anything the anchors were measured on cannot pass the
    ceiling by more than one in-flight window. ``--resume`` continues from the last row.
    """
    if spend_limit is None or not state["tokens"] or state.get("stop"):
        return
    from janitor.bill import CHARS_PER_TOKEN_HIGH, CHARS_PER_TOKEN_LOW, usd_apart, usd_for

    spent = usd_for(state["tokens"])
    if spent > spend_limit:
        ratio = state["chars"] / state["tokens"]
        # One precision for both, widened past usd()'s when the overshoot is smaller than it
        # shows: "$0.0058 passed the ceiling $0.0058" was true and unreadable.
        spent_s, limit_s = usd_apart(spent, spend_limit)
        state["stop"] = True  # before the raise: a worker that dequeues in this instant sends nothing
        raise ScanAborted(
            f"stopping: measured spend {spent_s} passed the ceiling {limit_s} after {state['metered']:,} sent {unit} "
            f"({state['tokens']:,} input tokens; this text measures {ratio:.2f} chars/token on payload plus questions, "
            f"where the pre-flight assumed {CHARS_PER_TOKEN_HIGH} to {CHARS_PER_TOKEN_LOW} on the same basis). "
            f"--resume continues from here; --max-usd raises the ceiling.", rows, reason="meter")


def _error_row(rel: str, exc: BaseException) -> dict[str, Any]:
    return {"kind": "error", "path": rel, "at": now(), "attempt": 1, "action": "error",
            "error": type(exc).__name__, "detail": redact(str(exc)).text[:500]}  # an SDK error may echo the request; the journal is outside the vault


def _vote_from_row(row: dict[str, Any]) -> Vote:
    return Vote(
        bucket=row["bucket"], bucket_probabilities=dict(row.get("bucket_probabilities") or {}), bucket_confidence=row["confidence"],
        persist=row["persist"], persist_confidence=0.0, contains_secret=row["contains_secret"],
        looks_like_duplicate=row["looks_like_duplicate"], records_a_decision=row["records_a_decision"],
        is_actionable=row["is_actionable"], safe_to_leave_in_git=row["safe_to_leave_in_git"], model=row.get("model", ""),
    )


def run_prepared(
    root: Path,
    plan: list[PlanEntry],
    items: list[Prepared],
    *,
    engine: JanitorClient,
    questions: dict,
    fingerprint: str,
    apply: bool = False,
    on_row: Callable[[dict[str, Any]], None] | None = None,
    workers: int = 1,
    trust_cache_across_models: bool = False,
    git_unsafe_threshold: float | None = None,
    payload: bool = False,
    spend_limit: float | None = None,
    question_chars: int = 0,
) -> list[dict[str, Any]]:
    """Vote (or serve from cache), decide, optionally apply. One writer: rows are emitted here only.

    With workers > 1 the request, decision and apply for each note run in a thread pool;
    everything that touches shared state (rows, the journal callback, the error-rate stop,
    the drift check, the spend meter) happens in this thread as results complete.

    ``spend_limit`` is the ceiling in dollars applied to what the API actually charged, row
    by row, from ``input_tokens``. The pre-flight guards the estimate; this guards the run.
    The first live run on generated filler measured 2.17 chars/token against a pessimistic
    anchor of 2.8, so the estimate was 35% light and the estimate-only guard would have let
    the ceiling be passed by a third before the measured line said a word. ``question_chars``
    is added once per metered call so the ratio the abort message prints is on the same
    basis as the range and the measured line (payload plus questions); the first cut counted
    the payload alone and would have printed 0.99 for text that measures 2.17.
    """
    rows: list[dict[str, Any]] = []

    def emit(row: dict[str, Any]) -> None:
        rows.append(row)
        if on_row is not None:
            on_row(row)

    for entry in plan:
        if entry.status == "skip_sensitive":
            emit({"kind": "skip", "path": entry.rel, "skipped": "sensitive_path", "action": "skip_sensitive"})

    def call_decide(item: Prepared, vote: Vote) -> Action:
        # `item.hits` is what local redaction found in THIS note. It is checked before the
        # vote, because redaction runs before the call: Jev sees `[KEY]`, not the key.
        return decide(vote, hits=item.own_hits, git_unsafe_threshold=git_unsafe_threshold)

    cached_models = {it.cached_row.get("model") for it in items if it.cached_row and it.cached_row.get("model")}
    state = {"cache_enabled": True, "sent": 0, "errors": 0, "drift_checked": False, "tokens": 0, "chars": 0, "metered": 0, "stop": False,
             "in_writer": False, "writer_failed": False}

    def work(item: Prepared) -> tuple[Prepared, Vote | None, Action | None, str | None, BaseException | None, float]:
        started = time.perf_counter()
        if state["stop"] and item.local is None:
            # A stop landed between this request leaving the queue and reaching the API.
            return item, None, None, None, NotSent(), started
        try:
            if item.local is not None:
                vote, action = item.local.vote, item.local.action  # decided in code; nothing is sent
            else:
                vote = engine.vote(item.state, questions)
                action = call_decide(item, vote)
            applied = None
            if apply and not state["stop"]:
                # A stop landed while this request was in flight: the vote was billed, but no
                # file changes without a row, and after an interrupt inside the writer there is
                # no row. --resume judges (or, from a row, applies) it again.
                if item.frontmatter_error:
                    applied = "unchanged: frontmatter unreadable"  # a header we cannot read is one we must not rewrite
                else:
                    applied = "frontmatter" if stamp(item.path, vote, action, taxonomy=fingerprint) else "unchanged"
                if action.name == "quarantine":
                    dest = quarantine(item.path, root, reason=action.reason, triggers=action.triggers)
                    applied = f"quarantine:{dest.relative_to(root).as_posix()}"
            return item, vote, action, applied, None, started
        except Exception as exc:  # noqa: BLE001
            return item, None, None, None, exc, started

    def finish(item: Prepared, vote: Vote | None, action: Action | None, applied: str | None, exc: BaseException | None, started: float) -> None:
        if isinstance(exc, NotSent):
            state["sent"] -= 1  # cancelled before the API saw it: no row, nothing billed, --resume sends it
            return
        if exc is not None:
            state["errors"] += 1
            emit(_error_row(item.rel, exc))
            from janitor.records import OUT_OF_CREDITS, out_of_credits  # local import: records imports scan

            if state["stop"]:
                return  # draining after a stop: record, never raise a second time
            if out_of_credits(exc):
                # The account, not the run: --resume cannot help until credits are added.
                state["stop"] = True
                raise ScanAborted(OUT_OF_CREDITS, rows, reason="402")
            if state["sent"] >= ERROR_STOP_WINDOW and state["errors"] / state["sent"] > ERROR_STOP_RATIO:
                state["stop"] = True
                raise ScanAborted(f"stopping: {state['errors']} of the first {state['sent']} sent notes failed; that is the run, not the notes.", rows, reason="error-rate")
            return
        assert vote is not None and action is not None
        if item.local is None and not state["drift_checked"] and cached_models:
            state["drift_checked"] = True
            if vote.model not in cached_models and not trust_cache_across_models:
                state["cache_enabled"] = False
                emit({"kind": "event", "event": "model_drift", "at": now(),
                      "detail": f"cached votes are from {sorted(cached_models)}, this run gets {vote.model!r}; cached votes are no longer served"})
        emit(_vote_row(item, vote, action, applied, fingerprint, started, payload=payload))
        if item.local is None and vote.input_tokens:
            state["tokens"] += vote.input_tokens
            state["chars"] += len(canonical(item.state)) + question_chars  # the basis the range is defined on
            state["metered"] += 1
            meter_check(state, spend_limit, rows, "notes")

    def serve_cached(item: Prepared) -> None:
        row = dict(item.cached_row or {})
        row.update({"cached": True, "at": now(), "ms": 0, "exact_duplicate_of": item.exact_duplicate_of})
        if apply and row.get("applied") is None:
            # The cached run was a dry run; this one applies. Rebuild the vote from the row.
            vote = _vote_from_row(row)
            action = call_decide(item, vote)
            if item.frontmatter_error:
                row["applied"] = "unchanged: frontmatter unreadable"
            else:
                row["applied"] = "frontmatter" if stamp(item.path, vote, action, taxonomy=fingerprint) else "unchanged"
            if action.name == "quarantine":
                dest = quarantine(item.path, root, reason=action.reason, triggers=action.triggers)
                row["applied"] = f"quarantine:{dest.relative_to(root).as_posix()}"
        emit(row)

    def serve(item: Prepared) -> None:
        state["in_writer"] = True  # emit, on_row, the journal and, under --apply, stamp: the writer too
        try:
            serve_cached(item)
        except BaseException:
            state["writer_failed"] = True
            state["stop"] = True
            raise
        finally:
            state["in_writer"] = False

    todo: list[Prepared] = []
    for item in items:
        if item.undecodable is not None:
            emit({"kind": "skip", "judge": "local", "path": item.rel, "skipped": "undecodable", "action": "skip_undecodable",
                  "findings": ["undecodable"], "detail": item.undecodable})
        elif item.error is not None:
            emit(_error_row(item.rel, item.error))
        elif item.locked:
            emit({"kind": "skip", "judge": "local", "path": item.rel, "skipped": "locked", "action": "skip_locked"})
        else:
            todo.append(item)

    if workers <= 1:
        try:
            for item in todo:
                if state["cache_enabled"] and item.cached_row is not None:
                    serve(item)
                    continue
                if item.local is None:
                    state["sent"] += 1
                finish(*work(item))
        except ScanAborted as exc:
            exc.in_flight = 0  # one at a time: nothing was in flight
            raise
        return rows

    # workers > 1: cached items are served inline in plan order; fresh ones go to the pool.
    # Results are finished here, in this thread, as they complete: one writer. The window
    # is bounded by waiting, not by polling: through 0.4.5 the loop only collected futures
    # that happened to be done, so the queue held nearly the whole run, and a stop raised
    # inside the executor's context let every queued request run, bill and vanish.
    pending: set = set()

    def record(result) -> None:
        # The writer: finish, emit, the journal callback. A Ctrl-C that lands in here leaves
        # in_writer set, and the stop below then cancels without draining (a drain would
        # re-enter the interrupted writer and could tear a journal line).
        state["in_writer"] = True
        try:
            finish(*result)
        except BaseException:
            state["writer_failed"] = True  # the interrupt or failure landed in the writer: never drain through it
            state["stop"] = True
            raise
        finally:
            state["in_writer"] = False

    def finish_done() -> None:
        done, _ = wait(pending, return_when=FIRST_COMPLETED)
        for f in done:
            pending.discard(f)
            record(f.result())

    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        for item in todo:
            if state["cache_enabled"] and item.cached_row is not None:
                serve(item)
                continue
            if item.local is not None:
                record(work(item))  # no request: done inline, in plan order
                continue
            state["sent"] += 1
            pending.add(pool.submit(work, item))
            while len(pending) >= workers * 4:  # bounded in-flight window
                finish_done()
        while pending:
            finish_done()
    except (ScanAborted, KeyboardInterrupt) as exc:
        # A stop or Ctrl-C: nothing queued goes out; what had already left for the API completes
        # and is recorded (it was sent and billed, and under --apply its file was written), then
        # the exception is re-raised with every row and, for a stop, the count.
        state["stop"] = True
        for f in pending:
            f.cancel()
        if isinstance(exc, KeyboardInterrupt) and state["writer_failed"]:
            raise  # the interrupt landed inside the writer: cancel, do not drain through it
        in_flight = 0
        for f in wait(pending).done:
            if f.cancelled():
                state["sent"] -= 1
                continue
            result = f.result()
            in_flight += 0 if isinstance(result[4], NotSent) else 1
            record(result)
        if isinstance(exc, ScanAborted):
            exc.in_flight = in_flight
        raise
    except BaseException:
        # A failure in finish or on_row (the writer): nothing queued goes out, but the drain is
        # skipped, because it would call the broken writer again. What is in flight finishes
        # (the executor waits) billed but unrecorded; --resume re-sends it.
        state["stop"] = True
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    return rows


def scan_vault(
    vault: Path,
    *,
    client: JanitorClient | None = None,
    taxonomy_path: Path | None = None,
    apply: bool = False,
    include_sensitive: bool = False,
    sensitive_parts: tuple[str, ...] | None = None,
    denylist: list[str] | None = None,
    offline: bool = False,
    model: str | None = None,
    on_row: Callable[[dict[str, Any]], None] | None = None,
    cache: dict[str, dict[str, Any]] | None = None,
    workers: int = 1,
    trust_cache_across_models: bool = False,
    excerpt_chars: int = MAX_EXCERPT,
    local_triage: bool = True,
) -> list[dict[str, Any]]:
    """Scan a vault or one note. Returns one row per note; calls ``on_row`` as each row is final.

    Convenience wrapper over prepare_vault + run_prepared. A note whose vote fails yields an
    ``error`` row and the scan continues; if more than ERROR_STOP_RATIO of the first
    ERROR_STOP_WINDOW sent notes fail, ScanAborted is raised carrying the rows so far.
    """
    model_requested = "fixture" if offline else (model or "jev-latest")
    root, plan, items, fingerprint = prepare_vault(
        vault, taxonomy_path=taxonomy_path, include_sensitive=include_sensitive, sensitive_parts=sensitive_parts,
        denylist=denylist, model_requested=model_requested, cache=cache, excerpt_chars=excerpt_chars,
        local_triage=local_triage,
    )
    taxonomy = load_taxonomy(taxonomy_path)
    questions = {} if offline else build_questions(taxonomy)
    engine: JanitorClient = client or (FixtureClient() if offline else TypeSafeJanitorClient(model=model))
    return run_prepared(root, plan, items, engine=engine, questions=questions, fingerprint=fingerprint, apply=apply,
                        on_row=on_row, workers=workers, trust_cache_across_models=trust_cache_across_models)
