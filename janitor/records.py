"""Records in, rows out: judge records that are not files in a vault.

A caller hands over a JSONL file of records and a question set (the ``questions:`` layout of
``janitor/schema.py``, any Choice, Scores and Nouls) and gets one row per record. No vault
walk, no file read beyond the JSONL, no write to the source; results go to a sidecar or
stdout. Reused unchanged: the redactor and denylist, ``HIGH_PRECISION_SECRETS``, the journal
and cache keyed on exactly what is sent, the concurrency and error-rate stop, the bill and
its ceiling, the review floor, STATE_VERSION and the digest.

What leaves the machine for a record is ``build_record_state``: the redacted, capped values
under the record's ``sent`` and their field names. The ``id`` is the row's address, raw on the
row and in the journal like the vault path, and is NOT sent: an address is not evidence.
A record whose ``sent`` carries a high-precision credential hit is never sent at all.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

from janitor import __version__
from janitor.bill import Bill, DEFAULT_MAX_USD, taxonomy_chars, usd
from janitor.frontmatter import HARD_EXCERPT_CAP, MAX_EXCERPT
from janitor.journal import (
    STATE_VERSION,
    Journal,
    cache_dir,
    cache_key,
    canonical,
    denylist_digest,
    new_run_id,
    now,
    read_journal,
)
from janitor.policy import HIGH_PRECISION_SECRETS, bucket_margin
from janitor.redact import redact
from janitor.scan import ERROR_STOP_RATIO, ERROR_STOP_WINDOW, NotSent, ScanAborted, meter_check
from janitor.schema import build_questions, load_question_set, question_payloads, review_choice, taxonomy_fingerprint

FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")  # a field name is caller text and is sent; only identifiers pass


def field_name_problem(name: Any) -> str | None:
    """Why a field name is refused, as a fixed phrase, or None. Never quotes the name: it is sent text.

    The identifier shape alone let a token through on the first outside run: `ghp_` plus 36
    alphanumerics IS an identifier, and so are the Stripe, npm, Hugging Face and fine-grained
    GitHub shapes, whose bodies use underscores. So every name also goes through the redactor,
    and any hit at all refuses the file.
    """
    if not isinstance(name, str) or not FIELD_NAME.match(name):
        return "has a name that is not an identifier (letters, digits, underscore, 64 max); field names are sent"
    if redact(name).hits:
        return "has a name the redactor would redact; field names are sent"
    return None


OUT_OF_CREDITS = "stopping: the TypeSafe account has no API credits (HTTP 402). Add credits and run again."


def out_of_credits(exc: BaseException) -> bool:
    """A 402 from the API is the account, not the run: retrying cannot help until credits are added."""
    for attr in ("status_code", "status", "code"):
        if getattr(exc, attr, None) == 402:
            return True
    text = str(exc)
    return "402" in text or ("no available" in text.lower() and "credits" in text.lower())
REVIEW_CONFIDENCE = 0.55
SECRET_THRESHOLD = 0.7


# --- records --------------------------------------------------------------------------------

@dataclass
class Record:
    id: str
    sent: dict[str, Any]
    line: int


def load_records(path: Path) -> list[Record]:
    """Read a JSONL file of records. Refuses the whole file on the first malformed line.

    Every refusal names the line number and a fixed phrase, never the caller's text: a bad
    field name may itself be the thing that must not leave, and this message goes wherever
    the operator pastes it. Only ``id`` and ``sent`` are read from a line.
    """
    records: list[Record] = []
    seen: dict[str, int] = {}
    with path.open(encoding="utf-8") as fh:
        for n, raw in enumerate(fh, start=1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {n}: not valid JSON") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"line {n}: a record is a JSON object")
            rid = obj.get("id")
            if not isinstance(rid, str) or not rid.strip():
                raise ValueError(f"line {n}: 'id' must be a non-empty string")
            if rid in seen:
                raise ValueError(f"line {n}: duplicate id, first seen on line {seen[rid]}")
            sent = obj.get("sent")
            if not isinstance(sent, dict) or not sent:
                raise ValueError(f"line {n}: 'sent' must be a non-empty object; it is the only thing that leaves")
            for i, (name, value) in enumerate(sent.items(), start=1):
                problem = field_name_problem(name)
                if problem:
                    raise ValueError(f"line {n}: field {i} {problem}")
                if isinstance(value, list):
                    if not all(isinstance(v, str) for v in value):
                        raise ValueError(f"line {n}: field {i} is a list with a non-string element; only lists of strings are sent")
                elif value is not None and not isinstance(value, (str, int, float, bool)):
                    raise ValueError(f"line {n}: field {i} is a nested object; values must be strings, numbers, booleans or lists of strings")
            seen[rid] = n
            records.append(Record(id=rid, sent=sent, line=n))
    if not records:
        raise ValueError("no records: the file is empty")
    return records


def _cap(text: str, excerpt_chars: int) -> str:
    return text[: (HARD_EXCERPT_CAP if excerpt_chars <= 0 else min(excerpt_chars, HARD_EXCERPT_CAP))]


def build_record_state(sent: dict[str, Any], denylist: list[str] | None, excerpt_chars: int = MAX_EXCERPT) -> tuple[dict[str, Any], list[str]]:
    """The state that leaves the machine for one record, and the redaction labels hit.

    Every string is redacted with the denylist, THEN cut to the cap, so a secret straddling
    the cap cannot leave as a fragment. Every number is redacted in its string form: a
    Luhn-valid 16-digit integer or a phone-shaped one is a CARD or a PHONE whatever the JSON
    type, so if redaction changed it the redacted string is sent, otherwise the number.
    Lists are redacted element by element. Booleans and nulls pass. The ``id`` is not here.

    Known limit, the same as the vault scan's: a secret split across two elements or two
    fields is two fragments to a regex and is not caught.
    """
    hits: list[str] = []
    fields: dict[str, Any] = {}

    def one(value: Any) -> Any:
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, (int, float)):
            r = redact(str(value), denylist=denylist)
            if r.hits:
                hits.extend(r.hits)
                return r.text
            return value
        r = redact(str(value), denylist=denylist)
        hits.extend(r.hits)
        return _cap(r.text, excerpt_chars)

    for name, value in sent.items():
        fields[name] = [one(v) for v in value] if isinstance(value, list) else one(value)
    state = {"fields": fields, "field_names": sorted(fields)}
    return state, sorted(set(hits))


# --- votes ----------------------------------------------------------------------------------

@dataclass
class RecordVote:
    choices: dict[str, dict[str, Any]]  # name -> pick, confidence, probabilities, margin
    scores: dict[str, dict[str, float]]  # name -> value, confidence
    nouls: dict[str, float]
    model: str
    input_tokens: int = 0


def vote_from_response(response: Any, payloads: dict[str, dict[str, Any]]) -> RecordVote:
    """Map a SystemOneResponse onto a RecordVote for any question set. Missing or mistyped answers raise."""
    answers = response.answers
    missing = [name for name in payloads if name not in answers]
    if missing:
        raise ValueError(f"Jev response is missing answers for: {', '.join(missing)}")
    choices: dict[str, dict[str, Any]] = {}
    scores: dict[str, dict[str, float]] = {}
    nouls: dict[str, float] = {}
    for name, payload in payloads.items():
        a = answers[name]
        got = getattr(a, "type", None)
        if got != payload["type"]:
            raise ValueError(f"Jev answer {name!r} has type {got!r}, expected {payload['type']!r}")
        if payload["type"] == "choice":
            probs = {str(k): round(float(v), 3) for k, v in sorted(a.probabilities.items(), key=lambda kv: -float(kv[1]))}
            choices[name] = {"pick": str(a.choice), "confidence": round(float(a.confidence), 3), "probabilities": probs, "margin": bucket_margin(probs)}
        elif payload["type"] == "score":
            scores[name] = {"value": round(float(a.score), 3), "confidence": round(float(a.confidence), 3)}
        else:
            nouls[name] = round(float(a.noul), 3)
    usage = getattr(response, "usage", None)
    return RecordVote(choices=choices, scores=scores, nouls=nouls,
                      model=str(getattr(response, "model", "") or "jev-latest"),
                      input_tokens=int(getattr(usage, "input_tokens", 0) or 0))


class RecordClient(Protocol):
    def judge(self, state: dict[str, Any], questions: dict, payloads: dict[str, dict[str, Any]]) -> RecordVote: ...


class TypeSafeRecordClient:
    def __init__(self, model: str | None = None) -> None:
        from typesafe_sdk import TypeSafeClient

        kwargs = {}
        if model:
            kwargs["model"] = model
        self._client = TypeSafeClient(**kwargs)

    def judge(self, state: dict[str, Any], questions: dict, payloads: dict[str, dict[str, Any]]) -> RecordVote:
        return vote_from_response(self._client.system_one(state=state, questions=questions), payloads)


class FixtureRecordClient:
    """Deterministic plumbing stand-in for --offline: first option, middle level, constant nouls. Not a classifier."""

    def judge(self, state: dict[str, Any], questions: dict, payloads: dict[str, dict[str, Any]]) -> RecordVote:
        choices, scores, nouls = {}, {}, {}
        for name, p in payloads.items():
            if p["type"] == "choice":
                first = next(iter(p["criteria"]))
                choices[name] = {"pick": first, "confidence": 0.8, "probabilities": {first: 0.8}, "margin": 0.8}
            elif p["type"] == "score":
                scores[name] = {"value": round((len(p["criteria"]) - 1) / 2, 3), "confidence": 0.75}
            else:
                nouls[name] = 0.05
        return RecordVote(choices=choices, scores=scores, nouls=nouls, model="fixture", input_tokens=0)


# --- decisions and rows ---------------------------------------------------------------------

@dataclass
class PreparedRecord:
    record: Record
    state: dict[str, Any]
    hits: list[str]
    key: str
    held: list[str] = field(default_factory=list)  # high-precision labels: never sent
    cached_row: dict[str, Any] | None = None


def _decide(vote: RecordVote, review: str | None) -> tuple[str, str, bool, str | None, list[str]]:
    """(action, reason, review, suggested, triggers). Quarantine on a record row means held back, never a file move."""
    if vote.nouls.get("contains_secret", 0.0) >= SECRET_THRESHOLD:
        return "quarantine", "contains_secret above threshold", False, None, ["contains_secret"]
    if review and review in vote.choices and vote.choices[review]["confidence"] < REVIEW_CONFIDENCE:
        return "label", "low confidence: routed to a person", True, vote.choices[review]["pick"], []
    return "label", "normal vote", False, None, []


def _row(item: PreparedRecord, vote: RecordVote | None, *, fingerprint: str, review: str | None, started: float, payload: bool) -> dict[str, Any]:
    if vote is None:  # held back by a local hit: nothing was sent
        action, reason, is_review, suggested, triggers = "quarantine", f"local redaction hit: {', '.join(item.held)}", False, None, [f"local:{h}" for h in item.held]
        choices, scores, nouls, model, tokens = {}, {}, {}, "local", 0
    else:
        action, reason, is_review, suggested, triggers = _decide(vote, review)
        choices, scores, nouls, model, tokens = vote.choices, vote.scores, vote.nouls, vote.model, vote.input_tokens
    lead = choices.get(review or "", {}) if review else {}
    row = {
        "kind": "vote",
        "judge": "local" if vote is None else "jev",
        "id": item.record.id,
        "review_choice": review,
        "pick": lead.get("pick"),
        "confidence": lead.get("confidence"),
        "choices": choices,
        "scores": scores,
        "nouls": nouls,
        "action": action,
        "reason": reason,
        "review": is_review,
        "suggested": suggested,
        "redacted": item.hits,
        "quarantine_triggers": triggers,
        "model": model,
        "input_tokens": tokens,
        "payload_chars": len(canonical(item.state)),
        "taxonomy": fingerprint,
        "key": item.key,
        "cached": False,
        "same_as": None,  # set when served from an identical record judged earlier this run
        "at": now(),
        "ms": round((time.perf_counter() - started) * 1000),
    }
    if payload:
        row["sent"] = item.state  # the exact object that left (or would have); never journaled
    return row


def _error_row(rid: str, exc: BaseException) -> dict[str, Any]:
    return {"kind": "error", "id": rid, "at": now(), "attempt": 1, "action": "error",
            "error": type(exc).__name__, "detail": redact(str(exc)).text[:500]}


def records_id(path: Path) -> str:
    """Journal directory key for a records file: a hash of its absolute path, never the path."""
    return hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()[:16]


def journal_dir_for_records(path: Path, where: str | None) -> Path | None:
    if where in (None, "", "default"):
        return cache_dir() / "records" / records_id(path)
    if where == "off":
        return None
    return Path(where)


def load_cache(directory: Path | None, model_requested: str) -> dict[str, dict[str, Any]]:
    """Fresh vote rows from the newest journal in the directory, by key. Same model only."""
    if directory is None or not directory.exists():
        return {}
    journals = sorted(directory.glob("run-*.jsonl"), key=lambda p: (p.stat().st_mtime_ns, p.name))
    if not journals:
        return {}
    header, rows, _ = read_journal(journals[-1])
    if (header or {}).get("model_requested") != model_requested:
        return {}
    return {r["key"]: r for r in rows if r.get("kind") == "vote" and r.get("judge") == "jev" and r.get("key") and not r.get("cached")}


def prepare_records(records: Iterable[Record], *, fingerprint: str, model_requested: str, denylist: list[str] | None,
                    excerpt_chars: int, cache: dict[str, dict[str, Any]] | None = None) -> list[PreparedRecord]:
    """Redact, hash, and decide locally what is never sent. No request here."""
    out: list[PreparedRecord] = []
    for rec in records:
        state, hits = build_record_state(rec.sent, denylist, excerpt_chars)
        key = cache_key(state, fingerprint, model_requested)
        held = [h for h in hits if h in HIGH_PRECISION_SECRETS]
        cached = (cache or {}).get(key) if not held else None
        out.append(PreparedRecord(record=rec, state=state, hits=hits, key=key, held=held, cached_row=cached))
    return out


def records_bill(items: list[PreparedRecord], *, question_chars: int, max_usd: float | None) -> Bill:
    bill = Bill(question_chars=question_chars, max_usd=max_usd)
    seen: set[str] = set()
    for it in items:
        if it.held:
            bill.local += 1
        elif it.cached_row is not None or it.key in seen:
            bill.cached += 1
        else:
            seen.add(it.key)
            bill.to_send += 1
            bill.payload_chars += len(canonical(it.state))
    return bill


def render_records_preflight(items: list[PreparedRecord], bill: Bill, *, live: bool, fingerprint: str, review: str | None, excerpt_chars: int) -> str:
    verb = "will be sent to TypeSafe" if live else "would be sent to TypeSafe by a live run; this run is offline and nothing leaves the machine"
    lines = [
        f"jev-records pre-flight: {bill.to_send:,} of {len(items):,} records {verb}",
        f"  question set {fingerprint}; review floor {REVIEW_CONFIDENCE} on choice {review!r}; each string cut at {excerpt_chars:,} chars after redaction",
        f"  {bill.cached:,} served from the journal or identical to a record already sent this run, {bill.local:,} held back by a local credential hit (never sent)",
        f"  bill (estimate): payload {bill.payload_chars:,} chars + questions -> ~{bill.tokens_low:,} to {bill.tokens_high:,} input tokens, ~{usd(bill.usd_low)} to {usd(bill.usd_high)}",
    ]
    if bill.max_usd is not None:
        lines.append(f"  ceiling {usd(bill.max_usd)}: {'OVER' if bill.over_budget else 'under'} at the pessimistic end")
    return "\n".join(lines)


def run_records(items: list[PreparedRecord], *, engine: RecordClient, questions: dict, payloads: dict[str, dict[str, Any]],
                fingerprint: str, review: str | None, on_row: Callable[[dict[str, Any]], None] | None = None,
                workers: int = 1, payload: bool = False, spend_limit: float | None = None, question_chars: int = 0) -> list[dict[str, Any]]:
    """Judge (or serve), decide, emit. One writer. Identical `sent` is judged once per run.

    ``spend_limit`` meters the run on the API's own token counts (see scan.meter_check)."""
    rows: list[dict[str, Any]] = []
    state = {"sent": 0, "errors": 0, "tokens": 0, "chars": 0, "metered": 0, "stop": False, "in_writer": False, "writer_failed": False}
    judged: dict[str, dict[str, Any]] = {}  # key -> first row this run

    def emit(row: dict[str, Any]) -> None:
        rows.append(row)
        if on_row is not None:
            on_row(row)

    def serve(item: PreparedRecord, source: dict[str, Any], same_as: str | None) -> None:
        row = {k: v for k, v in source.items() if k != "sent"}
        row.update({"id": item.record.id, "cached": True, "same_as": same_as, "at": now(), "ms": 0})
        if payload:
            row["sent"] = item.state
        emit(row)

    def work(item: PreparedRecord) -> tuple[PreparedRecord, RecordVote | None, BaseException | None, float]:
        started = time.perf_counter()
        if state["stop"]:
            return item, None, NotSent(), started  # a stop landed before this request reached the API
        try:
            return item, engine.judge(item.state, questions, payloads), None, started
        except Exception as exc:  # noqa: BLE001
            return item, None, exc, started

    def finish(item: PreparedRecord, vote: RecordVote | None, exc: BaseException | None, started: float) -> None:
        if isinstance(exc, NotSent):
            state["sent"] -= 1  # cancelled before the API saw it: no row, nothing billed
            return
        if exc is not None:
            state["errors"] += 1
            emit(_error_row(item.record.id, exc))
            if state["stop"]:
                return  # draining after a stop: record, never raise a second time
            if out_of_credits(exc):
                state["stop"] = True
                raise ScanAborted(OUT_OF_CREDITS, rows, reason="402")
            if state["sent"] >= ERROR_STOP_WINDOW and state["errors"] / state["sent"] > ERROR_STOP_RATIO:
                state["stop"] = True
                raise ScanAborted(f"stopping: {state['errors']} of the first {state['sent']} sent records failed; that is the run, not the records.", rows, reason="error-rate")
            return
        row = _row(item, vote, fingerprint=fingerprint, review=review, started=started, payload=payload)
        judged.setdefault(item.key, row)
        emit(row)
        if vote is not None and vote.input_tokens:
            state["tokens"] += vote.input_tokens
            state["chars"] += len(canonical(item.state)) + question_chars  # the basis the range is defined on
            state["metered"] += 1
            meter_check(state, spend_limit, rows, "records")

    todo: list[PreparedRecord] = []
    for item in items:
        if item.held:
            emit(_row(item, None, fingerprint=fingerprint, review=review, started=time.perf_counter(), payload=payload))
        elif item.cached_row is not None:
            serve(item, item.cached_row, None)
        else:
            todo.append(item)

    if workers <= 1:
        try:
            for item in todo:
                if item.key in judged:
                    serve(item, judged[item.key], judged[item.key]["id"])
                    continue
                state["sent"] += 1
                finish(*work(item))
        except ScanAborted as exc:
            exc.in_flight = 0
            raise
        return rows

    # workers > 1. A record identical to one already in flight waits for that result rather
    # than being sent again: `waiting` holds it by key until the first one finishes. Results
    # are finished here, in this thread, as they complete: one writer.
    pending: dict = {}  # future -> key
    waiting: dict[str, list[PreparedRecord]] = {}

    def settle(f) -> None:
        key = pending.pop(f)
        state["in_writer"] = True  # see scan.run_prepared: a Ctrl-C in the writer cancels without draining
        try:
            finish(*f.result())
        except BaseException:
            state["writer_failed"] = True
            state["stop"] = True
            raise
        finally:
            state["in_writer"] = False
        twins = waiting.pop(key, [])
        if not twins:
            return
        if key in judged:
            for twin in twins:
                serve(twin, judged[key], judged[key]["id"])
            return
        if state["stop"]:
            return  # nothing new after a stop; the twins are unsent and --resume sends them
        # The one in flight errored. Resubmit ONE twin and keep the rest waiting behind it;
        # the first outside run resubmitted all of them (three calls for one key). If this
        # one fails too, the next waits behind it in turn: every real call is counted once
        # and nothing is dropped or sent twice.
        first, rest = twins[0], twins[1:]
        if rest:
            waiting[key] = rest
        state["sent"] += 1
        pending[pool.submit(work, first)] = key

    def settle_done() -> None:
        done, _ = wait(list(pending), return_when=FIRST_COMPLETED)
        for f in done:
            if f in pending:
                settle(f)

    # The window is bounded by waiting, not polling, and a stop cancels the queue, lets the
    # at most `workers` in flight finish and records them, then re-raises (see scan.run_prepared).
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        for item in todo:
            if item.key in judged:
                serve(item, judged[item.key], judged[item.key]["id"])
                continue
            if item.key in pending.values():
                waiting.setdefault(item.key, []).append(item)
                continue
            state["sent"] += 1
            pending[pool.submit(work, item)] = item.key
            while len(pending) >= workers * 4:  # bounded in-flight window
                settle_done()
        while pending:
            settle_done()
    except (ScanAborted, KeyboardInterrupt) as exc:
        # A stop or Ctrl-C drains: cancel the queue, record what was in flight, re-raise (see scan.run_prepared).
        state["stop"] = True
        for f in pending:
            f.cancel()
        if isinstance(exc, KeyboardInterrupt) and state["writer_failed"]:
            raise
        in_flight = 0
        for f in wait(list(pending)).done:
            if f.cancelled():
                pending.pop(f, None)
                state["sent"] -= 1
                continue
            in_flight += 0 if isinstance(f.result()[2], NotSent) else 1
            settle(f)
        if isinstance(exc, ScanAborted):
            exc.in_flight = in_flight
        raise
    except BaseException:
        state["stop"] = True  # a writer failure: nothing queued goes out; no drain, the writer is broken
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    return rows


def render_table(rows: list[dict[str, Any]]) -> str:
    """id, pick, confidence, action, reason: labels and numbers only, never a value from `sent`."""
    lines = [f"  {'id':<32} {'pick':<20} {'conf':>5}  action       reason"]
    for r in rows:
        if r.get("kind") == "error":
            lines.append(f"  {r['id'][:32]:<32} {'':<20} {'':>5}  error        {r.get('error')}")
            continue
        conf = "" if r.get("confidence") is None else f"{r['confidence']:.2f}"
        lines.append(f"  {r['id'][:32]:<32} {str(r.get('pick') or ''):<20} {conf:>5}  {r.get('action', ''):<12} {r.get('reason', '')}")
    return "\n".join(lines)


# --- the library entry point ----------------------------------------------------------------

def judge_records(
    records: Iterable[dict[str, Any]] | Path,
    questions_path: Path,
    *,
    offline: bool = False,
    client: RecordClient | None = None,
    denylist: list[str] | None = None,
    model: str = "jev-latest",
    excerpt_chars: int = MAX_EXCERPT,
    max_usd: float | None = DEFAULT_MAX_USD,
    over_budget: bool = False,
    workers: int = 8,
    journal_dir: Path | None = None,
    use_cache: bool = True,
    review: str | None = None,
    on_row: Callable[[dict[str, Any]], None] | None = None,
    payload: bool = False,
) -> list[dict[str, Any]]:
    """Records in (a JSONL path or an iterable of ``{"id", "sent"}`` dicts), rows out. Nothing is written to the source.

    Live mode reads ``TYPESAFE_API_KEY`` from the environment, as the vault scan does, and
    refuses before any request when the pessimistic bill is over ``max_usd`` unless
    ``over_budget``. ``journal_dir=None`` writes no journal and serves no cache; pass a
    directory to get both. For a double run (stability scoring) use a fresh directory per
    run or ``journal_dir=None``, since the cache would otherwise serve the second run from
    the first.
    """
    if isinstance(records, Path):
        recs = load_records(records)
    else:
        recs = [Record(id=str(r["id"]), sent=dict(r["sent"]), line=i + 1) for i, r in enumerate(records)]
        # the same shape checks as the file path, through a temp-free round trip
        _check_records(recs)
    qset = load_question_set(questions_path)
    payloads = question_payloads(qset)
    fingerprint = taxonomy_fingerprint(questions_path)
    rev = review or review_choice(qset)
    if rev is not None and qset["questions"].get(rev, {}).get("type") != "choice":
        raise ValueError(f"review choice {rev!r} is not a choice in this question set")
    model_requested = "fixture" if offline else model
    cache = load_cache(journal_dir, model_requested) if use_cache else {}
    items = prepare_records(recs, fingerprint=fingerprint, model_requested=model_requested, denylist=denylist, excerpt_chars=excerpt_chars, cache=cache)
    bill = records_bill(items, question_chars=taxonomy_chars(qset), max_usd=max_usd)
    if not offline and bill.over_budget and not over_budget:
        raise ScanAborted(f"REFUSED: the pessimistic estimate of {usd(bill.usd_high)} is over the ceiling of {usd(bill.max_usd)}. Nothing was sent.", [])
    engine: RecordClient = client if client is not None else (FixtureRecordClient() if offline else TypeSafeRecordClient(model))
    # SDK question objects only for the SDK client. An injected client gets the plain payloads
    # (its third argument) and no SDK import, so a library caller or a test needs no SDK
    # installed; the first fresh-clone run without the SDK caught this building them anyway.
    questions = build_questions(qset) if (client is None and not offline and bill.to_send) else {}
    journal: Journal | None = None
    if journal_dir is not None:
        header = {"run": new_run_id(), "started": now(), "janitor": __version__, "state_version": STATE_VERSION,
                  "taxonomy": fingerprint, "model_requested": model_requested, "review_choice": rev,
                  "excerpt_cap": excerpt_chars, "denylist": denylist_digest(denylist), "question_chars": bill.question_chars,
                  "records": len(recs)}
        journal = Journal(Journal.new_path(journal_dir, header["run"]), header)

    counts = {"errors": 0}

    def sink(row: dict[str, Any]) -> None:
        if row.get("kind") == "error":
            counts["errors"] += 1
        if journal is not None:
            journal.append({k: v for k, v in row.items() if k != "sent"})  # the payload is never journaled
        if on_row is not None:
            on_row(row)

    rows: list[dict[str, Any]] = []  # bound before the try: an interrupt reaches the finally with no result
    aborted: ScanAborted | None = None
    completed = False  # set only when run_records returns
    failure: str | None = None
    spend_limit = None if offline or max_usd is None else (max(max_usd, bill.usd_high) if over_budget else max_usd)
    try:
        rows = run_records(items, engine=engine, questions=questions, payloads=payloads, fingerprint=fingerprint, review=rev,
                           on_row=sink, workers=workers, payload=payload, spend_limit=spend_limit, question_chars=bill.question_chars)
        completed = True
    except ScanAborted as exc:
        aborted = exc
        rows = exc.rows
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        failure = type(exc).__name__
        raise
    finally:
        if journal is not None:
            # A run that neither returned nor stopped (Ctrl-C, a writer failure, a full disk, a
            # bug) is closed as interrupted with its real row count and the reason in the footer.
            # jev-records has no --resume and load_cache reads rows, not footers; the footer is
            # the record. Through 0.4.5 `rows` was unbound here on an interrupt, so an
            # UnboundLocalError replaced it and no footer was written at all.
            unfinished = not completed and aborted is None
            reason = aborted.reason if aborted is not None else (f"failed:{failure}" if failure else ("interrupted" if unfinished else None))
            journal.close({"rows": journal.rows if unfinished else len(rows), "errors": counts["errors"],
                           "aborted": aborted is not None, "interrupted": unfinished, "reason": reason})
    if aborted is not None:
        raise aborted
    return rows


def _check_records(recs: list[Record]) -> None:
    seen: set[str] = set()
    for r in recs:
        if not r.id.strip():
            raise ValueError(f"record {r.line}: 'id' must be a non-empty string")
        if r.id in seen:
            raise ValueError(f"record {r.line}: duplicate id")
        seen.add(r.id)
        if not r.sent:
            raise ValueError(f"record {r.line}: 'sent' must be a non-empty object")
        for i, (name, value) in enumerate(r.sent.items(), start=1):
            problem = field_name_problem(name)
            if problem:
                raise ValueError(f"record {r.line}: field {i} {problem}")
            if isinstance(value, list):
                if not all(isinstance(v, str) for v in value):
                    raise ValueError(f"record {r.line}: field {i} is a list with a non-string element")
            elif value is not None and not isinstance(value, (str, int, float, bool)):
                raise ValueError(f"record {r.line}: field {i} is a nested object")


def print_stderr(text: str) -> None:
    print(text, file=sys.stderr)
