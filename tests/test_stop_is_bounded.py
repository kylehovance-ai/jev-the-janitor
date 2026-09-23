"""A stop stops. Nothing new is sent, the in-flight requests are recorded, no file is written
for a note without a row.

Through 0.4.5 the pool loop only collected futures that happened to be done and never waited,
so with workers > 1 nearly the whole run sat in the executor's queue; when the meter, the 402
stop or the error-rate stop raised inside the ``with ThreadPoolExecutor`` block, its exit ran
every queued request, billed it and threw the row away, and with --apply stamped files that had
no journal row. Every claim that a stop stops was false in practice. Found by an outside review
of 0.4.6.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from janitor import cli
from janitor.bill import PRICE_PER_MILLION_USD
from janitor.client import FixtureClient, Vote
from janitor.records import FixtureRecordClient, judge_records
from janitor.records_cli import main as records_main
from janitor.scan import ERROR_STOP_WINDOW, ScanAborted, prepare_vault, run_prepared

QUESTIONS = Path(__file__).resolve().parent.parent / "examples" / "triage.yaml"
TOKENS = 100_000  # per note: $0.0042 at the published price
WORKERS = 4


def _vault(tmp_path: Path, n: int) -> Path:
    for i in range(n):
        (tmp_path / f"n{i:03d}.md").write_text(f"# Note {i}\n\nbody of note {i}, a standing fact.\n", encoding="utf-8")
    return tmp_path


class Counting(FixtureClient):
    """Counts every request the API would see; sleeps so requests really overlap."""

    def __init__(self, tokens: int = TOKENS, sleep: float = 0.01) -> None:
        self.calls = 0
        self.lock = threading.Lock()
        self.tokens = tokens
        self.sleep = sleep

    def vote(self, state, questions):
        with self.lock:
            self.calls += 1
        time.sleep(self.sleep)
        return Vote(**{**super().vote(state, questions).__dict__, "input_tokens": self.tokens})


class Failing(Counting):
    def vote(self, state, questions):
        with self.lock:
            self.calls += 1
        time.sleep(self.sleep)
        raise ValueError("persist: nonsense")


class Broke(Exception):
    status_code = 402


class OutOfCredits(Counting):
    def vote(self, state, questions):
        with self.lock:
            self.calls += 1
        time.sleep(self.sleep)
        raise Broke("HTTP 402")


def _sent_rows(rows):
    return [r for r in rows if r["kind"] == "vote" and r["judge"] == "jev" and not r.get("cached")]


def test_meter_stop_under_workers_sends_nothing_new_and_records_the_in_flight(tmp_path: Path):
    root, plan, items, fp = prepare_vault(_vault(tmp_path, 100))
    engine = Counting()
    limit = 10 * TOKENS / 1_000_000 * PRICE_PER_MILLION_USD  # trips on the eleventh metered row
    with pytest.raises(ScanAborted, match="measured spend") as exc:
        run_prepared(root, plan, items, engine=engine, questions={}, fingerprint=fp, workers=WORKERS, spend_limit=limit)
    rows = exc.value.rows
    n = exc.value.in_flight
    # The eleventh metered row tripped it. What had already left for the API when it did (a
    # worker that just finished usually has the next request out) completed and is recorded;
    # the abort states that number exactly. Nothing queued behind them went out.
    assert engine.calls == 11 + n and n <= WORKERS * 4, (engine.calls, n)
    assert len(_sent_rows(rows)) == engine.calls  # every request the API saw has a row: nothing sent is lost
    assert f"Nothing new was sent after the stop; {n} requests already in flight completed and were recorded" in str(exc.value)
    assert "Nothing more is sent" not in str(exc.value)


def test_meter_stop_under_apply_writes_no_file_without_a_row(tmp_path: Path):
    vault = _vault(tmp_path, 100)
    root, plan, items, fp = prepare_vault(vault)
    engine = Counting()
    limit = 5 * TOKENS / 1_000_000 * PRICE_PER_MILLION_USD
    with pytest.raises(ScanAborted) as exc:
        run_prepared(root, plan, items, engine=engine, questions={}, fingerprint=fp, workers=WORKERS, spend_limit=limit, apply=True)
    stamped = {p.name for p in vault.glob("*.md") if "janitor:" in p.read_text(encoding="utf-8")}
    with_row = {r["path"] for r in exc.value.rows if r.get("applied")}
    assert stamped == with_row  # every changed file has a row that says so
    assert engine.calls == 6 + exc.value.in_flight and len(stamped) <= engine.calls  # in-flight completions after the stop write nothing
    assert len(stamped) <= 6 + WORKERS * 4  # the other ~90 notes are untouched, not stamped from a row-less request


def test_error_rate_stop_under_workers_is_bounded(tmp_path: Path):
    root, plan, items, fp = prepare_vault(_vault(tmp_path, 100))
    engine = Failing()
    with pytest.raises(ScanAborted, match="that is the run, not the notes") as exc:
        run_prepared(root, plan, items, engine=engine, questions={}, fingerprint=fp, workers=WORKERS)
    errors = [r for r in exc.value.rows if r["kind"] == "error"]
    assert engine.calls <= ERROR_STOP_WINDOW + WORKERS * 4
    assert len(errors) == engine.calls  # every failed request is on a row
    assert f"Nothing new was sent after the stop; {exc.value.in_flight} request" in str(exc.value)


def test_402_stop_under_workers_is_bounded_on_the_vault_path(tmp_path: Path):
    root, plan, items, fp = prepare_vault(_vault(tmp_path, 60))
    engine = OutOfCredits()
    with pytest.raises(ScanAborted, match="no API credits") as exc:
        run_prepared(root, plan, items, engine=engine, questions={}, fingerprint=fp, workers=WORKERS)
    assert engine.calls == 1 + exc.value.in_flight and exc.value.in_flight <= WORKERS * 4
    assert len([r for r in exc.value.rows if r["kind"] == "error"]) == engine.calls
    assert "Nothing new was sent after the stop" in str(exc.value) and "Nothing more will be sent" not in str(exc.value)


def test_402_stop_under_workers_is_bounded_on_the_records_path():
    class BrokeRecords(FixtureRecordClient):
        calls = 0
        lock = threading.Lock()

        def judge(self, state, questions, payloads):
            with BrokeRecords.lock:
                BrokeRecords.calls += 1
            time.sleep(0.01)
            raise Broke("HTTP 402")

    recs = [{"id": f"r{i}", "sent": {"what": f"w{i}"}} for i in range(60)]
    with pytest.raises(ScanAborted, match="no API credits") as exc:
        judge_records(recs, QUESTIONS, offline=False, client=BrokeRecords(), journal_dir=None, workers=WORKERS)
    assert BrokeRecords.calls == 1 + exc.value.in_flight and exc.value.in_flight <= WORKERS * 4
    assert len([r for r in exc.value.rows if r["kind"] == "error"]) == BrokeRecords.calls
    assert f"{exc.value.in_flight} request" in str(exc.value) and "already in flight completed" in str(exc.value)


def test_meter_stop_under_workers_is_bounded_on_the_records_path():
    class DenseRecords(FixtureRecordClient):
        calls = 0
        lock = threading.Lock()

        def judge(self, state, questions, payloads):
            with DenseRecords.lock:
                DenseRecords.calls += 1
            time.sleep(0.01)
            v = super().judge(state, questions, payloads)
            v.input_tokens = TOKENS
            return v

    recs = [{"id": f"r{i}", "sent": {"what": f"w{i}"}} for i in range(100)]
    limit = 10 * TOKENS / 1_000_000 * PRICE_PER_MILLION_USD
    with pytest.raises(ScanAborted, match="measured spend") as exc:
        judge_records(recs, QUESTIONS, offline=False, client=DenseRecords(), journal_dir=None, workers=WORKERS, max_usd=limit)
    judged = [r for r in exc.value.rows if r["kind"] == "vote" and not r.get("cached")]
    assert DenseRecords.calls == 11 + exc.value.in_flight and exc.value.in_flight <= WORKERS * 4
    assert len(judged) == DenseRecords.calls


# --- bug 1: a local decision is never served from the resume cache ---------------------------

def test_local_row_is_not_served_from_the_cache_after_the_twin_changes(tmp_path: Path, capsys):
    vault = tmp_path / "v"
    vault.mkdir()
    (vault / "a.md").write_text("# Same\n\nidentical body\n", encoding="utf-8")
    (vault / "b.md").write_text("# Same\n\nidentical body\n", encoding="utf-8")
    assert cli.main([str(vault), "--offline", "--json"]) == 0
    first = {r["path"]: r for r in json.loads(capsys.readouterr().out) if r["kind"] == "vote"}
    assert first["b.md"]["judge"] == "local" and "exact duplicate" in first["b.md"]["reason"]
    (vault / "a.md").write_text("# Same\n\nno longer identical\n", encoding="utf-8")
    assert cli.main([str(vault), "--offline", "--resume", "--json"]) == 0
    second = {r["path"]: r for r in json.loads(capsys.readouterr().out) if r["kind"] == "vote"}
    assert not second["b.md"].get("cached"), "a local row was served from the cache after its twin changed"
    assert second["b.md"]["judge"] == "jev"  # b is no longer a duplicate of anything: it is judged


# --- bug 3: the key check and the prompt are gated on what would be sent ----------------------

def test_live_run_that_is_all_local_decisions_needs_no_key_and_no_prompt(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr(cli, "TypeSafeJanitorClient", lambda *a, **k: pytest.fail("the SDK client was built for zero requests"))
    vault = tmp_path / "v"
    vault.mkdir()
    key = "sk-" + "abcdefghijklmnopqrstuvwxyz012345"  # assembled: a credential-shaped body is decided locally
    for i in range(3):
        (vault / f"n{i}.md").write_text(f"# Leak {i}\n\ntoken {key}{i}\n", encoding="utf-8")
    rc = cli.main([str(vault), "--journal", "off"])  # live, no --yes: a prompt would fail on a closed stdin
    err = capsys.readouterr().err
    assert rc == 0 and "nothing to send" in err and "TYPESAFE_API_KEY" not in err


# --- bug 4: jev-records builds the SDK client only when something is sent ----------------------

def test_records_cli_live_with_nothing_to_send_needs_no_sdk(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    import janitor.records_cli as rc_mod

    monkeypatch.setattr(rc_mod, "TypeSafeRecordClient", lambda *a, **k: pytest.fail("the SDK client was built for zero requests"))
    p = tmp_path / "r.jsonl"
    key = "sk-" + "abcdefghijklmnopqrstuvwxyz012345"
    p.write_text("".join(json.dumps({"id": f"r{i}", "sent": {"what": f"token {key}{i}"}}) + "\n" for i in range(3)), encoding="utf-8")
    assert records_main([str(p), "--questions", str(QUESTIONS), "--journal", "off"]) == 0  # live, held records only
    capsys.readouterr()


# --- bug 5: the cached count is a fact about the vault, not the survey sample ----------------

def test_cached_count_is_taken_before_the_survey_narrows(tmp_path: Path, capsys):
    vault = _vault(tmp_path / "v", 6) if (tmp_path / "v").mkdir() is None else None
    assert cli.main([str(vault), "--offline"]) == 0
    capsys.readouterr()
    assert cli.main([str(vault), "--offline", "--resume", "--survey", "2"]) == 0
    err = capsys.readouterr().err
    assert "6 already voted and unchanged: served from the journal" in err


def test_sequential_stop_states_zero_in_flight(tmp_path: Path):
    root, plan, items, fp = prepare_vault(_vault(tmp_path, 12))
    engine = Counting(sleep=0)
    limit = 3 * TOKENS / 1_000_000 * PRICE_PER_MILLION_USD
    with pytest.raises(ScanAborted) as exc:
        run_prepared(root, plan, items, engine=engine, questions={}, fingerprint=fp, workers=1, spend_limit=limit)
    assert exc.value.in_flight == 0 and engine.calls == 4 == len(_sent_rows(exc.value.rows))
    assert "0 requests already in flight completed and were recorded" in str(exc.value)


# --- an interrupt is a stop too ------------------------------------------------------------

def test_keyboard_interrupt_in_the_writer_sends_nothing_queued(tmp_path: Path):
    """Ctrl-C lands in the writer thread. Through the first cut of this fix the executor's exit
    still ran every queued request (one window, 4 x workers): billed, no row, stamped under
    --apply. The promise that a stop stops holds for an interrupt and for a writer failure."""
    vault = _vault(tmp_path, 100)
    root, plan, items, fp = prepare_vault(vault)
    engine = Counting()
    recorded: list[dict] = []

    class Interrupting(Counting):
        def vote(self, state, questions):
            with self.lock:
                self.calls += 1
                trigger = self.calls == 8  # decided under the lock: exactly one call raises
            time.sleep(self.sleep)
            if trigger:
                raise KeyboardInterrupt  # Ctrl-C lands while requests are in flight
            return Vote(**{**FixtureClient.vote(self, state, questions).__dict__, "input_tokens": self.tokens})
    engine = Interrupting()
    with pytest.raises(KeyboardInterrupt):
        run_prepared(root, plan, items, engine=engine, questions={}, fingerprint=fp, workers=WORKERS, on_row=recorded.append, apply=True)
    # Drained like a stop: what had already left for the API completed and was recorded, nothing
    # queued behind it ran, and no file was written for a note without a row.
    assert 8 <= engine.calls <= 8 + WORKERS * 4, engine.calls
    with_row = {r["path"] for r in recorded if r.get("applied")}
    assert len(with_row) <= engine.calls - 1  # a completion after the stop is recorded but writes nothing; the interrupted one has no row
    assert len([r for r in recorded if r["kind"] == "vote" and r["judge"] == "jev"]) == engine.calls - 1  # every completed request has a row
    stamped = {p.name for p in vault.glob("*.md") if "janitor:" in p.read_text(encoding="utf-8")}
    assert stamped == with_row
    engine.calls = 0
    time.sleep(0.1)
    assert engine.calls == 0  # nothing ran after the loop was left


def test_records_writer_failure_sends_nothing_queued():
    class SlowRecords(FixtureRecordClient):
        calls = 0
        lock = threading.Lock()

        def judge(self, state, questions, payloads):
            with SlowRecords.lock:
                SlowRecords.calls += 1
            time.sleep(0.01)
            return super().judge(state, questions, payloads)

    seen = 0

    def on_row(row):
        nonlocal seen
        seen += 1
        if seen == 5:
            raise RuntimeError("writer failed")
    recs = [{"id": f"r{i}", "sent": {"what": f"w{i}"}} for i in range(100)]
    with pytest.raises(RuntimeError, match="writer failed"):
        judge_records(recs, QUESTIONS, offline=False, client=SlowRecords(), journal_dir=None, workers=WORKERS, on_row=on_row)
    assert 5 <= SlowRecords.calls <= 5 + WORKERS * 4


# --- a live records run with nothing to send gets a client that refuses, never the fixture ----

def test_records_cli_live_with_nothing_to_send_uses_a_refusing_client(tmp_path: Path, capsys, monkeypatch):
    import janitor.records_cli as rc_mod

    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr(rc_mod, "TypeSafeRecordClient", lambda *a, **k: pytest.fail("the SDK client was built for zero requests"))
    calls = []
    real = rc_mod.RefusingRecordClient.judge
    monkeypatch.setattr(rc_mod.RefusingRecordClient, "judge", lambda self, *a: calls.append(1) or real(self, *a))
    p = tmp_path / "r.jsonl"
    key = "sk-" + "abcdefghijklmnopqrstuvwxyz012345"
    p.write_text("".join(json.dumps({"id": f"r{i}", "sent": {"what": f"token {key}{i}"}}) + "\n" for i in range(3)), encoding="utf-8")
    assert records_main([str(p), "--questions", str(QUESTIONS), "--journal", "off", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert calls == [] and len(rows) == 3 and all(r.get("judge") == "local" for r in rows)  # every record held locally, nothing judged
    with pytest.raises(RuntimeError, match="nothing should be sent"):
        rc_mod.RefusingRecordClient().judge({}, {}, {})


# --- an interrupted run is journaled as interrupted, and --resume prefers it ------------------

def _older_unfinished_journal(cache_dir: Path, vault: Path) -> Path:
    """A footer-less run from before: through 0.4.5 --resume picked THIS over an interrupted run."""
    from janitor.journal import vault_id
    d = cache_dir / "journals" / vault_id(vault)
    d.mkdir(parents=True, exist_ok=True)
    p = d / "run-20260101T000000-aaaaaaaa.jsonl"
    p.write_text(json.dumps({"kind": "run", "run": "aaaaaaaa", "started": "2026-01-01T00:00:00Z"}) + "\n"
                 + json.dumps({"kind": "vote", "judge": "jev", "path": "n000.md", "key": "stale", "bucket": "junk"}) + "\n", encoding="utf-8")
    import os
    os.utime(p, (1_700_000_000, 1_700_000_000))
    return p


def test_cli_interrupt_marks_the_journal_interrupted_and_resume_serves_its_rows(tmp_path: Path, capsys, monkeypatch):
    import os

    from janitor.journal import read_journal
    vault = _vault(tmp_path / "v", 20) if (tmp_path / "v").mkdir() is None else None
    cache = Path(os.environ["JEV_JANITOR_CACHE_DIR"])
    older = _older_unfinished_journal(cache, vault)

    class Interrupting(FixtureClient):
        calls = 0

        def vote(self, state, questions):
            Interrupting.calls += 1
            if Interrupting.calls == 6:
                raise KeyboardInterrupt
            return super().vote(state, questions)
    monkeypatch.setattr(cli, "FixtureClient", Interrupting)
    assert cli.main([str(vault), "--offline", "--workers", "1"]) == cli.EXIT_INTERRUPTED
    err = capsys.readouterr().err
    assert "interrupted" in err and "--resume continues from it" in err
    journals = sorted((cache / "journals").rglob("run-*.jsonl"), key=lambda p: p.stat().st_mtime_ns)
    newest = journals[-1]
    assert newest != older
    _, rows, _ = read_journal(newest)
    footer = rows[-1]
    assert footer["kind"] == "end" and footer["interrupted"] is True and footer["aborted"] is False
    assert footer["rows"] == 5 == sum(1 for r in rows if r["kind"] == "vote") and footer["exit"] == cli.EXIT_INTERRUPTED
    # --resume picks the interrupted run, not the older footer-less one, and serves its five rows
    monkeypatch.setattr(cli, "FixtureClient", FixtureClient)
    assert cli.main([str(vault), "--offline", "--resume", "--json"]) == 0
    out, err = capsys.readouterr()
    assert "(interrupted after 5 notes)" in err and "aaaaaaaa" not in err
    served = [r for r in json.loads(out) if r.get("cached")]
    assert len(served) == 5


def test_records_interrupt_with_a_journal_dir_writes_the_interrupted_footer(tmp_path: Path):
    """Through 0.4.5 `rows` was unbound in the finally, so an UnboundLocalError replaced the
    interrupt and no footer was written. The existing interrupt tests passed journal_dir=None."""
    from janitor.journal import read_journal

    class Interrupting(FixtureRecordClient):
        calls = 0

        def judge(self, state, questions, payloads):
            Interrupting.calls += 1
            if Interrupting.calls == 3:
                raise KeyboardInterrupt
            return super().judge(state, questions, payloads)
    recs = [{"id": f"r{i}", "sent": {"what": f"w{i}"}} for i in range(10)]
    with pytest.raises(KeyboardInterrupt):
        judge_records(recs, QUESTIONS, offline=True, client=Interrupting(), journal_dir=tmp_path, workers=1)
    journal = next(tmp_path.glob("run-*.jsonl"))
    _, rows, _ = read_journal(journal)
    footer = rows[-1]
    assert footer["kind"] == "end" and footer["interrupted"] is True and footer["rows"] == 2 == sum(1 for r in rows if r["kind"] == "vote")


def test_newest_journal_prefers_an_interrupted_or_aborted_footer_over_a_finished_run(tmp_path: Path):
    from janitor.resume import load_resume, newest_journal
    import os

    def write(name: str, footer: dict | None, mtime: int) -> Path:
        p = tmp_path / name
        lines = [json.dumps({"kind": "run", "run": name[-13:-6]}), json.dumps({"kind": "vote", "judge": "jev", "path": "a.md", "key": "k"})]
        if footer is not None:
            lines.append(json.dumps({"kind": "end", **footer}))
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.utime(p, (mtime, mtime))
        return p
    write("run-20260101T000000-aaaaaaa.jsonl", None, 1_700_000_000)  # older, footer-less
    interrupted = write("run-20260102T000000-bbbbbbb.jsonl", {"rows": 1, "interrupted": True, "aborted": False}, 1_700_000_100)
    write("run-20260103T000000-ccccccc.jsonl", {"rows": 1, "interrupted": False, "aborted": False}, 1_700_000_200)  # newest, finished
    assert newest_journal(tmp_path) == interrupted
    assert load_resume(interrupted, {}).completed is False
    aborted = write("run-20260104T000000-ddddddd.jsonl", {"rows": 1, "aborted": True}, 1_700_000_300)
    assert newest_journal(tmp_path) == aborted and load_resume(aborted, {}).completed is False


# --- any other failure leaves the journal unfinished, never a clean completed run ---------------

def test_cli_writer_failure_closes_the_journal_as_unfinished(tmp_path: Path, capsys, monkeypatch):
    """A writer failure (here: the journal itself raising OSError, as a full disk would) reached
    the finally with rows == [] and wrote rows 0, exit 0: a clean completed run, the same class as
    the interrupt footer bug."""
    import os

    from janitor.journal import Journal, read_journal
    from janitor.journal import vault_id
    from janitor.resume import newest_journal
    vault = _vault(tmp_path / "v", 20) if (tmp_path / "v").mkdir() is None else None
    cache = Path(os.environ["JEV_JANITOR_CACHE_DIR"])
    older = _older_unfinished_journal(cache, vault)
    real_append = Journal.append
    calls = {"n": 0}

    def failing_append(self, row):
        calls["n"] += 1
        if calls["n"] == 6:
            raise OSError(28, "No space left on device")
        real_append(self, row)
    monkeypatch.setattr(Journal, "append", failing_append)
    with pytest.raises(OSError):
        cli.main([str(vault), "--offline", "--workers", "1"])
    capsys.readouterr()
    d = cache / "journals" / vault_id(vault)
    newest = max(d.glob("run-*.jsonl"), key=lambda p: p.stat().st_mtime_ns)
    assert newest != older
    _, rows, _ = read_journal(newest)
    footer = rows[-1]
    assert footer["kind"] == "end" and footer["interrupted"] is True and footer["rows"] == 5 and footer["exit"] != 0
    assert newest_journal(d) == newest  # --resume prefers it over the older footer-less run


def test_records_writer_failure_closes_the_journal_as_unfinished(tmp_path: Path, monkeypatch):
    from janitor.journal import Journal, read_journal
    real_append = Journal.append
    calls = {"n": 0}

    def failing_append(self, row):
        calls["n"] += 1
        if calls["n"] == 4:
            raise OSError(28, "No space left on device")
        real_append(self, row)
    monkeypatch.setattr(Journal, "append", failing_append)
    recs = [{"id": f"r{i}", "sent": {"what": f"w{i}"}} for i in range(10)]
    with pytest.raises(OSError):
        judge_records(recs, QUESTIONS, offline=True, client=FixtureRecordClient(), journal_dir=tmp_path, workers=1)
    _, rows, _ = read_journal(next(tmp_path.glob("run-*.jsonl")))
    footer = rows[-1]
    assert footer["kind"] == "end" and footer["interrupted"] is True and footer["rows"] == 3 == sum(1 for r in rows if r["kind"] == "vote")


# --- a Ctrl-C inside the writer cancels without draining through it ------------------------------

def test_interrupt_inside_the_writer_does_not_drain_through_it(tmp_path: Path):
    root, plan, items, fp = prepare_vault(_vault(tmp_path, 100))
    engine = Counting()
    calls = {"on_row": 0}

    def on_row(row):
        calls["on_row"] += 1
        if calls["on_row"] == 8:
            raise KeyboardInterrupt  # Ctrl-C lands while the writer is running on the main thread
    with pytest.raises(KeyboardInterrupt):
        run_prepared(root, plan, items, engine=engine, questions={}, fingerprint=fp, workers=WORKERS, on_row=on_row)
    assert calls["on_row"] == 8  # the writer was not re-entered: no drain
    assert engine.calls <= 8 + WORKERS * 4  # nothing queued behind the window ran
    time.sleep(0.1)
    assert engine.calls <= 8 + WORKERS * 4


def test_records_interrupt_inside_the_writer_does_not_drain_through_it():
    class SlowRecords(FixtureRecordClient):
        calls = 0
        lock = threading.Lock()

        def judge(self, state, questions, payloads):
            with SlowRecords.lock:
                SlowRecords.calls += 1
            time.sleep(0.01)
            return super().judge(state, questions, payloads)
    calls = {"on_row": 0}

    def on_row(row):
        calls["on_row"] += 1
        if calls["on_row"] == 5:
            raise KeyboardInterrupt
    recs = [{"id": f"r{i}", "sent": {"what": f"w{i}"}} for i in range(100)]
    with pytest.raises(KeyboardInterrupt):
        judge_records(recs, QUESTIONS, offline=False, client=SlowRecords(), journal_dir=None, workers=WORKERS, on_row=on_row)
    assert calls["on_row"] == 5 and SlowRecords.calls <= 5 + WORKERS * 4


# --- which run --resume continues ------------------------------------------------------------------

def _journals(cache: Path, vault: Path) -> list[Path]:
    from janitor.journal import vault_id
    d = cache / "journals" / vault_id(vault)
    return sorted(d.glob("run-*.jsonl"), key=lambda p: (p.stat().st_mtime_ns, p.name))


def _run_id(p: Path) -> str:
    from janitor.journal import read_journal_ends
    return read_journal_ends(p)[0]["run"]


def _interrupting_after(n: int):
    class Interrupting(FixtureClient):
        calls = 0

        def vote(self, state, questions):
            Interrupting.calls += 1
            if Interrupting.calls == n + 1:
                raise KeyboardInterrupt
            return super().vote(state, questions)
    return Interrupting


def test_resume_picks_the_finished_resume_not_the_old_stop_it_continued(tmp_path: Path, capsys, monkeypatch):
    """A stopped, B resumed A and finished, C must continue B: through 0.4.6 A won for ever."""
    import os
    import time as _t
    vault = _vault(tmp_path / "v", 20) if (tmp_path / "v").mkdir() is None else None
    cache = Path(os.environ["JEV_JANITOR_CACHE_DIR"])
    monkeypatch.setattr(cli, "FixtureClient", _interrupting_after(5))
    assert cli.main([str(vault), "--offline", "--workers", "1"]) == cli.EXIT_INTERRUPTED  # A
    capsys.readouterr()
    monkeypatch.setattr(cli, "FixtureClient", FixtureClient)
    _t.sleep(0.01)
    assert cli.main([str(vault), "--offline", "--resume"]) == 0  # B resumes A and finishes
    a, b = _journals(cache, vault)[-2:]
    err = capsys.readouterr().err
    assert f"resuming run {_run_id(a)}" in err and "(interrupted after 5 notes)" in err
    _t.sleep(0.01)
    assert cli.main([str(vault), "--offline", "--resume", "--json"]) == 0  # C
    out, err = capsys.readouterr()
    assert f"resuming run {_run_id(b)}" in err and "(completed after 20 notes)" in err
    assert sum(1 for r in json.loads(out) if r.get("cached")) == 20  # nothing re-sent


def test_resume_prefers_the_live_stop_over_a_newer_unrelated_finished_run(tmp_path: Path, capsys, monkeypatch):
    """A interrupted, then a plain run O that did not resume it finished: --resume continues A."""
    import os
    import time as _t
    vault = _vault(tmp_path / "v", 20) if (tmp_path / "v").mkdir() is None else None
    cache = Path(os.environ["JEV_JANITOR_CACHE_DIR"])
    monkeypatch.setattr(cli, "FixtureClient", _interrupting_after(5))
    assert cli.main([str(vault), "--offline", "--workers", "1"]) == cli.EXIT_INTERRUPTED  # A
    monkeypatch.setattr(cli, "FixtureClient", FixtureClient)
    _t.sleep(0.01)
    assert cli.main([str(vault), "--offline"]) == 0  # O: newer, finished, not a resume
    a, o = _journals(cache, vault)[-2:]
    capsys.readouterr()
    _t.sleep(0.01)
    assert cli.main([str(vault), "--offline", "--resume", "--json"]) == 0
    out, err = capsys.readouterr()
    assert f"resuming run {_run_id(a)}" in err and _run_id(o) not in err
    assert sum(1 for r in json.loads(out) if r.get("cached")) == 5


def test_a_resume_stopped_part_way_serves_its_ancestor_rows_too(tmp_path: Path, capsys, monkeypatch):
    """A stopped after 5, B resumed A and was stopped after 3 fresh notes: C continues B and
    still serves A's five, whether or not B got as far as re-serving them."""
    import os
    import time as _t
    vault = _vault(tmp_path / "v", 20) if (tmp_path / "v").mkdir() is None else None
    cache = Path(os.environ["JEV_JANITOR_CACHE_DIR"])
    monkeypatch.setattr(cli, "FixtureClient", _interrupting_after(5))
    from janitor.journal import read_journal
    assert cli.main([str(vault), "--offline", "--workers", "1"]) == cli.EXIT_INTERRUPTED  # A
    capsys.readouterr()
    a_paths = {r["path"] for r in read_journal(_journals(cache, vault)[-1])[1] if r.get("kind") == "vote"}
    assert len(a_paths) == 5
    _t.sleep(0.01)
    monkeypatch.setattr(cli, "FixtureClient", _interrupting_after(3))
    assert cli.main([str(vault), "--offline", "--workers", "1", "--resume"]) == cli.EXIT_INTERRUPTED  # B
    capsys.readouterr()
    a, b = _journals(cache, vault)[-2:]
    _t.sleep(0.01)
    monkeypatch.setattr(cli, "FixtureClient", FixtureClient)
    assert cli.main([str(vault), "--offline", "--resume", "--json"]) == 0  # C
    out, err = capsys.readouterr()
    assert f"resuming run {_run_id(b)}" in err and "continues 1 earlier run(s)" in err
    rows = json.loads(out)
    cached = {r["path"] for r in rows if r.get("cached")}
    assert a_paths <= cached and len(cached) == 8  # A's five plus B's three: none of them re-sent


def test_resume_summary_names_the_stop_reason(tmp_path: Path):
    from janitor.resume import load_resume, resume_summary
    for reason, text in (("meter", "stopped by the meter"), ("402", "stopped by a 402"), ("error-rate", "stopped by the error rate"),
                         ("interrupted", "interrupted"), ("failed:OSError", "failed (OSError)")):
        p = tmp_path / f"run-20260101T000000-{abs(hash(reason)) % 10**7:07d}.jsonl"
        p.write_text(json.dumps({"kind": "run", "run": "r"}) + "\n" + json.dumps({"kind": "vote", "judge": "jev", "path": "a.md", "key": "k"}) + "\n"
                     + json.dumps({"kind": "end", "rows": 1, "aborted": reason in ("meter", "402", "error-rate"), "interrupted": reason not in ("meter", "402", "error-rate"), "reason": reason}) + "\n",
                     encoding="utf-8")
        plan = load_resume(p, {})
        assert plan.completed is False and f"({text} after 1 notes)" in resume_summary(plan, cached_hits=0, retries=0, fresh=0)


# --- last round: relative journal paths, per-key chain cache, no file write after a writer interrupt

def test_interrupt_inside_the_writer_under_apply_changes_no_file_without_a_row(tmp_path: Path):
    vault = _vault(tmp_path, 100)
    root, plan, items, fp = prepare_vault(vault)
    engine = Counting(sleep=0.02)
    recorded: list[dict] = []

    def on_row(row):
        recorded.append(row)
        if len(recorded) == 8:
            raise KeyboardInterrupt  # inside the writer: no drain, and the in-flight requests must not write
    with pytest.raises(KeyboardInterrupt):
        run_prepared(root, plan, items, engine=engine, questions={}, fingerprint=fp, workers=WORKERS, on_row=on_row, apply=True)
    time.sleep(0.2)  # let the in-flight requests finish
    stamped = {p.name for p in vault.glob("*.md") if "janitor:" in p.read_text(encoding="utf-8")}
    with_row = {r["path"] for r in recorded if r.get("applied")}
    assert stamped == with_row and len(recorded) == 8


def test_resumed_from_is_absolute_and_a_relative_journal_dir_keeps_the_chain(tmp_path: Path, capsys, monkeypatch):
    from janitor.journal import read_journal, read_journal_ends
    monkeypatch.chdir(tmp_path)
    vault = _vault(tmp_path / "v", 20) if (tmp_path / "v").mkdir() is None else None
    monkeypatch.setattr(cli, "FixtureClient", _interrupting_after(5))
    assert cli.main(["v", "--offline", "--workers", "1", "--journal", "rel/j"]) == cli.EXIT_INTERRUPTED  # A
    capsys.readouterr()
    a = sorted((tmp_path / "rel" / "j").glob("run-*.jsonl"))[-1]
    a_paths = {r["path"] for r in read_journal(a)[1] if r.get("kind") == "vote"}
    time.sleep(0.01)
    monkeypatch.setattr(cli, "FixtureClient", _interrupting_after(3))
    assert cli.main(["v", "--offline", "--workers", "1", "--journal", "rel/j", "--resume"]) == cli.EXIT_INTERRUPTED  # B
    capsys.readouterr()
    b = sorted((tmp_path / "rel" / "j").glob("run-*.jsonl"), key=lambda p: (p.stat().st_mtime_ns, p.name))[-1]
    header, _ = read_journal_ends(b)
    assert Path(header["resumed_from"]).is_absolute() and Path(header["resumed_from"]).name == a.name
    time.sleep(0.01)
    monkeypatch.setattr(cli, "FixtureClient", FixtureClient)
    assert cli.main(["v", "--offline", "--journal", "rel/j", "--resume", "--json"]) == 0  # C
    out, err = capsys.readouterr()
    assert "continues 1 earlier run(s)" in err
    cached = {r["path"] for r in json.loads(out) if r.get("cached")}
    assert a_paths <= cached and len(cached) == 8


def test_chain_cache_is_per_key_so_a_descendant_with_other_keys_hides_no_live_vote(tmp_path: Path, capsys, monkeypatch):
    """A (default wording) interrupted after 5; O resumes A under another taxonomy (every key differs)
    and finishes; --resume from O still serves A's five votes for the default wording."""
    import os

    from janitor.journal import read_journal
    from janitor.schema import DEFAULT_TAXONOMY
    vault = _vault(tmp_path / "v", 20) if (tmp_path / "v").mkdir() is None else None
    cache = Path(os.environ["JEV_JANITOR_CACHE_DIR"])
    other = tmp_path / "other.yaml"
    other.write_text(DEFAULT_TAXONOMY.read_text(encoding="utf-8").replace("Which vault bucket", "Which bucket"), encoding="utf-8")
    monkeypatch.setattr(cli, "FixtureClient", _interrupting_after(5))
    assert cli.main([str(vault), "--offline", "--workers", "1"]) == cli.EXIT_INTERRUPTED  # A
    capsys.readouterr()
    a_paths = {r["path"] for r in read_journal(_journals(cache, vault)[-1])[1] if r.get("kind") == "vote"}
    time.sleep(0.01)
    monkeypatch.setattr(cli, "FixtureClient", FixtureClient)
    assert cli.main([str(vault), "--offline", "--resume", "--taxonomy", str(other)]) == 0  # O: resumes A, other keys, finishes
    err = capsys.readouterr().err
    assert "0 already voted and unchanged" in err  # O could serve nothing: every key differs
    time.sleep(0.01)
    assert cli.main([str(vault), "--offline", "--resume", "--json"]) == 0  # picks O (finished, newest); chain holds A
    out, err = capsys.readouterr()
    assert "continues 1 earlier run(s)" in err
    cached = {r["path"] for r in json.loads(out) if r.get("cached")}
    assert cached == a_paths  # A's five live votes, not hidden by O's rows for the same notes


def test_an_aborted_footer_without_a_reason_reads_as_stopped(tmp_path: Path):
    from janitor.journal import read_journal_ends
    from janitor.resume import load_resume, resume_summary
    p = tmp_path / "run-20260101T000000-eeeeeee.jsonl"
    p.write_text(json.dumps({"kind": "run", "run": "e"}) + "\n" + json.dumps({"kind": "vote", "judge": "jev", "path": "a.md", "key": "k"}) + "\n"
                 + json.dumps({"kind": "end", "rows": 1, "aborted": True}) + "\n", encoding="utf-8")
    plan = load_resume(p, {})
    assert "(stopped after 1 notes)" in resume_summary(plan, cached_hits=0, retries=0, fresh=0)
    q = tmp_path / "run-20260101T000001-fffffff.jsonl"
    q.write_text("[1, 2]\n42\n", encoding="utf-8")  # JSON, but not objects: no header, no footer, no crash
    assert read_journal_ends(q) == (None, None)
