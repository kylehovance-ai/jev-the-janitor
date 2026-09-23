"""The ceiling meters the run, not only the estimate.

Found 2026-09-22 on the first live run of the 2,000-note synthetic corpus: generated filler
tokenized at 2.17 chars/token against a pessimistic anchor of 2.8, so the estimate-only guard
would have let a run pass the ceiling by about a third before the measured line said a word.
The anchors are measured on notes and do not move on synthetic text; the meter catches any
text. Both paths.
"""

import json
from pathlib import Path

import pytest

from janitor import cli
from janitor.bill import PRICE_PER_MILLION_USD
from janitor.client import FixtureClient, Vote
from janitor.records import FixtureRecordClient, judge_records
from janitor.scan import ScanAborted, prepare_vault, run_prepared

QUESTIONS = Path(__file__).resolve().parent.parent / "examples" / "triage.yaml"
TOKENS = 100_000  # per note: $0.0042 at the published price


class Dense(FixtureClient):
    calls = 0

    def vote(self, state, questions):
        Dense.calls += 1
        return Vote(**{**super().vote(state, questions).__dict__, "input_tokens": TOKENS})


def _vault(tmp_path: Path, n: int = 12) -> Path:
    for i in range(n):
        (tmp_path / f"n{i}.md").write_text(f"# N{i}\n\nbody {i}\n", encoding="utf-8")
    return tmp_path


def test_vault_run_stops_when_measured_spend_passes_the_ceiling(tmp_path: Path):
    vault = _vault(tmp_path)
    root, plan, items, fp = prepare_vault(vault)
    Dense.calls = 0
    limit = 3 * TOKENS / 1_000_000 * PRICE_PER_MILLION_USD  # three notes' worth
    with pytest.raises(ScanAborted, match="measured spend") as exc:
        run_prepared(root, plan, items, engine=Dense(), questions={}, fingerprint=fp, workers=1, spend_limit=limit)
    assert Dense.calls == 4 and len(exc.value.rows) == 4  # the fourth row tipped it; nothing after it was sent
    msg = str(exc.value)
    # The ceiling is shown to the hundredth of a cent below a dime, like the spend: "$0.0058 passed $0.01" read as a contradiction.
    assert "measured spend $0.0168 passed the ceiling $0.0126 after 4 sent notes" in msg and "--resume continues" in msg and "chars/token" in msg
    # No limit: every note goes.
    Dense.calls = 0
    rows = run_prepared(root, plan, items, engine=Dense(), questions={}, fingerprint=fp, workers=1)
    assert Dense.calls == 12 and len(rows) == 12


def test_vault_meter_bounds_the_overshoot_under_threads(tmp_path: Path):
    vault = _vault(tmp_path, 40)
    root, plan, items, fp = prepare_vault(vault)
    Dense.calls = 0
    limit = 2 * TOKENS / 1_000_000 * PRICE_PER_MILLION_USD
    with pytest.raises(ScanAborted):
        run_prepared(root, plan, items, engine=Dense(), questions={}, fingerprint=fp, workers=4, spend_limit=limit)
    assert Dense.calls <= 2 + 4 * 4  # at most one in-flight window past the ceiling


def test_records_run_stops_on_the_meter_and_offline_never_meters(tmp_path: Path):
    class DenseRecords(FixtureRecordClient):
        calls = 0

        def judge(self, state, questions, payloads):
            DenseRecords.calls += 1
            v = super().judge(state, questions, payloads)
            v.input_tokens = TOKENS
            return v

    recs = [{"id": f"r{i}", "sent": {"what": f"w{i}"}} for i in range(10)]
    limit = 2 * TOKENS / 1_000_000 * PRICE_PER_MILLION_USD
    # offline=False with an injected client: the meter is armed at max_usd
    with pytest.raises(ScanAborted, match="after 3 sent records"):
        judge_records(recs, QUESTIONS, offline=False, client=DenseRecords(), journal_dir=None, workers=1, max_usd=limit)
    assert DenseRecords.calls == 3
    DenseRecords.calls = 0
    rows = judge_records(recs, QUESTIONS, offline=True, client=DenseRecords(), journal_dir=None, workers=1, max_usd=limit)
    assert DenseRecords.calls == 10 and len(rows) == 10  # offline sends nothing, so nothing is metered


def test_over_budget_meters_at_the_accepted_bill_not_unbounded(tmp_path: Path):
    class DenseRecords(FixtureRecordClient):
        calls = 0

        def judge(self, state, questions, payloads):
            DenseRecords.calls += 1
            v = super().judge(state, questions, payloads)
            v.input_tokens = TOKENS
            return v

    recs = [{"id": f"r{i}", "sent": {"what": f"w{i}"}} for i in range(10)]
    # A ceiling far below the bill, accepted with over_budget: the limit becomes the bill's pessimistic end,
    # which for ten short records is well under one dense note's cost, so the meter still stops.
    with pytest.raises(ScanAborted, match="measured spend"):
        judge_records(recs, QUESTIONS, offline=False, client=DenseRecords(), journal_dir=None, workers=1, max_usd=0.000001, over_budget=True)
    assert DenseRecords.calls == 1


def test_abort_message_ratio_is_the_measured_lines_figure_on_both_paths(tmp_path: Path):
    """Two places report one quantity. The first cut counted payload only in the meter and printed
    0.99 for text the measured line calls 2.17; a reviewer read the counter before spending on it."""
    import re

    from janitor.bill import measured_line, taxonomy_chars
    from janitor.journal import canonical
    from janitor.schema import load_question_set, load_taxonomy

    class Ratioed(FixtureClient):
        def vote(self, state, questions):
            return Vote(**{**super().vote(state, questions).__dict__, "input_tokens": max(1, len(canonical(state)) // 2)})

    vault = _vault(tmp_path, 6)
    root, plan, items, fp = prepare_vault(vault)
    q = taxonomy_chars(load_taxonomy())
    with pytest.raises(ScanAborted) as exc:
        run_prepared(root, plan, items, engine=Ratioed(), questions={}, fingerprint=fp, workers=1, spend_limit=0.0, question_chars=q)
    printed = float(re.search(r"measures ([0-9.]+) chars/token on payload plus questions", str(exc.value)).group(1))
    line = float(measured_line(exc.value.rows, question_chars=q).split("measured: ")[1].split(" ")[0])
    assert printed == line and printed > 10  # the questions dominate on tiny notes: far from a payload-only 2.0

    class RatioedRecords(FixtureRecordClient):
        def judge(self, state, questions, payloads):
            v = super().judge(state, questions, payloads)
            v.input_tokens = len(canonical(state)) * 200  # dense enough to pass the bill's own pessimistic end
            return v

    recs = [{"id": f"r{i}", "sent": {"what": f"w{i}"}} for i in range(6)]
    qr = taxonomy_chars(load_question_set(QUESTIONS))
    with pytest.raises(ScanAborted) as exc:
        # over_budget so the pre-flight does not refuse first; the meter's limit is then the bill's pessimistic end
        judge_records(recs, QUESTIONS, offline=False, client=RatioedRecords(), journal_dir=None, workers=1, max_usd=0.0000001, over_budget=True)
    assert "measured spend" in str(exc.value)
    printed = float(re.search(r"measures ([0-9.]+) chars/token on payload plus questions", str(exc.value)).group(1))
    line = float(measured_line(exc.value.rows, question_chars=qr).split("measured: ")[1].split(" ")[0])
    assert printed == line and 0 < printed < 1  # far from the payload-only figure either way


def test_cli_arms_the_meter_only_when_live(tmp_path: Path, monkeypatch, capsys):
    vault = _vault(tmp_path, 2)
    monkeypatch.setenv("JEV_JANITOR_CACHE_DIR", str(tmp_path / "cache"))
    seen = {}

    def fake_run(*a, **kw):
        seen.update(kw)
        return []

    monkeypatch.setattr(cli, "run_prepared", fake_run)
    assert cli.main([str(vault), "--offline"]) == 0
    assert seen["spend_limit"] is None
    monkeypatch.setenv("TYPESAFE_API_KEY", "not-a-real-key")
    monkeypatch.setattr(cli, "build_questions", lambda taxonomy: {})
    monkeypatch.setattr(cli, "TypeSafeJanitorClient", lambda *a, **k: object())
    assert cli.main([str(vault), "--yes", "--max-usd", "1.5"]) == 0
    assert seen["spend_limit"] == 1.5
    capsys.readouterr()


CEILING = 0.0058  # below a dime, so usd() shows four places; :.2f showed "$0.01"


def test_every_ceiling_print_uses_one_format(tmp_path: Path, capsys, monkeypatch):
    """Two places that report one quantity must agree. Reproduced in review:
    Bill(max_usd=0.0058, to_send=100, payload_chars=500_000) refused with "the pessimistic
    estimate of $0.0075 ... is over the ceiling of $0.01" while the meter's abort named the
    same ceiling $0.0058. Six prints name the ceiling; all six go through usd()."""
    import re

    from janitor.bill import Bill, over_budget_refusal, render_bill, usd
    from janitor.records import load_records, prepare_records, records_bill, render_records_preflight
    from janitor.records_cli import main as records_main

    shown = usd(CEILING)
    assert shown == "$0.0058"
    bill = Bill(max_usd=CEILING, to_send=100, payload_chars=500_000)
    assert bill.over_budget
    # 1, 2: the vault bill's ceiling line (live and offline) and the vault refusal
    for live in (True, False):
        assert f"ceiling {shown}: OVER at the pessimistic end" in render_bill(bill, live=live)
    assert f"is over the ceiling of {shown}. Nothing was sent." in over_budget_refusal(bill)
    # 3: the records pre-flight's ceiling line
    # 40 distinct records under the default excerpt cap: identical `sent` would be judged once and billed once.
    raw = [{"id": f"r{i}", "sent": {"what": f"{i:03d}" + "w" * 15_000}} for i in range(40)]
    p = tmp_path / "r.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in raw), encoding="utf-8")
    items = prepare_records(load_records(p), fingerprint="x", model_requested="fixture", denylist=[], excerpt_chars=0, cache={})
    rbill = records_bill(items, question_chars=2_000, max_usd=CEILING)
    assert rbill.over_budget
    preflight = render_records_preflight(items, rbill, live=True, fingerprint="x", review=None, excerpt_chars=0)
    assert f"ceiling {shown}: OVER at the pessimistic end" in preflight
    # 4: the library refusal
    with pytest.raises(ScanAborted, match=re.escape(f"over the ceiling of {shown}. Nothing was sent.")):
        judge_records(raw, QUESTIONS, offline=False, client=FixtureRecordClient(), journal_dir=None, max_usd=CEILING)
    # 5: the console script's refusal
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert records_main([str(p), "--questions", str(QUESTIONS), "--yes", "--max-usd", str(CEILING), "--journal", "off"]) == 1
    err = capsys.readouterr().err
    assert f"ceiling {shown}: OVER" in err and f"over the ceiling of {shown}. Nothing was sent." in err
    # 6: the meter's abort (already usd() in 0.4.6; pinned here with the rest)
    (tmp_path / "v").mkdir()
    root, plan, items, fp = prepare_vault(_vault(tmp_path / "v", 4))
    with pytest.raises(ScanAborted, match=re.escape(f"passed the ceiling {shown} after 2 sent notes")):
        run_prepared(root, plan, items, engine=Dense(), questions={}, fingerprint=fp, workers=1, spend_limit=CEILING)
    # And no print site formats a ceiling on its own: every dollar figure that leaves goes through usd() or usd_apart().
    src = Path(__file__).resolve().parent.parent / "janitor"
    for py in src.glob("*.py"):
        text = py.read_text(encoding="utf-8")
        hit = re.search(r"\{[^}]*(max_usd|spend_limit)[^}]*:[^}]*\.\d+f\}", text)
        assert hit is None, f"{py.name}: {hit.group(0)}"


def test_measured_line_names_the_meter_only_when_a_ceiling_was_set(tmp_path: Path, monkeypatch, capsys):
    """The first cut of this flag said "the ceiling is guarded by the meter" under --max-usd 0,
    where there is no ceiling and no meter. The line now knows what the run was armed with."""
    from janitor.bill import measured_line

    rows = [{"kind": "vote", "judge": "jev", "cached": False, "payload_chars": 200, "input_tokens": 100} for _ in range(3)]
    armed = measured_line(rows, spend_limit=2.0)
    unarmed = measured_line(rows, spend_limit=None)
    assert "denser than the notes" in armed and "denser than the notes" in unarmed
    assert "the ceiling is guarded by the meter, not the estimate" in armed
    assert "guarded by the meter" not in unarmed and "no ceiling metered this run" in unarmed
    assert measured_line(rows) == unarmed  # a caller that says nothing about a ceiling gets no claim about one

    # Through the command: --offline arms no meter (nothing is spent), so the line must not claim one.
    class DenseFixture(FixtureClient):
        def vote(self, state, questions):
            from janitor.journal import canonical

            return Vote(**{**super().vote(state, questions).__dict__, "input_tokens": len(canonical(state)) * 20})

    vault = _vault(tmp_path, 3)
    monkeypatch.setenv("JEV_JANITOR_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(cli, "FixtureClient", DenseFixture)
    assert cli.main([str(vault), "--offline", "--max-usd", "0"]) == 0
    err = capsys.readouterr().err
    assert "measured: " in err and "denser than the notes" in err
    assert "guarded by the meter" not in err and "no ceiling metered this run" in err


def test_meter_abort_shows_the_ceiling_and_the_spend_apart(tmp_path: Path):
    """A spend that passes the ceiling by less than usd() can show printed "$0.0058 passed the
    ceiling $0.0058": true, and unreadable. Both figures widen together until they differ."""
    from janitor.bill import usd_apart, usd_for

    assert usd_apart(0.0168, 0.0126) == ("$0.0168", "$0.0126")  # the ordinary case is usd()'s own format
    assert usd_apart(1.448, 1.2) == ("$1.45", "$1.20")
    assert usd_apart(0.1061, 0.1059) == ("$0.1061", "$0.1059")  # above a dime, widened past the cent until they part
    tokens = 138_119  # $0.005800998: the same "$0.0058" as the ceiling at four places
    spent = usd_for(tokens)
    assert CEILING < spent < CEILING + 0.00001
    assert usd_apart(spent, CEILING) == ("$0.005801", "$0.005800")

    class Hair(FixtureClient):
        def vote(self, state, questions):
            return Vote(**{**super().vote(state, questions).__dict__, "input_tokens": tokens})

    root, plan, items, fp = prepare_vault(_vault(tmp_path, 2))
    with pytest.raises(ScanAborted, match="measured spend \\$0.005801 passed the ceiling \\$0.005800 after 1 sent notes") as exc:
        run_prepared(root, plan, items, engine=Hair(), questions={}, fingerprint=fp, workers=1, spend_limit=CEILING)
    assert "$0.0058 passed the ceiling $0.0058" not in str(exc.value)
