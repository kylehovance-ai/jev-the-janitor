"""The pre-flight bill: a range from the actual payloads, printed before consent, enforced live.

The refusal is testable without a key or a network: the ceiling check runs before the key
check, so a live run over budget fails on the bill and never gets as far as looking for one.
"""

from pathlib import Path

import pytest

from janitor import cli
from janitor.bill import (
    CHARS_PER_TOKEN_HIGH,
    CHARS_PER_TOKEN_LOW,
    DEFAULT_MAX_USD,
    PRICE_PER_MILLION_USD,
    build_bill,
    measured_line,
    render_bill,
    tokens_for,
)
from janitor.client import FixtureClient, Vote
from janitor.journal import canonical
from janitor.scan import prepare_vault, scan_vault

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    files = {
        "notes/a.md": "# A\n\n" + ("alpha words here. " * 200) + "\n",
        "notes/b.md": "# B\n\n" + ("beta words here. " * 50) + "\n",
        "projects/c.md": "# C\n\ngamma\n",
        "projects/empty.md": "",
        "projects/secret.md": f"# S\n\n{KEY}\n",
        "projects/locked.md": "---\njanitor:\n  locked: true\n---\n# L\n\nlocked body\n",
        "family/mom.md": "# Mom\n\nprivate\n",
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


def test_bill_counts_every_class_and_sums_the_real_payloads(vault: Path):
    root, plan, items, _ = prepare_vault(vault)
    bill = build_bill(plan, items, question_chars=100)
    assert (bill.to_send, bill.local, bill.locked, bill.cached, bill.errors) == (3, 2, 1, 0, 0)
    assert dict(bill.skipped) == {"sensitive path part 'family'": 1}
    sent = [it for it in items if it.local is None and not it.locked and it.error is None]
    assert bill.payload_chars == sum(len(canonical(it.state)) for it in sent)
    assert bill.chars == bill.payload_chars + 100 * 3
    assert bill.tokens_high == tokens_for(bill.chars, CHARS_PER_TOKEN_LOW) > bill.tokens_low == tokens_for(bill.chars, CHARS_PER_TOKEN_HIGH)
    assert bill.usd_high == bill.tokens_high / 1_000_000 * PRICE_PER_MILLION_USD
    assert bill.largest_folders()[0][0] == "notes/"  # a.md dominates
    assert [f for f, _, _ in bill.largest_folders()] == ["notes/", "projects/"]
    assert bill.max_usd == DEFAULT_MAX_USD == 2.0 and not bill.over_budget


def test_the_guard_uses_the_pessimistic_end(vault: Path):
    root, plan, items, _ = prepare_vault(vault)
    bill = build_bill(plan, items, max_usd=(build_bill(plan, items).usd_low + build_bill(plan, items).usd_high) / 2)
    assert bill.usd_low < bill.max_usd < bill.usd_high
    assert bill.over_budget  # a ceiling between the two ends refuses: the guard errs toward not spending


def test_render_shows_a_range_and_names_the_ceiling(vault: Path):
    root, plan, items, _ = prepare_vault(vault)
    from janitor.bill import usd

    ceiling = build_bill(plan, items, question_chars=100).usd_high / 2  # a few thousandths of a cent for this vault
    text = render_bill(build_bill(plan, items, question_chars=100, max_usd=ceiling), live=True)
    assert "bill (estimate): 3 notes to send, 0 served from the journal, 2 decided locally, 1 locked, 1 skipped, 0 undecodable, 0 unreadable" in text
    assert " to " in text and "3.8 down to 2.8 chars/token, the range measured on real notes" in text
    assert "$0.042 per million" in text
    # The ceiling to the same places as the bill it is compared with (through 0.4.5 this line said "ceiling $0.00: OVER").
    assert f"ceiling {usd(ceiling)}: OVER at the pessimistic end" in text and "ceiling $0.00:" not in text
    assert "largest folders by payload:" in text and "notes/" in text
    offline = render_bill(build_bill(plan, items), live=False)
    assert "a live run would send" in offline and "ceiling $2.00: under" in offline


def test_plan_and_offline_print_the_bill_without_a_key(vault: Path, capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert cli.main([str(vault), "--plan"]) == 0
    out = capsys.readouterr().out
    assert "bill (estimate): 3 notes to send" in out and "ceiling $2.00: under" in out
    assert cli.main([str(vault), "--offline"]) == 0
    assert "a live run would send" in capsys.readouterr().err


def test_live_run_over_the_ceiling_refuses_before_looking_for_a_key(vault: Path, capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert cli.main([str(vault), "--max-usd", "0.0001", "--yes"]) == cli.EXIT_REFUSED
    err = capsys.readouterr().err
    assert "ceiling $0.0001: OVER" in err
    assert "REFUSED: the pessimistic estimate of $" in err and "the optimistic end is $" in err and "over the ceiling of $0.0001." in err
    assert "--over-budget" in err and "Nothing was sent" in err
    # --over-budget accepts the bill; the run then proceeds to the key check, which is the next gate
    with pytest.raises(SystemExit, match="TYPESAFE_API_KEY is not set"):
        cli.main([str(vault), "--max-usd", "0.0001", "--yes", "--over-budget"])
    # --plan shows the refusal and exits 0: it is the reading command
    assert cli.main([str(vault), "--max-usd", "0.0001", "--plan"]) == 0
    assert "REFUSED: the pessimistic estimate" in capsys.readouterr().out


def test_zero_means_no_ceiling(vault: Path, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="TYPESAFE_API_KEY is not set"):
        cli.main([str(vault), "--max-usd", "0", "--yes"])


def test_reference_workload_passes_the_default_ceiling():
    """A real pass of 18,738 notes, 86,397,152 excerpt chars. 0.3.0's first draft refused it.

    The questions ride along with every call (2,086 chars at the default taxonomy, their wire
    form), so the bill the pre-flight prints for this vault is $1.39 to $1.88, and the projection
    at the 31-note live ratio of 3.53 on the same basis is about $1.49, inside it. That pass has
    not been run live at 0.4.x; through 0.4.0 this test called $1.22 "measured" when it was 2.98
    (a payload-only ratio) applied to the payload, an inference on the wrong basis. The ceiling
    must still sit above the pessimistic end, and it does, with 6% to spare."""
    from janitor.bill import Bill, taxonomy_chars
    from janitor.schema import load_taxonomy

    q = taxonomy_chars(load_taxonomy())
    assert q == 2_086
    bill = Bill(to_send=18_738, payload_chars=86_397_152, question_chars=q)
    projected_usd = (86_397_152 + 18_738 * q) / 3.53 / 1_000_000 * 0.042
    assert bill.usd_low < projected_usd < bill.usd_high < DEFAULT_MAX_USD
    assert round(bill.usd_low, 2) == 1.39 and round(bill.usd_high, 2) == 1.88 and round(projected_usd, 2) == 1.49


def test_measured_line_counts_the_questions_the_estimate_counted():
    """The first live run on a synthetic test corpus (182 short notes, 287,073 tokens) printed 1.83 chars/token
    and told the operator to re-anchor, because the line divided payload chars alone by tokens
    that included the questions. On the estimate's own basis it is 2.89, inside the range, and
    the pre-flight had bracketed the real bill."""
    n, tokens_total, q = 182, 287_073, 1_681
    payload_total = round(1.83 * tokens_total)
    rows = [{"kind": "vote", "judge": "jev", "cached": False, "payload_chars": payload_total // n, "input_tokens": tokens_total // n} for _ in range(n)]
    rows[-1]["payload_chars"] += payload_total - (payload_total // n) * n  # the totals are what is measured
    rows[-1]["input_tokens"] += tokens_total - (tokens_total // n) * n
    old = measured_line(rows, spend_limit=2.0)
    new = measured_line(rows, question_chars=q, spend_limit=2.0)
    assert old.startswith("measured: 1.83 chars/token") and "OUTSIDE the assumed range" in old
    assert "denser than the notes" in old and "guarded by the meter" in old and "bill.py" not in old  # a fact, not advice to edit source
    ratio = float(new.split("measured: ")[1].split(" ")[0])
    assert 2.88 <= ratio <= 2.91 and "OUTSIDE" not in new  # 2.89 on the live run; the payload here is rebuilt from a rounded 1.83
    assert f"+ {q * n:,} question chars" in new and "on the same basis" in new


def test_small_bills_show_fractions_of_a_cent():
    """Below a dime the bill used to print `~$0.01 to $0.01`, which said nothing."""
    from janitor.bill import Bill, usd

    assert usd(0.0049) == "$0.0049" and usd(0.0121) == "$0.0121" and usd(0.10) == "$0.10" and usd(1.448) == "$1.45"
    text = render_bill(Bill(to_send=3, payload_chars=30_000, question_chars=1_681), live=False)
    assert "~$0.0004 to $0.0005 at $0.042 per million" in text


class Counting(FixtureClient):
    """A client that reports token counts, as the real one does."""

    def vote(self, state, questions):
        v = super().vote(state, questions)
        return Vote(**{**v.__dict__, "input_tokens": len(canonical(state)) // 4})


def test_rows_carry_tokens_and_payload_and_the_measured_line_uses_them(vault: Path):
    rows = scan_vault(vault, client=Counting(), offline=True)
    sent = [r for r in rows if r.get("judge") == "jev"]
    assert all(r["input_tokens"] > 0 and r["payload_chars"] > 0 for r in sent)
    line = measured_line(rows)
    assert line is not None and line.startswith("measured: ") and "chars/token over 3 sent notes" in line
    assert "the pre-flight assumed 3.8 to 2.8" in line
    ratio = float(line.split("measured: ")[1].split(" ")[0])
    assert 3.9 <= ratio <= 4.1  # len // 4 per note, so just over 4: outside the assumed range, and the line says so
    assert "OUTSIDE the assumed range" in line and "lighter than the notes" in line  # len // 4 is above 3.8


def test_fixture_client_reports_no_tokens_so_nothing_is_measured(vault: Path, capsys):
    rows = scan_vault(vault, offline=True)
    assert measured_line(rows) is None
    assert cli.main([str(vault), "--offline"]) == 0
    assert "measured:" not in capsys.readouterr().err


def test_measured_line_is_printed_after_a_run_with_token_counts(vault: Path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "FixtureClient", Counting)
    assert cli.main([str(vault), "--offline"]) == 0
    assert "measured: " in capsys.readouterr().err
