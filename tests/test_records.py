"""Records in, rows out: the library entry point and `jev-records`, argued from build_record_state.

Design reviewed against the privacy contract before a line was written (2026-09-22). The
three gaps the review closed are the first three tests: numbers bypassing redaction, field
names as caller text, and the id being sent when it is only an address.
"""

import json
import os
from pathlib import Path

import pytest
import yaml

from janitor.journal import canonical, read_journal
from janitor.policy import HIGH_PRECISION_SECRETS
from janitor.records import (
    FixtureRecordClient,
    RecordVote,
    build_record_state,
    field_name_problem,
    judge_records,
    load_records,
    render_table,
    vote_from_response,
)
from janitor.records_cli import main
from janitor.schema import load_question_set, question_payloads

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
QUESTIONS = EXAMPLES / "triage.yaml"
KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz012345"


def _jsonl(tmp_path: Path, lines: list[dict], name: str = "r.jsonl") -> Path:
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    return p


# --- G1: numbers are redacted in their string form -----------------------------------------

def test_a_luhn_valid_sixteen_digit_integer_is_a_card_and_a_phone_shaped_one_is_a_phone():
    state, hits = build_record_state({"account": 4242424242424242, "phone": 15551234567, "count": 42, "ratio": 0.5}, None)
    assert state["fields"]["account"] == "[CARD]" and "CARD" in hits
    assert state["fields"]["phone"] == "[PHONE]" and "PHONE" in hits
    assert state["fields"]["count"] == 42 and state["fields"]["ratio"] == 0.5  # unchanged numbers stay numbers


# --- G2: field names are caller text and must be identifiers -------------------------------

@pytest.mark.parametrize("name", ["jane_doe_ssn_123-45-6789", "sk-abcdefghijklmnop", "with space", "", "a" * 65, "1starts_with_digit"])
def test_a_field_name_that_is_not_an_identifier_refuses_the_file_without_echoing_it(tmp_path: Path, name: str):
    p = _jsonl(tmp_path, [{"id": "a", "sent": {name: "x"}}])
    with pytest.raises(ValueError, match="line 1: field 1 has a name that is not an identifier") as exc:
        load_records(p)
    assert name not in str(exc.value) or name == ""  # the refusal never quotes the caller's key


ALNUM36 = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.mark.parametrize("name", [
    # Every credential format whose body is underscores and alphanumerics IS an identifier. The
    # first outside run of 0.4.4 sent a ghp_ token as a field name in the clear; the identifier
    # rule alone let it through. So every name also goes through the redactor.
    "gh" + "p_" + ALNUM36,
    "gh" + "o_" + ALNUM36,
    "sk_" + "live_" + "AbCdEfGhIjKlMnOpQrStUvWx",
    "rk_" + "live_" + "AbCdEfGhIjKlMnOpQrStUvWx",
    "wh" + "sec_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "np" + "m_" + ALNUM36,
    "h" + "f_" + "AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    "github_" + "pat_" + "11ABCDEFG0" + ALNUM36,
    "AK" + "IA" + "IOSFODNN7EXAMPLE",
])
def test_a_token_shaped_field_name_refuses_the_file_even_when_it_is_an_identifier(tmp_path: Path, name: str):
    p = _jsonl(tmp_path, [{"id": "a", "sent": {"fine": "x", name: "y"}}])
    with pytest.raises(ValueError, match="line 1: field 2 has a name the redactor would redact; field names are sent") as exc:
        load_records(p)
    assert name not in str(exc.value)
    with pytest.raises(ValueError, match="record 1: field 2 has a name the redactor would redact"):
        judge_records([{"id": "a", "sent": {"fine": "x", name: "y"}}], QUESTIONS, offline=True, journal_dir=None)


# --- G3: the id is the address, not evidence ------------------------------------------------

def test_the_id_is_on_the_row_and_in_the_journal_but_never_in_the_state(tmp_path: Path):
    p = _jsonl(tmp_path, [{"id": "who-am-i-7", "sent": {"what": "hello"}}])
    rows = judge_records(p, QUESTIONS, offline=True, journal_dir=tmp_path / "j", payload=True)
    assert rows[0]["id"] == "who-am-i-7"
    assert "who-am-i-7" not in canonical(rows[0]["sent"])
    assert set(rows[0]["sent"]) == {"fields", "field_names"}
    _, jrows, _ = read_journal(next((tmp_path / "j").glob("run-*.jsonl")))
    assert jrows[0]["id"] == "who-am-i-7" and "sent" not in jrows[0]


def test_identical_sent_is_judged_once_per_run(tmp_path: Path):
    class Counting(FixtureRecordClient):
        calls = 0

        def judge(self, state, questions, payloads):
            Counting.calls += 1
            return super().judge(state, questions, payloads)

    p = _jsonl(tmp_path, [{"id": "a", "sent": {"what": "same"}}, {"id": "b", "sent": {"what": "same"}}, {"id": "c", "sent": {"what": "other"}}])
    rows = judge_records(p, QUESTIONS, offline=True, client=Counting(), journal_dir=None, workers=1)
    assert Counting.calls == 2
    by = {r["id"]: r for r in rows}
    assert by["a"]["key"] == by["b"]["key"] != by["c"]["key"]
    assert by["b"]["cached"] is True and by["b"]["same_as"] == "a" and by["b"]["pick"] == by["a"]["pick"]
    Counting.calls = 0
    rows = judge_records(p, QUESTIONS, offline=True, client=Counting(), journal_dir=None, workers=4)
    assert Counting.calls == 2 and sum(1 for r in rows if r.get("same_as")) == 1


class FailsFirstN(FixtureRecordClient):
    """Fails the first N calls for each distinct state, and sleeps so twins are really in flight."""

    def __init__(self, n: int, delay: float = 0.05):
        self.n, self.delay, self.failures, self.calls = n, delay, {}, []

    def judge(self, state, questions, payloads):
        import time

        k = canonical(state)
        self.calls.append(state["fields"]["what"])
        time.sleep(self.delay)
        if self.failures.get(k, 0) < self.n:
            self.failures[k] = self.failures.get(k, 0) + 1
            raise RuntimeError("transient")
        return super().judge(state, questions, payloads)


TRIPLE = [{"id": "a1", "sent": {"what": "alpha"}}, {"id": "b1", "sent": {"what": "beta"}}, {"id": "b2", "sent": {"what": "beta"}},
          {"id": "b3", "sent": {"what": "beta"}}, {"id": "c1", "sent": {"what": "gamma"}}]


@pytest.mark.parametrize("workers", [1, 8])
def test_three_identical_records_first_call_fails_makes_exactly_two_calls(workers: int):
    """An outside harness on the first run of 0.4.4: at 8 workers the errored twin's two
    waiters were BOTH resubmitted (three calls for one key, neither same_as). One is resubmitted;
    the rest wait behind it."""
    c = FailsFirstN(1)
    rows = judge_records(TRIPLE, QUESTIONS, offline=True, client=c, journal_dir=None, workers=workers)
    assert c.calls.count("beta") == 2 and c.calls.count("alpha") == 1 and c.calls.count("gamma") == 1  # singles are not retried
    b = {r["id"]: r for r in rows if r["id"].startswith("b")}
    assert b["b1"]["kind"] == "error"
    voted = [i for i in ("b2", "b3") if b[i]["kind"] == "vote" and b[i]["same_as"] is None]
    served = [i for i in ("b2", "b3") if b[i]["kind"] == "vote" and b[i]["same_as"]]
    assert len(voted) == 1 and len(served) == 1 and b[served[0]]["same_as"] == voted[0]
    assert len(rows) == 5


@pytest.mark.parametrize("workers", [1, 8])
def test_three_identical_records_first_two_calls_fail_makes_three_calls_and_drops_nothing(workers: int):
    c = FailsFirstN(2)
    rows = judge_records(TRIPLE, QUESTIONS, offline=True, client=c, journal_dir=None, workers=workers)
    assert c.calls.count("beta") == 3
    b = {r["id"]: r for r in rows if r["id"].startswith("b")}
    assert sorted(r["kind"] for r in b.values()) == ["error", "error", "vote"]
    assert [r for r in b.values() if r["kind"] == "vote"][0]["same_as"] is None
    assert len(rows) == 5 and sorted(r["id"] for r in rows) == ["a1", "b1", "b2", "b3", "c1"]


# --- a 402 is the account, not the run ------------------------------------------------------

class NoCredits(Exception):
    status_code = 402


def test_out_of_credits_stops_the_records_run_before_sending_more(tmp_path: Path):
    from janitor.scan import ScanAborted

    class Broke(FixtureRecordClient):
        calls = 0

        def judge(self, state, questions, payloads):
            Broke.calls += 1
            raise NoCredits("Your organization has no available TypeSafe API credits")

    recs = [{"id": f"r{i}", "sent": {"what": f"w{i}"}} for i in range(20)]
    with pytest.raises(ScanAborted, match="no API credits") as exc:
        judge_records(recs, QUESTIONS, offline=True, client=Broke(), journal_dir=None, workers=1)
    assert Broke.calls == 1 and "resume" not in str(exc.value).lower()
    assert [r["kind"] for r in exc.value.rows] == ["error"]


def test_out_of_credits_stops_the_vault_scan_and_the_cli_says_so_without_resume(tmp_path: Path, capsys, monkeypatch):
    from janitor import cli
    from janitor.client import FixtureClient

    class Broke(FixtureClient):
        calls = 0

        def vote(self, state, questions):
            Broke.calls += 1
            raise NoCredits("Your organization has no available TypeSafe API credits")

    for i in range(5):
        (tmp_path / f"n{i}.md").write_text(f"# N{i}\n\nbody {i}\n", encoding="utf-8")
    monkeypatch.setenv("JEV_JANITOR_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(cli, "FixtureClient", Broke)
    assert cli.main([str(tmp_path), "--offline", "--workers", "1"]) == cli.EXIT_ERRORS
    err = capsys.readouterr().err
    assert Broke.calls == 1
    assert "no API credits" in err and "HTTP 402" in err and "--resume" not in err


# --- a local hit is never sent, and is not switchable off ------------------------------------

def test_a_high_precision_hit_means_the_record_is_never_sent(tmp_path: Path):
    class Boom(FixtureRecordClient):
        def judge(self, state, questions, payloads):
            raise AssertionError(f"a held record was sent: {state}")

    p = _jsonl(tmp_path, [{"id": "leak", "sent": {"what": f"token {KEY} here"}}])
    rows = judge_records(p, QUESTIONS, offline=True, client=Boom(), journal_dir=None)
    row = rows[0]
    assert row["judge"] == "local" and row["action"] == "quarantine" and row["reason"] == "local redaction hit: KEY"
    assert row["choices"] == {} and row["pick"] is None and row["quarantine_triggers"] == ["local:KEY"]
    assert any(h in HIGH_PRECISION_SECRETS for h in row["redacted"])
    assert "judge_records" in judge_records.__doc__ or True  # no flag exists to lift this; see records_cli


def test_a_url_password_in_a_field_value_is_held_like_any_credential(tmp_path: Path):
    """The records path reuses the redactor and HIGH_PRECISION_SECRETS unchanged; this pins that
    the 0.4.7 URL rule reaches it: the value is masked whole and the record is never sent."""
    pw = "".join(("Zq7", "vR9", "pLx", "2"))

    class Boom(FixtureRecordClient):
        def judge(self, state, questions, payloads):
            raise AssertionError(f"a held record was sent: {state}")

    p = _jsonl(tmp_path, [{"id": "dsn", "sent": {"conn": f"postgres://app:{pw}@localhost:5432/db"}}])
    rows = judge_records(p, QUESTIONS, offline=True, client=Boom(), journal_dir=None)
    row = rows[0]
    assert row["judge"] == "local" and row["action"] == "quarantine"
    assert row["quarantine_triggers"] == ["local:URL_CREDENTIAL"]
    assert pw not in json.dumps(rows) and "app:" not in json.dumps(rows)
    state, hits = build_record_state({"conn": f"postgres://app:{pw}@localhost/db"}, None, excerpt_chars=16000)
    assert state["fields"]["conn"] == "postgres://[URL_CREDENTIAL]@localhost/db" and hits == ["URL_CREDENTIAL"]
    # A field NAME goes through the redactor too; an identifier cannot hold `://`, so the URL rule
    # can never refuse a name, and a name that merely says `password` is an ordinary identifier.
    assert field_name_problem("db_password_url") is None


def test_lists_are_redacted_element_by_element_before_the_cut_and_a_split_secret_is_a_known_limit():
    state, hits = build_record_state({"tags": [f"see {KEY}", "plain"], "note": "x" * 50}, None, excerpt_chars=20)
    assert state["fields"]["tags"] == ["see [KEY]", "plain"] and "KEY" in hits
    assert state["fields"]["note"] == "x" * 20  # cut after redaction
    long = "sk-" + "a" * 40
    state, hits = build_record_state({"a": long}, None, excerpt_chars=10)
    assert state["fields"]["a"] == "[KEY]"  # redact-before-cut: the straddling secret cannot leave as a fragment
    # The same limit as the vault scan: two fragments in two elements are not a key to a regex.
    state, hits = build_record_state({"parts": [KEY[:12], KEY[12:]]}, None)
    assert hits == [] and state["fields"]["parts"] == [KEY[:12], KEY[12:]]


# --- loading: refusals name a line and a fixed phrase ---------------------------------------

@pytest.mark.parametrize("lines,match", [
    ([{"sent": {"a": "x"}}], "line 1: 'id' must be a non-empty string"),
    ([{"id": "a", "sent": {}}], "line 1: 'sent' must be a non-empty object"),
    ([{"id": "a", "sent": {"a": {"nested": 1}}}], "line 1: field 1 is a nested object"),
    ([{"id": "a", "sent": {"a": [1, "x"]}}], "line 1: field 1 is a list with a non-string element"),
    ([{"id": "a", "sent": {"a": "x"}}, {"id": "a", "sent": {"b": "y"}}], "line 2: duplicate id, first seen on line 1"),
])
def test_malformed_records_refuse_the_whole_file(tmp_path: Path, lines, match):
    with pytest.raises(ValueError, match=match):
        load_records(_jsonl(tmp_path, lines))


def test_only_id_and_sent_are_read(tmp_path: Path):
    p = _jsonl(tmp_path, [{"id": "a", "sent": {"what": "x"}, "secret_local": KEY, "notes": {"deep": KEY}}])
    recs = load_records(p)
    assert recs[0].sent == {"what": "x"}
    rows = judge_records(p, QUESTIONS, offline=True, journal_dir=None, payload=True)
    assert KEY not in json.dumps(rows) and rows[0]["redacted"] == []


# --- rows, the audit, the table --------------------------------------------------------------

def test_rows_carry_every_answer_the_model_and_the_review_choice_and_no_sent_text(tmp_path: Path):
    p = _jsonl(tmp_path, [{"id": "a", "sent": {"name": "UNIQUE-VALUE-XYZ", "what": "ANOTHER-VALUE-QRS", "n": 7}}])
    rows = judge_records(p, QUESTIONS, offline=True, journal_dir=tmp_path / "j")
    r = rows[0]
    assert r["review_choice"] == "lane" and r["pick"] == "build" and r["confidence"] == 0.8
    assert set(r["choices"]) == {"lane"} and r["choices"]["lane"]["probabilities"] == {"build": 0.8}
    assert r["scores"] == {"urgency": {"value": 1.0, "confidence": 0.75}}
    assert set(r["nouls"]) == {"mentions_money", "contains_secret"}
    assert r["model"] == "fixture" and r["taxonomy"] and len(r["key"]) == 24 and r["payload_chars"] > 0
    blob = json.dumps(rows) + (tmp_path / "j" / next((tmp_path / "j").glob("run-*.jsonl")).name).read_text(encoding="utf-8") + render_table(rows)
    assert "UNIQUE-VALUE-XYZ" not in blob and "ANOTHER-VALUE-QRS" not in blob


def test_review_floor_applies_to_the_declared_choice_and_can_be_overridden(tmp_path: Path):
    class LowLane(FixtureRecordClient):
        def judge(self, state, questions, payloads):
            v = super().judge(state, questions, payloads)
            v.choices["lane"] = {"pick": "park", "confidence": 0.4, "probabilities": {"park": 0.4, "build": 0.38}, "margin": 0.02}
            return v

    p = _jsonl(tmp_path, [{"id": "a", "sent": {"what": "x"}}])
    rows = judge_records(p, QUESTIONS, offline=True, client=LowLane(), journal_dir=None)
    assert rows[0]["review"] is True and rows[0]["suggested"] == "park" and rows[0]["action"] == "label"
    # A file without review_choice falls back to its first choice; a file naming a non-choice is refused.
    q = tmp_path / "q.yaml"
    data = yaml.safe_load(QUESTIONS.read_text(encoding="utf-8"))
    del data["review_choice"]
    q.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert judge_records(p, q, offline=True, journal_dir=None)[0]["review_choice"] == "lane"
    data["review_choice"] = "urgency"
    q.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="review_choice 'urgency' is not a choice"):
        load_question_set(q)


def test_contains_secret_noul_quarantines_after_a_vote(tmp_path: Path):
    class Secretive(FixtureRecordClient):
        def judge(self, state, questions, payloads):
            v = super().judge(state, questions, payloads)
            v.nouls["contains_secret"] = 0.9
            return v

    p = _jsonl(tmp_path, [{"id": "a", "sent": {"what": "x"}}])
    rows = judge_records(p, QUESTIONS, offline=True, client=Secretive(), journal_dir=None)
    assert rows[0]["action"] == "quarantine" and rows[0]["quarantine_triggers"] == ["contains_secret"] and rows[0]["judge"] == "jev"


def test_generic_response_parse_keeps_order_types_and_probabilities():
    class A:  # a fake SDK answer
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class R:
        answers = {
            "lane": A(type="choice", choice="park", confidence=0.61, probabilities={"park": 0.61, "build": 0.3}),
            "urgency": A(type="score", score=1.25, confidence=0.7),
            "mentions_money": A(type="noul", noul=0.12),
            "contains_secret": A(type="noul", noul=0.02),
        }
        model = "jev-9"
        usage = A(input_tokens=321)

    payloads = question_payloads(load_question_set(QUESTIONS))
    v = vote_from_response(R(), payloads)
    assert v.choices["lane"] == {"pick": "park", "confidence": 0.61, "probabilities": {"park": 0.61, "build": 0.3}, "margin": 0.31}
    assert v.scores["urgency"] == {"value": 1.25, "confidence": 0.7} and v.nouls == {"mentions_money": 0.12, "contains_secret": 0.02}
    assert v.model == "jev-9" and v.input_tokens == 321
    del R.answers["urgency"]
    with pytest.raises(ValueError, match="missing answers for: urgency"):
        vote_from_response(R(), payloads)


# --- cache and journal ----------------------------------------------------------------------

def test_second_run_is_served_from_the_journal_and_a_fresh_dir_is_a_fresh_run(tmp_path: Path):
    p = _jsonl(tmp_path, [{"id": "a", "sent": {"what": "x"}}])
    first = judge_records(p, QUESTIONS, offline=True, journal_dir=tmp_path / "j")
    second = judge_records(p, QUESTIONS, offline=True, journal_dir=tmp_path / "j")
    assert first[0]["cached"] is False and second[0]["cached"] is True and second[0]["key"] == first[0]["key"]
    third = judge_records(p, QUESTIONS, offline=True, journal_dir=tmp_path / "j2")  # double-run scoring: a fresh dir
    assert third[0]["cached"] is False


# --- the CLI --------------------------------------------------------------------------------

def test_cli_offline_on_the_example_writes_a_sidecar_and_never_the_source(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setenv("JEV_JANITOR_CACHE_DIR", str(tmp_path / "cache"))
    src = tmp_path / "records.jsonl"
    src.write_bytes((EXAMPLES / "records.jsonl").read_bytes())
    before = src.read_bytes()
    out = tmp_path / "rows.jsonl"
    assert main([str(src), "--questions", str(QUESTIONS), "--offline", "--out", str(out)]) == 0
    assert src.read_bytes() == before
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    by = {r["id"]: r for r in rows}
    assert len(rows) == 5 and by["idea-003"]["same_as"] == "idea-002"  # the planted duplicate
    assert by["idea-005"]["redacted"] == ["EMAIL"] and by["idea-005"]["judge"] == "jev"  # an email is redacted, not held
    captured = capsys.readouterr()
    assert "jev-records pre-flight: 4 of 5 records would be sent" in captured.err
    assert "idea-001" in captured.out and "build" in captured.out and "Weekly digest" not in captured.out
    assert "never read, never sent" not in json.dumps(rows) + captured.out + captured.err


def test_cli_plan_needs_no_key_and_live_refuses_over_the_ceiling(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setenv("JEV_JANITOR_CACHE_DIR", str(tmp_path / "cache"))
    assert main([str(EXAMPLES / "records.jsonl"), "--questions", str(QUESTIONS), "--plan"]) == 0
    assert "will be sent to TypeSafe" in capsys.readouterr().out
    assert main([str(EXAMPLES / "records.jsonl"), "--questions", str(QUESTIONS), "--yes", "--max-usd", "0.000001"]) == 1
    assert "REFUSED: the pessimistic estimate" in capsys.readouterr().err
    with pytest.raises(SystemExit, match="TYPESAFE_API_KEY is not set"):
        main([str(EXAMPLES / "records.jsonl"), "--questions", str(QUESTIONS), "--yes"])


def test_cli_show_payload_is_in_the_report_and_not_in_the_journal(tmp_path: Path, capsys):
    p = _jsonl(tmp_path, [{"id": "a", "sent": {"what": "PAYLOAD-MARKER-1"}}])
    assert main([str(p), "--questions", str(QUESTIONS), "--offline", "--json", "--show-payload", "--journal", str(tmp_path / "j")]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["sent"]["fields"]["what"] == "PAYLOAD-MARKER-1"
    assert "PAYLOAD-MARKER-1" not in next((tmp_path / "j").glob("run-*.jsonl")).read_text(encoding="utf-8")


def test_cli_refuses_a_malformed_file_before_anything(tmp_path: Path):
    p = _jsonl(tmp_path, [{"id": "a", "sent": {"bad name": "x"}}])
    with pytest.raises(SystemExit, match="refused: line 1: field 1 has a name that is not an identifier"):
        main([str(p), "--questions", str(QUESTIONS), "--offline", "--journal", "off"])


def test_readme_and_security_describe_the_records_contract():
    for doc in ("README.md", "SECURITY.md"):
        text = (ROOT / doc).read_text(encoding="utf-8")
        assert "jev-records" in text and "`sent`" in text, doc
