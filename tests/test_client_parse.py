"""The live parser must read the SDK's ``answers`` dict and fail loudly on mismatch."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from janitor.client import vote_from_response

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "jev_response.json"


def _stub(answers: dict, model: str = "jev-1.13", input_tokens: int = 123):
    return SimpleNamespace(answers=answers, model=model, usage=SimpleNamespace(input_tokens=input_tokens))


def _full_answers():
    return {
        "bucket": SimpleNamespace(type="choice", choice="code_note", confidence=0.71,
                                  probabilities={"code_note": 0.71, "reference": 0.2}),
        "persist": SimpleNamespace(type="score", score=1.4, confidence=0.6),
        "contains_secret": SimpleNamespace(type="noul", noul=0.05),
        "looks_like_duplicate": SimpleNamespace(type="noul", noul=0.1),
        "records_a_decision": SimpleNamespace(type="noul", noul=0.3),
        "is_actionable": SimpleNamespace(type="noul", noul=0.6),
        "safe_to_leave_in_git": SimpleNamespace(type="noul", noul=0.8),
    }


def test_parse_reads_answers_by_name():
    vote = vote_from_response(_stub(_full_answers()))
    assert vote.bucket == "code_note"
    assert vote.bucket_confidence == pytest.approx(0.71)
    assert vote.persist == pytest.approx(1.4)
    assert vote.contains_secret == pytest.approx(0.05)
    assert vote.model == "jev-1.13"
    assert vote.input_tokens == 123


def test_parse_fails_loudly_on_missing_answer():
    answers = _full_answers()
    del answers["persist"]
    with pytest.raises(ValueError, match="missing answers for: persist"):
        vote_from_response(_stub(answers))


def test_parse_fails_loudly_on_wrong_type():
    answers = _full_answers()
    answers["bucket"] = SimpleNamespace(type="noul", noul=0.5)
    with pytest.raises(ValueError, match="expected 'choice'"):
        vote_from_response(_stub(answers))


@pytest.mark.skipif(not FIXTURE.exists(), reason="no recorded live response yet")
def test_parse_recorded_live_response():
    """Round-trip a real recorded response through the SDK's own model, then the parser."""
    typesafe_sdk = pytest.importorskip("typesafe_sdk")
    from typesafe_sdk._core.response_types import SystemOneResponse  # noqa: PLC0415

    text = FIXTURE.read_text(encoding="utf-8")
    raw = json.loads(text)
    # The SDK decodes from JSON text, not dicts: strict mode only coerces "0" -> 0 legend keys there.
    response = SystemOneResponse.model_validate_json(text)
    vote = vote_from_response(response)
    assert vote.bucket in raw["answers"]["bucket"]["probabilities"]
    assert 0.0 <= vote.contains_secret <= 1.0
    assert vote.model == raw["model"]
