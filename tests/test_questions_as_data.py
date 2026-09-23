"""Every word Jev is asked is in the taxonomy file, and the fingerprint covers all of it.

Through 0.4.2 the Choice and Score instruction sentences were Python strings in schema.py:
outside the fingerprint stamped on every vote, guarded only by the test-time source digest.
Since 0.4.3 the file holds a whole question set and ``question_payloads`` builds the wire
form from it. The wording did not change, and the wire did not change: measured on every
note of a synthetic test corpus before and after, the state plus the serialized questions were
byte-identical (192 notes, 2026-09-22). These tests keep those properties.
"""

from pathlib import Path

import pytest
import yaml

from janitor.journal import canonical
from janitor.schema import (
    DEFAULT_TAXONOMY,
    LEGACY_INSTRUCTIONS,
    REQUIRED_NOULS,
    buckets,
    load_question_set,
    load_taxonomy,
    nouls,
    persist_levels,
    question_payloads,
    taxonomy_fingerprint,
)


def test_every_instruction_sentence_is_in_the_file_not_in_python():
    raw = yaml.safe_load(DEFAULT_TAXONOMY.read_text(encoding="utf-8"))
    for name, q in raw["questions"].items():
        assert q["instructions"].strip(), name
    # The two sentences that used to live in Python are in the file, byte for byte.
    assert raw["questions"]["bucket"]["instructions"] == LEGACY_INSTRUCTIONS["bucket"]
    assert raw["questions"]["persist"]["instructions"] == LEGACY_INSTRUCTIONS["persist"]


def test_fingerprint_covers_the_instruction_sentences(tmp_path: Path):
    """Editing an instruction sentence, and nothing else, changes the fingerprint. It did not before."""
    edited = tmp_path / "t.yaml"
    text = DEFAULT_TAXONOMY.read_text(encoding="utf-8")
    assert "Judge the note itself" in text
    edited.write_text(text.replace("Judge the note itself", "Judge the note body"), encoding="utf-8")
    assert taxonomy_fingerprint(edited) != taxonomy_fingerprint()
    assert question_payloads(load_taxonomy(edited))["bucket"]["instructions"] != question_payloads(load_taxonomy())["bucket"]["instructions"]


def test_payloads_are_in_file_order_and_carry_the_wire_shape():
    payloads = question_payloads(load_taxonomy())
    assert list(payloads) == ["bucket", "persist", *REQUIRED_NOULS]
    assert payloads["bucket"]["type"] == "choice" and set(payloads["bucket"]["criteria"]) == set(buckets(load_taxonomy()))
    assert payloads["persist"]["type"] == "score" and payloads["persist"]["criteria"] == persist_levels(load_taxonomy())
    for name in REQUIRED_NOULS:
        assert payloads[name] == {"type": "noul", "instructions": nouls(load_taxonomy())[name]}


def test_payloads_equal_what_the_sdk_serializes():
    pytest.importorskip("typesafe_sdk")
    from janitor.schema import build_questions

    tax = load_taxonomy()
    dumped = {name: q.model_dump() for name, q in build_questions(tax).items()}
    assert canonical(dumped) == canonical(question_payloads(tax))


def test_a_legacy_layout_file_produces_the_identical_wire(tmp_path: Path):
    """A custom taxonomy written against 0.4.x keeps working and sends exactly what it did."""
    raw = yaml.safe_load(DEFAULT_TAXONOMY.read_text(encoding="utf-8"))["questions"]
    legacy = {
        "buckets": raw["bucket"]["options"],
        "persist": raw["persist"]["levels"],
        "nouls": {n: raw[n]["instructions"] for n in REQUIRED_NOULS},
    }
    p = tmp_path / "old.yaml"
    p.write_text(yaml.safe_dump(legacy, allow_unicode=True, sort_keys=False), encoding="utf-8")
    assert canonical(question_payloads(load_taxonomy(p))) == canonical(question_payloads(load_taxonomy()))
    assert taxonomy_fingerprint(p) != taxonomy_fingerprint()  # a different file is a different fingerprint


def test_a_question_set_can_be_something_other_than_the_vault_scan(tmp_path: Path):
    """The format describes any question set: another caller's Choice, Scores and Nouls."""
    p = tmp_path / "gate.yaml"
    p.write_text(yaml.safe_dump({"questions": {
        "lane": {"type": "choice", "instructions": "Which lane?", "options": {"build": "Make it.", "park": "Later."}},
        "urgency": {"type": "score", "instructions": "How urgent?", "levels": ["low", "high"]},
        "has_revenue": {"type": "noul", "instructions": "Does it mention money?"},
    }}, sort_keys=False), encoding="utf-8")
    payloads = question_payloads(load_question_set(p))
    assert list(payloads) == ["lane", "urgency", "has_revenue"]
    assert payloads["lane"]["criteria"] == {"build": "Make it.", "park": "Later."}
    with pytest.raises(ValueError, match="choice named 'bucket'"):
        load_taxonomy(p)  # the vault scan needs its own questions


@pytest.mark.parametrize("bad,match", [
    ({"questions": {"q": {"type": "guess", "instructions": "x"}}}, "needs a type"),
    ({"questions": {"q": {"type": "noul"}}}, "needs instructions"),
    ({"questions": {"q": {"type": "choice", "instructions": "x", "options": {}}}}, "mapping of options"),
    ({"questions": {"q": {"type": "score", "instructions": "x", "levels": ["one"]}}}, "at least two levels"),
    ({"questions": {}}, "needs a 'questions' mapping"),
])
def test_malformed_question_sets_are_refused_before_any_request(tmp_path: Path, bad, match):
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(bad, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match=match):
        load_question_set(p)
