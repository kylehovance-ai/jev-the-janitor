"""0.6.1: an SSN, a card and a phone number next to each other are each redacted whole.

Through 0.6.0 PHONE, CARD and SSN ran one after another, each on the previous one's output. In
`123-45-6789 4111 1111 1111 1111` CARD (which ran before SSN) found `6789 4111 1111 1111`, a valid
4-4-4-4 card across the two numbers, and the text went out as `123-45-[CARD] 1111`: five SSN
digits and the card's last four. Now every validated candidate of the three labels is found on
the same text first, and the redaction covers all of them (redact._redact_numbers).

The numbers are invented or documented test values: 4111 1111 1111 1111 and 5555 5555 5555 4444
are the networks' published test cards, 3782 822463 10005 is Amex's, 555 numbers are fictional,
and 123-45-6789 is the classic sample SSN.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from janitor.redact import redact

SSN, SSN2 = "123-45-6789", "987-65-4321"
CARD, CARD2, AMEX, CARD_RUN = "4111 1111 1111 1111", "5555 5555 5555 4444", "3782 822463 10005", "4111111111111111"
PHONE = "555-201-4477"
NL = chr(10)
LABEL = {SSN: "[SSN]", SSN2: "[SSN]", CARD: "[CARD]", CARD2: "[CARD]", AMEX: "[CARD]", CARD_RUN: "[CARD]", PHONE: "[PHONE]"}

PAIRS = [(SSN, CARD), (CARD, SSN), (SSN, PHONE), (PHONE, SSN), (CARD, PHONE), (PHONE, CARD),
         (CARD, CARD2), (AMEX, CARD), (CARD, AMEX), (SSN, CARD_RUN), (CARD_RUN, SSN), (SSN, SSN2)]
SEPARATORS = {"space": " ", "newline": "\n", "hyphen": "-"}

# Run together with no separator, two numbers are one longer token. Some still hold a phone shape,
# and that whole token is redacted; the rest match no label and are left as they are, as in 0.6.0.
# None comes out partly redacted, which three of them did through 0.6.0.
FUSED = {
    (SSN, CARD): None, (CARD, SSN): "[PHONE]", (SSN, PHONE): None, (PHONE, SSN): "[PHONE]",
    (CARD, PHONE): "[PHONE]", (PHONE, CARD): None, (CARD, CARD2): None, (AMEX, CARD): None,
    (CARD, AMEX): None, (SSN, CARD_RUN): None, (CARD_RUN, SSN): None, (SSN, SSN2): None,
}


def _digits_left(text: str) -> str:
    return "".join(re.findall(r"\d", text))


@pytest.mark.parametrize("sep", list(SEPARATORS), ids=list(SEPARATORS))
@pytest.mark.parametrize(("a", "b"), PAIRS, ids=[f"{LABEL[a][1:-1]}-{LABEL[b][1:-1]}" for a, b in PAIRS])
def test_two_numbers_with_a_separator_are_each_redacted_whole(a: str, b: str, sep: str):
    text = f"note {a}{SEPARATORS[sep]}{b} end"
    out = redact(text)
    assert out.text == f"note {LABEL[a]}{SEPARATORS[sep]}{LABEL[b]} end"
    assert _digits_left(out.text) == ""  # not one digit of either number leaves
    assert sorted(out.hits) == sorted({LABEL[a][1:-1], LABEL[b][1:-1]})


@pytest.mark.parametrize(("a", "b"), PAIRS, ids=[f"{LABEL[a][1:-1]}-{LABEL[b][1:-1]}" for a, b in PAIRS])
def test_two_numbers_run_together_are_never_partly_redacted(a: str, b: str):
    text = f"note {a}{b} end"
    out = redact(text).text
    expected = FUSED[(a, b)]
    assert out == (text if expected is None else f"note {expected} end")
    assert out == text or _digits_left(out) == ""  # whole or untouched, never a fragment


def test_the_reported_input_and_the_order_of_the_patterns_no_longer_matter():
    assert redact("123-45-6789 4111 1111 1111 1111").text == "[SSN] [CARD]"  # 0.6.0: "123-45-[CARD] 1111"
    assert redact("4111 1111 1111 1111 123-45-6789").text == "[CARD] [SSN]"
    assert redact("4111 1111 1111 1111-123-45-6789").text == "[CARD]-[SSN]"  # 0.6.0: the card's tail took `-123`, Luhn refused, the card left
    assert redact("555-201-4477123-45-6789").text == "[PHONE]"  # 0.6.0: "555-[PHONE]-45-6789"


def test_what_the_number_rules_already_kept_is_kept():
    assert redact("qty 2 4111 1111 1111 1111").text == "qty 2 [CARD]"  # a count before a card stays (test_redact_review_findings)
    assert redact("see clients/example/audits/111122223333-2026-04-30-map.md").text.endswith("111122223333-2026-04-30-map.md")
    assert redact("Order 555-201-4477").text == "Order 555-201-4477"  # an order number is not a phone
    assert redact("on 2026-09-24 at 18:08").text == "on 2026-09-24 at 18:08"
    assert redact("call 555-201-4477 2 times").text == "call [PHONE] 2 times"  # a space on each side: nothing widens



# 0.6.2: the one sentence docs/what-jev-sees.md, docs/privacy-contract.md and SECURITY.md use for the
# widen step (redact._redact_numbers). It says "can" on purpose: the step is not a complete rule, and
# a pre-release audit found ten false claims in a sentence that stated it as one.
WIDEN_SENTENCE = (
    'Next to a phone, card or SSN match, redaction can also take nearby digits: when a digit touches the match, '
    'directly or across a hyphen, the digits joined to it by a single hyphen or space, on either side, can be '
    'redacted with it, so a date, a count or an order number touching the match can go too (`555-201-4477-2026` '
    'becomes `[PHONE]`, and `qty 2 4111 1111 1111 1111-2026` becomes `qty [CARD]`). Two joiners in a row, such as '
    'two spaces or a space and a hyphen, end it (`555-201-4477-99  123` becomes `[PHONE]  123`). This errs toward '
    'privacy. A neighbouring phone, card or SSN usually keeps its own label (`555-201-4477-123-45-6789` becomes '
    '`[PHONE]-[SSN]`); when the two overlap, they can share one label, and every digit of both is still redacted '
    '(`4111 1111 1111 1111-003-45-6789` becomes `[CARD]`). A match with only spaces around it takes nothing (`qty '
    '2 4111 1111 1111 1111` becomes `qty 2 [CARD]`; `555-201-4477 2026` becomes `[PHONE] 2026`). Elsewhere, a '
    'number in a format no rule recognises, such as a nine-digit order number or a date standing alone, leaves as '
    'written.'
)
WIDEN_DOCS = ("docs/what-jev-sees.md", "docs/privacy-contract.md", "SECURITY.md")


def test_the_widen_sentence_is_in_each_doc_word_for_word():
    root = Path(__file__).resolve().parent.parent
    for rel in WIDEN_DOCS:
        # SECURITY.md wraps its list items with a two-space indent; undoing that keeps the sentence's double spaces
        flat = (root / rel).read_text(encoding="utf-8").replace(NL + "  ", " ")
        assert flat.count(WIDEN_SENTENCE) == 1, rel


def test_every_example_the_widen_sentence_quotes_is_what_redact_does():
    examples = re.findall(r"`([^`]+)` becomes `([^`]+)`", WIDEN_SENTENCE)
    assert len(examples) == 7  # round 3: one two-space case and one overlap case among them
    for before, after in examples:
        assert redact(before).text == after, before


@pytest.mark.parametrize(("text", "expected"), [
    # once a digit touches the match, widening runs both ways and across spaces (round 2 of the 0.6.2 audit)
    ("qty 2 4111 1111 1111 1111-2026", "qty [CARD]"),
    ("123456789 555-201-4477-99", "[PHONE]"),
    ("on 2026-11-15 123-45-6789-00", "on [SSN]"),
    ("2 555-201-4477-2026", "[PHONE]"),
    # a neighbouring phone, card or SSN keeps its own label
    ("555-201-4477-123-45-6789", "[PHONE]-[SSN]"),
    ("4111 1111 1111 1111-123-45-6789", "[CARD]-[SSN]"),
    # the joiner is a single hyphen or space: two in a row end it (round 3)
    ("555-201-4477-99  123", "[PHONE]  123"),
    ("99  2026-555-201-4477-1", "99  [PHONE]"),
    ("555-201-4477-2026 -11", "[PHONE] -11"),
    ("2026 -555-201-4477-99", "2026 -[PHONE]"),
    ("555-201-4477-2026--11", "[PHONE]--11"),
    ("11- 555-201-4477-2026", "11- [PHONE]"),
    # when two candidates overlap they can share one label, and every digit of both is still redacted (round 3);
    # 4111111111111111003 passes Luhn, so the card takes the -003 tail and the SSN or phone extends it
    ("4111 1111 1111 1111-003-45-6789", "[CARD]"),
    ("4111 1111 1111 1111-003-555-2014", "[CARD]"),
    ("5555 5555 5555 4444-018-45-6789", "[CARD]"),
    ("5555 5555 5555 4444-018-555-2014", "[CARD]"),
    # without an overlap the neighbour keeps its label
    ("5555 5555 5555 4444-004-45-6789", "[CARD]-[SSN]"),
    # spaces alone take nothing
    ("555-201-4477 2026", "[PHONE] 2026"),
    ("qty 2 4111 1111 1111 1111", "qty 2 [CARD]"),
    # a digit touching the match with no hyphen starts it too (redact: right_cut is `-?\d`, left_cut `\d-?$`)
    ("555-201-4477123-45-6789", "[PHONE]"),
    # more of the first round's cases, unchanged
    ("2026-11-15-123-45-6789", "[SSN]"),
    ("555-201-4477-19.99", "[PHONE].99"),
    ("4111 1111 1111 1111-99", "[CARD]"),
    ("555-201-4477 -2026", "[PHONE] -2026"),
    # no rule recognises these
    ("order 123456789 on 2026-11-15", "order 123456789 on 2026-11-15"),
])
def test_the_widen_step_as_the_docs_describe_it(text: str, expected: str):
    assert redact(text).text == expected


def test_an_overlap_shares_one_label_and_reports_both_hits():
    out = redact("4111 1111 1111 1111-003-45-6789")
    assert out.text == "[CARD]" and sorted(out.hits) == ["CARD", "SSN"]
    out = redact("4111 1111 1111 1111-003-555-2014")
    assert out.text == "[CARD]" and sorted(out.hits) == ["CARD", "PHONE"]


@pytest.mark.parametrize("card", [CARD, CARD2, AMEX], ids=["visa", "mastercard", "amex"])
def test_a_card_followed_by_any_three_digit_group_and_an_ssn_or_phone_leaves_no_digit(card: str):
    """Round 3: "every digit of both is still redacted", over every 000-999 group, whether or not the spans overlap."""
    for n in range(1000):
        for tail in (f"-{n:03d}-45-6789", f"-{n:03d}-555-2014", f"-{n:03d}-201-4477"):
            assert _digits_left(redact(card + tail).text) == "", card + tail
