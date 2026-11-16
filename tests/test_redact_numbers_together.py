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

import pytest

from janitor.redact import redact

SSN, SSN2 = "123-45-6789", "987-65-4321"
CARD, CARD2, AMEX, CARD_RUN = "4111 1111 1111 1111", "5555 5555 5555 4444", "3782 822463 10005", "4111111111111111"
PHONE = "555-201-4477"
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
