"""CARD needs a card shape as well as a Luhn pass. From the first live run of 0.4.0."""

from janitor.redact import card_shape_ok, luhn_ok, redact


def test_aws_account_id_plus_year_is_not_a_card():
    text = "see clients/example/audits/111122223333-2026-04-30-map.md"
    assert luhn_ok("111122223333-2026")  # it passes Luhn by coincidence, as one 16-digit run in ten does
    r = redact(text)
    assert r.text == text and r.hits == []  # 12-then-4 is not a card shape


def test_all_zero_bitmask_is_not_a_card():
    """CapEff: 0000000000000000 from the first live run: sixteen zeros pass Luhn (digit sum 0)
    and the contiguous shape rule. No payment card starts with 0."""
    text = "CapEff: 0000000000000000\nCapBnd: 000001ffffffffff"
    assert luhn_ok("0000000000000000")
    assert redact(text).text == text and not card_shape_ok(__import__("re").search(r"\d{16}", text))


def test_real_card_shapes_still_redact():
    for text in ("4111 1111 1111 1111", "4111-1111-1111-1111", "4111111111111111", "3782 822463 10005", "6011 1111 1111 1117", "5555 5555 5555 4444", "2223 0031 2200 3222"):
        r = redact(f"paid with {text} today")
        assert r.text == "paid with [CARD] today" and r.hits == ["CARD"], text


def test_wrong_grouping_or_bad_luhn_is_left_alone():
    for text in ("4111 11111111 1111", "411111111111 1111", "4111 1111 1111 1112", "1234 5678 9012 3456"):
        assert "[CARD]" not in redact(text).text, text
