"""Outside review findings 10b and 10c: the denylist matches whole words, and PHONE leaves order numbers alone."""

from janitor.redact import redact


def test_denylist_matches_whole_words_only():
    r = redact("Anniversary party for Ann and Annabel; call ann tomorrow (Ann's idea).", denylist=["Ann"])
    assert r.text == "Anniversary party for [NAME] and Annabel; call [NAME] tomorrow ([NAME]'s idea)."
    assert r.hits == ["NAME"]
    assert redact("Annie and Joanna", denylist=["Ann"]).text == "Annie and Joanna"
    assert redact("Rowan Hovance-Smith met Rowan.", denylist=["Rowan"]).text == "[NAME] Hovance-Smith met [NAME]."
    assert redact("see O'Brien!", denylist=["O'Brien"]).text == "see [NAME]!"  # punctuation inside a name still works


def test_phone_shaped_identifiers_after_order_words_are_not_phones():
    keep = [
        "Order 123-456-7890 shipped",
        "invoice #555-123-4567 is due",
        "Ticket no. 555.123.4567 closed",
        "ref: 555 123 4567",
        "tracking 555-123-4567",
    ]
    for text in keep:
        r = redact(text)
        assert "[PHONE]" not in r.text and r.hits == [], text
    redacted = [
        "call 555-123-4567 tomorrow",
        "Order placed; call 555-123-4567 with questions",
        "mobile (555) 123-4567",
    ]
    for text in redacted:
        assert "[PHONE]" in redact(text).text, text
