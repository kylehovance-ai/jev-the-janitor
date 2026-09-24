"""Redactor findings from an outside review of 0.4.6, each reproduced before it was fixed.

Every credential-shaped string here is assembled at runtime from pieces, so no line of this
file is a literal a push-protection scanner would block. Escapes are built with chr(92) so a
test of a literal backslash is not a test of a real newline.
"""

from __future__ import annotations

import pytest

from janitor.policy import HIGH_PRECISION_SECRETS
from janitor.redact import MIN_DENYLIST_CHARS, denylist_patterns, redact

BS = chr(92)
NL = chr(10)


def j(*parts: str) -> str:
    return "".join(parts)


GHP = j("gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
JWT = "eyJ" + "a" * 20 + ".eyJ" + "b" * 20 + "." + "c" * 20
AWS_SECRET = j("wJalrXUtnFEMI", "/K7MDENG/bPxRfiCYEXAMPLEKEY")


def _gone(secret: str, text: str) -> None:
    for i in range(0, len(secret) - 8):
        assert secret[i:i + 8] not in text, secret[i:i + 8]


# --- finding 5: the denylist across whitespace, in its own redacted form, and short entries ----

@pytest.mark.parametrize("text", ["Jane Doe", "Jane  Doe", "Jane" + NL + "Doe", "Jane" + NL + "  Doe", "jane doe"])
def test_a_multi_word_entry_matches_across_any_run_of_whitespace(text: str):
    """Hard-wrapped markdown puts the surname on the next line. Through 0.4.6 only the exact
    spacing matched."""
    result = redact(f"met {text} today", ["Jane Doe"])
    assert result.text == "met [NAME] today" and result.hits == ["NAME"]


def test_an_entry_holding_an_email_still_matches_after_email_has_run():
    """The patterns run first, so `Jane Doe <jane@x.com>` in the text is already
    `Jane Doe <[EMAIL]>` when the denylist looks; the entry is matched in that form too."""
    result = redact("cc Jane Doe <jane@example.com> and Bob", ["Jane Doe <jane@example.com>"])
    assert result.text == "cc [NAME] and Bob"
    assert result.hits == ["EMAIL", "NAME"]
    # An entry that is nothing but an email is not turned into a match on every [EMAIL] token.
    assert redact("write to bob@example.com", ["jane@example.com"]).text == "write to [EMAIL]"


def test_entries_under_three_characters_are_ignored_and_the_limit_is_named():
    assert MIN_DENYLIST_CHARS == 3
    assert denylist_patterns("Al") == () and denylist_patterns(" Al ") == ()
    assert redact("Al is here", ["Al"]).hits == []
    assert redact("Ann is here", ["Ann"]).text == "[NAME] is here"


def test_load_denylist_says_which_entries_are_ignored(tmp_path, capsys):
    from janitor.cli import load_denylist

    p = tmp_path / "deny.txt"
    p.write_text("# comment\nJane Doe\nAl\n\nJo\n", encoding="utf-8")
    assert load_denylist(p) == ["Jane Doe", "Al", "Jo"]
    err = capsys.readouterr().err
    assert "2 entries under 3 characters ignored" in err and "'Al'" in err and "'Jo'" in err
    p.write_text("Jane Doe\n", encoding="utf-8")
    load_denylist(p)
    assert capsys.readouterr().err == ""


def test_denylist_patterns_are_compiled_once_per_entry():
    assert denylist_patterns("Jane Doe") is denylist_patterns("Jane Doe")


# --- finding 6: temporary AWS key ids ---------------------------------------------------------

def test_a_temporary_asia_key_id_is_a_key():
    asia = j("AS", "IA", "IOSFODNN7EXAMPLE")
    result = redact('"AccessKeyId": "' + asia + '"')
    assert result.text == '"AccessKeyId": "[KEY]"' and result.hits == ["KEY"]


# --- finding 7 and 10: PGP blocks, and a block with no END line -------------------------------

def test_a_pgp_private_key_block_is_pem():
    block = "-----BEGIN PGP PRIVATE KEY BLOCK-----" + NL + "lQ" + "a" * 60 + NL + "-----END PGP PRIVATE KEY BLOCK-----"
    result = redact("key:" + NL + block + NL + "after")
    assert result.text == "key:" + NL + "[PEM]" + NL + "after" and "PEM" in HIGH_PRECISION_SECRETS


def test_an_unterminated_private_key_is_taken_to_the_first_blank_line():
    body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"
    text = "-----BEGIN OPENSSH PRIVATE KEY-----" + NL + body + NL + body + NL + NL + "prose after the key"
    result = redact(text)
    assert result.text == "[PEM]" + NL + NL + "prose after the key" and result.hits == ["PEM"]
    # No blank line: the block runs to the end of the text.
    assert redact("-----BEGIN RSA PRIVATE KEY-----" + NL + body).text == "[PEM]"
    # A one-line paste with the material after the header.
    assert redact("-----BEGIN RSA PRIVATE KEY----- " + body).text == "[PEM]"


def test_a_terminated_block_still_ends_at_its_end_line():
    text = "-----BEGIN RSA PRIVATE KEY-----" + NL + "abc" + NL + "-----END RSA PRIVATE KEY-----" + NL + "kept line"
    assert redact(text).text == "[PEM]" + NL + "kept line"


# --- finding 8: a key after a JSON escape, a percent-encoded byte, or an underscore -----------

@pytest.mark.parametrize("prefix", ["x" + BS + "n", BS + "t", BS + "r", "%3D", "%2f", '"', "=", ":", " "])
def test_a_key_is_taken_after_json_escapes_and_percent_encoding(prefix: str):
    result = redact(prefix + GHP + " end")
    assert result.text == prefix + "[KEY] end", prefix
    assert "KEY" in result.hits


def test_a_jwt_after_an_underscore_or_an_escape_is_taken():
    for prefix in ("token_", BS + "n", "%3D", "="):
        result = redact(prefix + JWT)
        assert result.text == prefix + "[JWT]", prefix


def test_a_key_glued_to_a_word_is_still_not_the_format():
    """The widened boundary allows an escape or a percent-encoded byte before a key, not a
    letter: `xghp_...` is not a GitHub token, and the ARN case the Telegram shape excludes
    still holds."""
    assert redact("x" + GHP).hits == []
    assert redact("an" + GHP).hits == []  # `n` after a letter is not an escape
    arn = "arn:aws:sns:us-east-1:" + "123456789012" + ":" + "data-inbound-snapshot-topic-x01"
    assert "KEY" not in redact(arn).hits


# --- finding 9: padded spacing around the AWS secret ------------------------------------------

@pytest.mark.parametrize("line", [
    "aws_secret_access_key   =   {s}",
    "aws_secret_access_key = {s}",
    "AWS_SECRET_ACCESS_KEY={s}",
    'aws_secret_key:   "{s}"',
    "aws secret access key :  {s}",
])
def test_the_aws_secret_is_taken_whatever_the_spacing(line: str):
    result = redact(line.format(s=AWS_SECRET))
    assert "AWS_SECRET" in result.hits, line
    _gone(AWS_SECRET, result.text)


# --- finding 11: a card after a leading digit group -------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("qty 2 4111 1111 1111 1111", "qty 2 [CARD]"),
    ("2026 4111-1111-1111-1111", "2026 [CARD]"),
    ("card 4111111111111111 ok", "card [CARD] ok"),
    ("amex 3782 822463 10005", "amex [CARD]"),
    ("4111 1111 1111 1111 2026", "[CARD] 2026"),
])
def test_a_card_after_a_count_or_a_year_is_still_found(text: str, expected: str):
    assert redact(text).text == expected


@pytest.mark.parametrize("text", [
    "111122223333-2026",  # 12-digit account id then a year: not a card shape
    "CapEff: 0000000000000000",  # a leading 0 is never a card
    "1695400000123",  # a millisecond timestamp starting with 1
])
def test_the_card_exclusions_of_0_4_0_still_hold(text: str):
    assert "CARD" not in redact(text).hits, text


# --- finding 12: ordinary words are not identifier markers; a leading plus is a phone ----------

@pytest.mark.parametrize("text", [
    "in case: 555-123-4567",
    "call my cell, id 555 123 4567",
    "the part 555-123-4567 is mine",
    "call 555-123-4567",
])
def test_case_id_and_part_no_longer_hide_a_phone_number(text: str):
    assert redact(text).hits == ["PHONE"], text


@pytest.mark.parametrize("text", [
    "Order 555-123-4567",
    "invoice #555-123-4567",
    "case #555-123-4567",
    "id number 555 123 4567",
    "part no. 555-123-4567",
    "ref: 555-123-4567",
])
def test_an_identifier_after_an_explicit_marker_is_not_a_phone(text: str):
    assert redact(text).hits == [], text


@pytest.mark.parametrize("text,expected", [
    ("+44 20 7946 0958", "[PHONE]"),
    ("+49 30 901820", "[PHONE]"),
    ("+1 (555) 123-4567", "[PHONE]"),
    ("call +61.2.9374.4000 now", "call [PHONE] now"),
])
def test_a_number_with_a_leading_plus_and_country_code_is_a_phone(text: str, expected: str):
    assert redact(text).text == expected


@pytest.mark.parametrize("text", [
    "2026-09-24",  # a date
    "temperature +44 today",  # too short
    "x = a+123456789",  # glued to a letter
    "version 2+3456",
])
def test_no_bare_digit_international_shape_is_attempted(text: str):
    assert "PHONE" not in redact(text).hits, text


# --- finding 14: with --no-local-triage a credential hit still quarantines, and nothing of the
# token travels: the text after a slash is not part of a format that has no slash. ---------------

def test_no_local_triage_still_quarantines_a_credential_hit_and_sends_only_the_token(tmp_path):
    from janitor.client import FixtureClient
    from janitor.scan import scan_vault

    class Recording(FixtureClient):
        def __init__(self):
            self.states = []

        def vote(self, state, questions):
            self.states.append(state)
            return super().vote(state, questions)

    whsec = j("wh", "sec_", "AbCdEfGhIjKlMnOpQrStUvWx")
    (tmp_path / "a.md").write_text("# T" + NL + NL + whsec + "/tail+XYZ" + NL, encoding="utf-8")
    rec = Recording()
    rows = scan_vault(tmp_path, client=rec, offline=True, local_triage=False)
    [state] = rec.states  # sent, because local triage is off
    assert state["excerpt"] == "# T" + NL + NL + "[KEY]/tail+XYZ"
    _gone(whsec, state["excerpt"])
    assert rows[0]["action"] == "quarantine" and rows[0]["quarantine_triggers"] == ["local:KEY"]
