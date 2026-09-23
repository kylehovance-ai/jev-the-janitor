"""v0.1.2: redact the body before cutting to the cap, and require Luhn for [CARD].

In 0.1.1 the excerpt was cut to 1,200 characters and then redacted, so a secret that
straddled the cap left as a partial string with no token. And any 13 to 19 digit run
became [CARD], including millisecond timestamps and ISBNs.
"""

import json
from pathlib import Path

from janitor.client import FixtureClient
from janitor.frontmatter import MAX_EXCERPT
from janitor.redact import luhn_ok, redact
from janitor.scan import scan_vault


class Recording(FixtureClient):
    def __init__(self):
        self.states = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


def test_secret_straddling_the_cap_is_redacted_not_truncated(tmp_path: Path):
    key = "sk-abcdefghijklmnopqrstuvwxyz012345"
    body = "# T\n\n" + ("x" * (MAX_EXCERPT - 11)) + " " + key + " rest of the note\n"  # key starts inside the cap and crosses it
    (tmp_path / "k.md").write_text(body, encoding="utf-8")
    rec = Recording()
    # local_triage=False: with triage on, the KEY hit quarantines locally and nothing is sent. This
    # test is about the excerpt that would leave, which --show-payload still shows.
    scan_vault(tmp_path, client=rec, offline=True, local_triage=False)
    excerpt = rec.states[0]["excerpt"]
    assert len(excerpt) <= MAX_EXCERPT
    assert "sk-" not in excerpt
    assert "[KEY]" in excerpt
    assert "KEY" in {h for r in scan_vault(tmp_path, offline=True) for h in r["redacted"]}


def test_excerpt_is_first_N_chars_of_redacted_text(tmp_path: Path):
    # Email early in the body shrinks to a token, so more of the tail fits under the cap.
    body = "# T\n\nwrite to someone.important@example.com about it\n" + ("y" * (MAX_EXCERPT + 200)) + "\n"
    (tmp_path / "e.md").write_text(body, encoding="utf-8")
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True)
    excerpt = rec.states[0]["excerpt"]
    assert excerpt.startswith("# T\n\nwrite to [EMAIL] about it")
    assert len(excerpt) == MAX_EXCERPT
    assert "example.com" not in json.dumps(rec.states)


def test_nothing_past_the_cap_leaves_after_redaction_either(tmp_path: Path):
    body = "# T\n\n" + ("z" * (MAX_EXCERPT + 200)) + "BELOW-THE-CAP-SENTINEL\n"
    (tmp_path / "z.md").write_text(body, encoding="utf-8")
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True)
    assert "BELOW-THE-CAP-SENTINEL" not in json.dumps(rec.states)


def test_luhn():
    assert luhn_ok("4111 1111 1111 1111")
    assert luhn_ok("378282246310005")
    assert not luhn_ok("1726700000000")  # epoch milliseconds
    assert not luhn_ok("9780306406157")  # ISBN-13
    assert not luhn_ok("123")


def test_card_requires_luhn():
    assert redact("card 4111 1111 1111 1111 on file").text == "card [CARD] on file"
    assert redact("amex 378282246310005 on file").text == "amex [CARD] on file"
    r = redact("epoch ms 1726700000000 logged; ISBN 9780306406157")
    assert r.text == "epoch ms 1726700000000 logged; ISBN 9780306406157"
    assert "CARD" not in r.hits


def test_other_patterns_unaffected_by_validator_change():
    r = redact("mail ops@example.com, ssn 123-45-6789, key sk-abcdefghijklmnopqrstuvwxyz012345")
    assert r.text == "mail [EMAIL], ssn [SSN], key [KEY]"
    assert r.hits == ["EMAIL", "KEY", "SSN"]
