"""A token-shaped filename leaks nowhere, AWS secrets are taken without an `aws` prefix, an
Obsidian or callback URL is not a credential, and the docs' label lists match the code.

Each of these was found by an outside review of 0.4.7's first cut, before it shipped.

Every credential-shaped string is assembled at runtime from pieces.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from janitor.client import FixtureClient
from janitor.frontmatter import note_title
from janitor.policy import HIGH_PRECISION_SECRETS
from janitor.redact import redact
from janitor.scan import scan_vault

ROOT = Path(__file__).resolve().parent.parent


def j(*parts: str) -> str:
    return "".join(parts)


GHP = j("gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
GLPAT = j("gl", "pat-", "AbCdEfGhIjKlMnOpQrSt")
AWS_SECRET = j("wJalrXUtnFEMI", "/K7MDENG/bPxRfiCYEXAMPLEKEY")
SESSION = j("FwoGZXIvYXdzE", "A" * 40, "b" * 40)


class Recording(FixtureClient):
    def __init__(self) -> None:
        self.states: list[dict] = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


def _no_fragment(secret: str, text: str) -> None:
    for i in range(0, len(secret) - 8):
        assert secret[i:i + 8] not in text, secret[i:i + 8]


# --- a token-shaped filename with no title and no H1 -----------------------------------------

def test_the_filename_fallback_keeps_a_credential_shaped_stem_whole(tmp_path: Path):
    assert note_title(tmp_path / f"{GHP}.md", {}, "body") == GHP  # not `ghp <36>`
    assert note_title(tmp_path / f"notes_{GLPAT}.md", {}, "body") == f"notes_{GLPAT}"
    assert note_title(tmp_path / "weekly_plan-2026.md", {}, "body") == "weekly plan 2026"  # unchanged for ordinary stems
    assert note_title(tmp_path / f"{GHP}.md", {"title": "Given"}, "body") == "Given"


@pytest.mark.parametrize("local_triage", [True, False])
def test_a_token_filename_leaks_nowhere_in_a_default_run(tmp_path: Path, local_triage: bool):
    """No frontmatter title, no H1. The note quarantines on its own path hit; its title must
    not go out as a sibling title of the four other notes in the folder, and without local
    triage its own sent title must be the token, not the token split into words."""
    (tmp_path / f"{GHP}.md").write_text("no title, body only\n", encoding="utf-8")
    for i in range(4):
        (tmp_path / f"n{i}.md").write_text(f"# Note {i}\n\nordinary body {i}\n", encoding="utf-8")
    rec = Recording()
    rows = scan_vault(tmp_path, client=rec, offline=True, local_triage=local_triage)
    blob = json.dumps(rec.states)
    _no_fragment(GHP, blob)
    assert "ghp " not in blob
    for state in rec.states:
        if state["path"] != "[KEY].md":
            assert state["other_note_titles"] == [f"Note {k}" for k in range(4) if f"Note {k}" != state["title"]]
    token_row = next(r for r in rows if r["path"] == f"{GHP}.md")  # the row's path is local, raw
    assert token_row["action"] == "quarantine" and "KEY" in token_row["redacted_own"]
    if not local_triage:
        own = next(s for s in rec.states if s["path"] == "[KEY].md")
        assert own["title"] == "[KEY]"


def test_a_note_whose_title_holds_a_credential_is_never_a_sibling_even_for_a_single_file(tmp_path: Path):
    (tmp_path / "leak.md").write_text(f"# token {GHP}\n\nbody\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("# B\n\nbody b\n", encoding="utf-8")
    rec = Recording()
    scan_vault(tmp_path / "b.md", client=rec, offline=True)
    [state] = rec.states
    assert state["other_note_titles"] == []


# --- AWS secrets and session tokens named without `aws` --------------------------------------

@pytest.mark.parametrize("line", [
    '"SecretAccessKey": "{s}"',
    "SecretAccessKey: {s}",
    "secret_access_key = {s}",
    "secret-access-key={s}",
    'SECRET_ACCESS_KEY="{s}"',
])
def test_a_secret_access_key_named_without_aws_is_an_aws_secret(line: str):
    result = redact(line.format(s=AWS_SECRET))
    assert "AWS_SECRET" in result.hits, line
    _no_fragment(AWS_SECRET, result.text)


@pytest.mark.parametrize("line", ['"SessionToken": "{s}"', "aws_session_token = {s}", "session_token: {s}"])
def test_a_session_token_is_an_aws_secret(line: str):
    result = redact(line.format(s=SESSION))
    assert "AWS_SECRET" in result.hits, line
    _no_fragment(SESSION, result.text)


def test_assume_role_output_is_held_whole_without_local_triage(tmp_path: Path):
    asia = j("AS", "IA", "IOSFODNN7EXAMPLE")
    body = json.dumps({"Credentials": {"AccessKeyId": asia, "SecretAccessKey": AWS_SECRET, "SessionToken": SESSION}}, indent=2)
    (tmp_path / "creds.md").write_text("# Creds\n\n" + body + "\n", encoding="utf-8")
    rec = Recording()
    rows = scan_vault(tmp_path, client=rec, offline=True, local_triage=False)
    [state] = rec.states
    _no_fragment(AWS_SECRET, state["excerpt"])
    _no_fragment(SESSION, state["excerpt"])
    assert asia not in state["excerpt"]
    assert rows[0]["action"] == "quarantine"


def test_ordinary_prose_about_session_tokens_is_not_a_secret():
    assert redact("rotate the session token every hour; the secret access key lives in the vault").hits == []


# --- Obsidian and callback URLs, templated ports, short numeric passwords --------------------

@pytest.mark.parametrize("text", [
    "obsidian://open?vault=Main:Notes@home",
    "obsidian://open?vault=Main&file=Meetings%2F1:1%20with%20a@b",
    "x-callback-url://run?name=a:b@c",
    "http://localhost:${PORT}/api/users/@me",
    "http://localhost:$PORT/api/users/@me",
    "http://localhost:%PORT%/api/users/@me",
    "https://example.com/#/path:with@at",
])
def test_urls_whose_at_sign_follows_a_query_fragment_or_templated_port_are_not_credentials(text: str):
    result = redact(text)
    assert "URL_CREDENTIAL" not in result.hits, (text, result)


@pytest.mark.parametrize("scheme,user,digits,rest", [
    ("mysql://", "root", "1234", "localhost:3306/db"),
    ("redis://", "", "4242", "10.0.0.5:6379"),
    ("postgres://", "admin", "12345", "db.example.com/x"),
    ("mysql://", "root", "123456", "localhost"),
    ("http://", "localhost", "8080", "evil.example.com/"),  # the phishing shape: a credential on purpose
])
def test_digits_that_run_straight_into_the_at_sign_are_a_password_not_a_port(scheme: str, user: str, digits: str, rest: str):
    """0.4.7's first cut read a one-to-five-digit password as a port (`root:1234@`,
    `admin:12345@`, the weak defaults dev notes hold), which would have sent it or let EMAIL
    half-take it on a dotted host. A port is a port only when a path, query or fragment
    follows it. (Assembled at runtime so the tree-scan test does not flag this file.)"""
    result = redact(scheme + user + ":" + digits + "@" + rest)
    assert result.text == scheme + "[URL_CREDENTIAL]@" + rest and result.hits == ["URL_CREDENTIAL"], (scheme, user, digits)


def test_a_real_password_still_wins_next_to_those_shapes():
    pw = j("Zq7", "?vR", "9x")
    for text in ("postgres://app:" + pw + "@localhost/db", "http://user:" + pw + "#1@host.example.com/x?y=1"):
        result = redact(text)
        assert result.hits == ["URL_CREDENTIAL"], text
        assert "Zq7" not in result.text


# --- every doc list of quarantining labels equals HIGH_PRECISION_SECRETS ---------------------

LABEL = r"`\[?[A-Z_]+\]?`"
LABEL_LIST = re.compile(LABEL + r"(?:,?\s+(?:and\s+|or\s+)?" + LABEL + r")+")
SOFT = {"EMAIL", "PHONE", "CARD", "SSN", "NAME"}


def _label_lists(text: str) -> list[tuple[str, set[str]]]:
    """Every run of two or more backticked labels, across line breaks, that holds KEY and PEM
    and no soft label: those are the lists that claim to name what quarantines."""
    found = []
    for m in LABEL_LIST.finditer(text):
        labels = set(re.findall(r"`\[?([A-Z_]+)\]?`", m.group(0)))
        if "KEY" in labels and "PEM" in labels and not labels & SOFT:
            found.append((m.group(0), labels))
    return found


@pytest.mark.parametrize("doc", ["README.md", "SECURITY.md", "POLICY.md"])
def test_every_documented_list_of_quarantining_labels_matches_the_code(doc: str):
    """The next label added to HIGH_PRECISION_SECRETS must appear in every list the docs give,
    or this fails and names the stale sentence. Lists are recognised as a parenthesised run of
    backticked labels that includes KEY and PEM; a colon-introduced list is checked by hand."""
    text = (ROOT / doc).read_text(encoding="utf-8")
    lists = _label_lists(text)
    assert lists, (doc, "no quarantining-label list recognised; did the wording change?")
    for sentence, labels in lists:
        assert labels == set(HIGH_PRECISION_SECRETS), (doc, sentence, labels ^ set(HIGH_PRECISION_SECRETS))
    # The lists that are not parenthesised, pinned as substrings:
    for label in HIGH_PRECISION_SECRETS:
        assert f"`{label}`" in text or f"`[{label}]`" in text, (doc, label)
