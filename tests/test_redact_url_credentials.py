"""A password inside a URL is redacted whole, before EMAIL can half-take it, and quarantines.

Measured on 0.4.6 with a synthetic password assembled at runtime (written ``<pw>`` here, which
the rule itself reads as a placeholder): ``postgres://app:<pw>@localhost``, ``redis://:<pw>@127.0.0.1``,
``jdbc:mysql://app:<pw>@10.0.0.5`` and ``DATABASE_URL=postgres://…`` went out in the clear with
no hit at all. ``postgresql://app:<pw>@db.example.com`` was masked by accident: EMAIL took
``<pw>@db.example.com``, the user was still sent, the row read hits=['EMAIL'], and EMAIL does
not quarantine. The same accident for ``mongodb+srv://`` and ``https://user:<pw>@host``. The one real credential a gate scan found in a real vault was a
localhost database password in exactly this shape.

Every password here is assembled at runtime from pieces, so no line of this file is a
credential-shaped literal to a push-protection scanner.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from janitor.client import FixtureClient
from janitor.policy import HIGH_PRECISION_SECRETS
from janitor.redact import PATTERNS, redact
from janitor.scan import scan_vault


def j(*parts: str) -> str:
    return "".join(parts)


PW = j("Zq7", "vR9", "pLx", "2")
TRICKY = j("p@ss", ":w0", "rd@", "x")  # unencoded @ and : inside the password, and it ends in @x


def _no_fragment(secret: str, text: str, ctx: object) -> None:
    for i in range(0, max(1, len(secret) - 3)):
        assert secret[i:i + 4] not in text, (ctx, secret[i:i + 4])


LEAKED_THROUGH_046 = {
    # name: (text with {pw}, expected redacted text)
    "postgres localhost with port": ("postgres://app:{pw}@localhost:5432/db", "postgres://[URL_CREDENTIAL]@localhost:5432/db"),
    "redis, no user": ("redis://:{pw}@127.0.0.1:6379/0", "redis://[URL_CREDENTIAL]@127.0.0.1:6379/0"),
    "jdbc two-part scheme": ("jdbc:mysql://app:{pw}@10.0.0.5:3306/db", "jdbc:mysql://[URL_CREDENTIAL]@10.0.0.5:3306/db"),
    "env assignment": ("DATABASE_URL=postgres://app:{pw}@localhost/db", "DATABASE_URL=postgres://[URL_CREDENTIAL]@localhost/db"),
    "sqlalchemy driver suffix, ipv6 host": ("postgresql+psycopg2://app:{pw}@[::1]:5432/db", "postgresql+psycopg2://[URL_CREDENTIAL]@[::1]:5432/db"),
    "amqp": ("amqp://app:{pw}@localhost:5672/", "amqp://[URL_CREDENTIAL]@localhost:5672/"),
    "quoted in code": ("url = 'mysql://app:{pw}@localhost/db'", "url = 'mysql://[URL_CREDENTIAL]@localhost/db'"),
    "in parentheses": ("see (postgres://app:{pw}@localhost) now", "see (postgres://[URL_CREDENTIAL]@localhost) now"),
}

HALF_EATEN_BY_EMAIL_THROUGH_046 = {
    "postgresql dotted host": ("postgresql://app:{pw}@db.example.com:5432/db", "postgresql://[URL_CREDENTIAL]@db.example.com:5432/db"),
    "mongodb+srv": ("mongodb+srv://app:{pw}@cluster0.abc.mongodb.net/db?retryWrites=true", "mongodb+srv://[URL_CREDENTIAL]@cluster0.abc.mongodb.net/db?retryWrites=true"),
    "https basic auth": ("https://user:{pw}@host.example.com/path?q=1#frag", "https://[URL_CREDENTIAL]@host.example.com/path?q=1#frag"),
    "ftp": ("ftp://user:{pw}@files.example.org/pub", "ftp://[URL_CREDENTIAL]@files.example.org/pub"),
    "smtp": ("smtp://user:{pw}@mail.example.org:587", "smtp://[URL_CREDENTIAL]@mail.example.org:587"),
    "ldap": ("ldap://cn=admin,dc=x:{pw}@ldap.example.org", "ldap://[URL_CREDENTIAL]@ldap.example.org"),
}


@pytest.mark.parametrize("name", list(LEAKED_THROUGH_046) + list(HALF_EATEN_BY_EMAIL_THROUGH_046))
def test_url_password_is_redacted_whole_user_included_and_quarantines(name: str):
    text, expected = {**LEAKED_THROUGH_046, **HALF_EATEN_BY_EMAIL_THROUGH_046}[name]
    result = redact(text.format(pw=PW))
    assert result.text == expected, name
    assert result.hits == ["URL_CREDENTIAL"], (name, result.hits)  # not EMAIL: this rule runs first
    assert "URL_CREDENTIAL" in HIGH_PRECISION_SECRETS
    _no_fragment(PW, result.text, name)
    assert "app:" not in result.text and "user:" not in result.text, name  # the user is identifying too


def test_url_credential_runs_before_every_other_pattern():
    """The userinfo may hold a key in any format below, and EMAIL must never see a dotted host
    first. Position, not just membership, is the contract."""
    assert PATTERNS[0][0] == "URL_CREDENTIAL"


@pytest.mark.parametrize("context", [
    "postgres://app:{pw}@localhost/db",
    "postgres://app:{pw}@db.example.com/db",
    "redis://:{pw}@localhost",
    "DATABASE_URL=postgres://app:{pw}@localhost:5432/db\nnext line",
])
def test_unencoded_at_and_colon_in_the_password_run_to_the_last_at(context: str):
    """People write `p@ss:w0rd` unencoded. The match takes everything up to the LAST `@`
    before the host, so no fragment of the password leaves and the host is the host."""
    result = redact(context.format(pw=TRICKY))
    assert result.hits == ["URL_CREDENTIAL"], result
    _no_fragment(TRICKY, result.text, context)
    assert "[URL_CREDENTIAL]@" in result.text
    host = result.text.split("[URL_CREDENTIAL]@", 1)[1]
    assert host.startswith(("localhost", "db.example.com")), host


@pytest.mark.parametrize("placeholder", [
    "password", "PASSWORD", "Password", "passwd", "pass", "pwd", "secret", "changeme", "changeit",
    "${DB_PASSWORD}", "${DB_PASSWORD:-dev}", "$DB_PASSWORD", "%DB_PASSWORD%",
    "{{ db_password }}", "{password}", "<password>", "<your password here>", "[password]",
    "xxxxxxxx", "XXXX", "x", "********", "...",
])
def test_placeholder_passwords_are_left_untouched_and_do_not_quarantine(placeholder: str):
    """Documentation, not a credential. `postgres://user:password@localhost` is in every second
    dev note; quarantining each one would bury the review pile."""
    text = f"postgres://user:{placeholder}@localhost:5432/db"
    result = redact(text)
    assert result.text == text, placeholder
    assert result.hits == [], placeholder


def test_a_placeholder_on_a_dotted_host_still_meets_email_and_does_not_quarantine():
    """The URL rule declines a placeholder, so the older accident is what remains for it: EMAIL
    takes `password@db.example.com`. That is a placeholder, and EMAIL never quarantines."""
    result = redact("postgres://user:password@db.example.com/db")
    assert result.hits == ["EMAIL"]
    assert not any(h in HIGH_PRECISION_SECRETS for h in result.hits)


@pytest.mark.parametrize("text", [
    "postgres://user:@localhost/db",  # empty password
    "postgres://user@localhost/db",  # no password
    "ssh://git@github.com/org/repo",
    "https://example.com/path:with@colon",  # the colon and @ are past the first slash
    "see http://localhost:8080/health and mailto:a@b.com",
    "https://api.telegram.org/bot123456:ABC/getMe",
    "Server=db;User Id=app;Password=hunter2;",  # key=value form: not this rule (0.4.7 log)
    "the ratio is 3:1 @ noon",
])
def test_urls_without_a_password_and_non_urls_are_not_taken(text: str):
    assert "URL_CREDENTIAL" not in redact(text).hits, text


def test_a_default_such_as_guest_guest_is_a_credential_not_a_placeholder():
    """A `guest` user with the password `guest` is RabbitMQ's default. On a real host it is exactly
    what must not leave; the placeholder list is words that mean 'put a password here', not weak
    ones. (Spelled in pieces below because the tree-scan test in test_redact_formats would
    otherwise flag this file, which is the point of that test.)"""
    result = redact("amqp://" + j("gue", "st:gu", "est") + "@broker.example.com:5672/")
    assert result.text == "amqp://[URL_CREDENTIAL]@broker.example.com:5672/"
    assert result.hits == ["URL_CREDENTIAL"]


def test_a_key_format_inside_the_userinfo_goes_out_as_one_url_credential():
    token = j("gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
    result = redact(f"https://x-access-token:{token}@github.com/org/repo.git")
    assert result.text == "https://[URL_CREDENTIAL]@github.com/org/repo.git"
    assert result.hits == ["URL_CREDENTIAL"]
    _no_fragment(token, result.text, "ghp in userinfo")


@pytest.mark.parametrize("special", ["#", "?", "/", "'", '"', "`", "!", "&", "=", ";", ","])
def test_any_non_whitespace_character_may_sit_inside_the_password(special: str):
    """Only whitespace ends the password. An early cut of this rule stopped at `#`, `?`, `/` and
    quotes, so `app:PW#1@localhost` went out whole with no hit, and on a dotted host EMAIL
    half-took it again. Those characters are common in passwords and, unencoded, turn up
    exactly in the malformed URLs people paste into notes."""
    pw = j("Zq7", special, "vR", "9x")
    for host in ("localhost:5432/db", "db.example.com/db"):
        result = redact(f"postgres://app:{pw}@{host}")
        assert result.hits == ["URL_CREDENTIAL"], (special, host, result)
        assert result.text == f"postgres://[URL_CREDENTIAL]@{host}", (special, host)


@pytest.mark.parametrize("text", [
    "http://localhost:8080?x=a@b.com",  # port, then an email in the query: user=localhost, password=8080?x=a
    "http://localhost:8080/path/a@b.com",
    "http://localhost:8080#section@b",
    "https://example.com:443/login?next=/u@x",
    "http://[::1]:8080/x@y",  # an IPv6 literal is not a user
])
def test_a_port_before_a_later_at_sign_is_not_a_password(text: str):
    """Allowing `/`, `?` and `#` inside the password opens one false shape: a host:port followed
    by a path, query or fragment that later holds an `@`. One to five digits followed by `/`,
    `?` or `#` is a port; `[` starts an IPv6 literal, not a user."""
    assert "URL_CREDENTIAL" not in redact(text).hits, text


def test_a_real_password_that_starts_with_a_dollar_sign_or_percent_is_not_a_placeholder():
    """`$VAR` and `%VAR%` are placeholders only in UPPER_SNAKE, case-sensitively: `$Zq7vR2mW9x` is
    a password that starts with a dollar sign. The residual: an all-caps password starting
    with `$` reads as a placeholder."""
    for pw in ("$" + PW, "%" + PW + "%", "$db_password", "%db_password%", "$Db_Password"):
        result = redact(f"postgres://app:{pw}@localhost/db")
        assert result.text == "postgres://[URL_CREDENTIAL]@localhost/db", pw
    for placeholder in ("$DB_PASSWORD", "%DB_PASSWORD%", "${db_password}", "$ZQ7VR2MW9X"):
        assert redact(f"postgres://app:{placeholder}@localhost/db").hits == [], placeholder


class RecordingClient(FixtureClient):
    def __init__(self) -> None:
        self.states: list[dict] = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


def test_title_aliases_excerpt_and_sibling_titles_are_all_covered(tmp_path: Path):
    """Redaction is one function called on every string that leaves; this pins that the scan
    path calls it for the title, the aliases, the excerpt and a sibling's title alike, and that
    the note with the credential is quarantined on the local hit."""
    url = f"postgres://app:{PW}@localhost/db"
    (tmp_path / "a.md").write_text(
        f"---\naliases: ['mirror at {url}']\n---\n# Connect via {url}\n\nbody uses {url} daily\n",
        encoding="utf-8")
    (tmp_path / "b.md").write_text("# Plain sibling\n\nsee [[a]]\n", encoding="utf-8")
    client = RecordingClient()
    rows = scan_vault(tmp_path, client=client, offline=True)
    blob = json.dumps(client.states) + json.dumps(rows)
    _no_fragment(PW, blob, "scan states and rows")
    assert "app:" not in blob
    a = next(r for r in rows if r["path"] == "a.md")
    assert "URL_CREDENTIAL" in a["redacted_own"]
    assert a["action"] == "quarantine" and a["quarantine_triggers"] == ["local:URL_CREDENTIAL"]
    b = next(s for s in client.states if s["path"].endswith("b.md"))
    # A note whose own title holds a credential is never listed as a sibling: its title would
    # go out as a token, but there is nothing to gain from listing it.
    assert b["other_note_titles"] == []
    # The sibling path itself is still redacted when a title without a credential is listed.
    (tmp_path / "c.md").write_text(f"# Plain title\n\nsee {url}\n", encoding="utf-8")
    client = RecordingClient()
    scan_vault(tmp_path, client=client, offline=True)
    b = next(s for s in client.states if s["path"].endswith("b.md"))
    assert b["other_note_titles"] == ["Plain title"]
