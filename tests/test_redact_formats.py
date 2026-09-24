"""Every credential format the README names is redacted whole and quarantines locally.

Found on 2026-09-22 by an outside read of v0.3.0 and reproduced against v0.4.0: sixteen
common formats went out in the clear, and the README's "GitHub, Google and Slack formats"
was a false claim (gho_/ghu_/ghs_/ghr_, GOCSPX- and Slack webhooks and xapp- all leaked).
The worst case was a Telegram bot token: the bot id is phone-shaped, so the redactor
produced [PHONE]:<secret>, the row read hits=['PHONE'], and PHONE is not a quarantine label.

Every string here is fabricated in the vendor's documented shape and ASSEMBLED AT RUNTIME
from pieces: GitHub's push protection scans every commit for these same shapes and blocked
the first cut of this file, which held them as literals. No piece below is a secret, and no
line of this file matches a vendor scanner on its own.
"""

import re
from pathlib import Path

import pytest

from janitor.policy import HIGH_PRECISION_SECRETS
from janitor.redact import KEY_FORMATS, KEY_FORMATS_OWN_BOUNDARY, WEBHOOK_FORMATS, redact

ROOT = Path(__file__).resolve().parent.parent
ALNUM36 = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
ALNUM24 = "AbCdEfGhIjKlMnOpQrStUvWx"
DIGITS18 = "123456789012345678"


def j(*parts: str) -> str:
    """Join the pieces of a secret-shaped string at runtime."""
    return "".join(parts)


SAMPLES: dict[str, tuple[str, str]] = {
    # name: (fabricated secret, expected label)
    "github ghp (control, redacted through 0.4.0)": (j("gh", "p_", ALNUM36), "KEY"),
    "telegram bot token (measured shape: 10-digit id, 35-char secret starting A)": (j("12345", "67890", ":", "AA", "Habcdefghijklmnopqrstuvwxyz012345"), "KEY"),
    "github gho": (j("gh", "o_", ALNUM36), "KEY"),
    "github ghu": (j("gh", "u_", ALNUM36), "KEY"),
    "github ghs": (j("gh", "s_", ALNUM36), "KEY"),
    "github ghr": (j("gh", "r_", ALNUM36), "KEY"),
    "github fine-grained": (j("github_", "pat_", "11ABCDEFG0", ALNUM36, ALNUM36), "KEY"),
    "google oauth client secret": (j("GOC", "SPX-", "AbCdEfGhIjKlMnOpQrStUvWxYz12"), "KEY"),
    "google api key": (j("AI", "za", "SyA", ALNUM36), "KEY"),
    "slack webhook": (j("https://", "hooks.", "slack.com/", "services/", "T0123ABCD/", "B0123ABCD/", ALNUM24), "WEBHOOK"),
    "slack app-level token": (j("xa", "pp-1-", "A0123ABCD-1234567890123-", "abcdef0123456789abcdef0123456789abcdef0123456789"), "KEY"),
    "slack bot token": (j("xo", "xb-", "1234567890-1234567890123-", ALNUM24), "KEY"),
    "stripe sk_live": (j("sk_", "live_", ALNUM24), "KEY"),
    "stripe sk_test": (j("sk_", "test_", ALNUM24), "KEY"),
    "stripe rk_live": (j("rk_", "live_", ALNUM24), "KEY"),
    "stripe whsec": (j("wh", "sec_", ALNUM24, "Yz0123456789"), "KEY"),
    "discord webhook": (j("https://", "discord.com/", "api/", "webhooks/", DIGITS18, "/", ALNUM24, "Yz0123456789-_abcdefghijklmnopqrstuvwxyz0123"), "WEBHOOK"),
    "discordapp webhook": (j("https://", "discordapp.com/", "api/", "webhooks/", DIGITS18, "/", ALNUM24, "Yz0123456789-_abcdefghijklmnopqrstuvwxyz0123"), "WEBHOOK"),
    "sendgrid": (j("S", "G.", "AbCdEfGhIjKlMnOpQrStUv", ".", ALNUM24, "Yz0123456789abcdefg"), "KEY"),
    "npm": (j("np", "m_", ALNUM36), "KEY"),
    "gitlab pat": (j("gl", "pat-", "AbCdEfGhIjKlMnOpQrSt"), "KEY"),
    "hugging face": (j("h", "f_", ALNUM24, "Yz01234567"), "KEY"),
    "openai / anthropic": (j("s", "k-", ALNUM36), "KEY"),
    "aws access key id": (j("AK", "IA", "IOSFODNN7EXAMPLE"), "KEY"),
}


@pytest.mark.parametrize("name", list(SAMPLES))
def test_format_is_redacted_whole_and_quarantines(name: str):
    secret, label = SAMPLES[name]
    for text in (f"token: {secret} end", f"{secret}", f"(see {secret}), then", f"url={secret}\n"):
        result = redact(text)
        assert secret not in result.text, name
        # No fragment of the secret survives: nothing longer than 8 chars of it is left.
        for i in range(0, len(secret) - 8):
            assert secret[i:i + 8] not in result.text, (name, secret[i:i + 8])
        assert label in result.hits, (name, result.hits)
        assert any(h in HIGH_PRECISION_SECRETS for h in result.hits), name


def test_telegram_token_is_one_key_not_a_phone_and_a_leak():
    secret, _ = SAMPLES["telegram bot token (measured shape: 10-digit id, 35-char secret starting A)"]
    result = redact(f"bot: {secret}")
    assert result.text == "bot: [KEY]"
    assert result.hits == ["KEY"]  # not PHONE: the id half must not be taken first
    assert redact(f"https://api.telegram.org/bot{secret}/getMe").text == "https://api.telegram.org/bot[KEY]/getMe"


TELEGRAM = j("12345", "67890", ":", "AA", "Habcdefghijklmnopqrstuvwxyz012345")


@pytest.mark.parametrize("context", [
    "see {tok} here",
    "token: {tok}",
    "TELEGRAM_BOT_TOKEN={tok}",
    '"{tok}"',
    "token:{tok}",  # v0.4.1: [PHONE]:<secret>, SENT
    "https://api.telegram.org/bot{tok}/sendMessage",  # v0.4.1: no hit, whole token SENT; the commonest context in code
    "arn:aws:sns:us-east-1:{tok}",  # v0.4.1: [PHONE]:<secret>, SENT
])
def test_telegram_token_is_redacted_whole_in_every_common_context(context: str):
    """Published v0.4.1 leaked a Telegram token in three of seven common contexts (found by an
    outside review against the tag). A `(?<!:)` guard meant for an AWS ARN refused real tokens after a
    colon, after which PHONE took the id and the secret half went out; the shared alphanumeric
    boundary refused the `bot` prefix of the Bot API URL, so the whole token went out."""
    result = redact(context.format(tok=TELEGRAM))
    assert "KEY" in result.hits and "PHONE" not in result.hits, result
    for i in range(0, len(TELEGRAM) - 8):
        assert TELEGRAM[i:i + 8] not in result.text, (context, TELEGRAM[i:i + 8])
    assert any(h in HIGH_PRECISION_SECRETS for h in result.hits)


@pytest.mark.parametrize("name,text", [
    # An AWS SNS ARN: 12-digit account id, colon, 31-char topic name. Took [KEY] under a wider
    # cut in the 0.4.1 amend and would have moved the note under --apply. The 8-to-10-digit id
    # run excludes it on its own: a 12-digit run cannot start inside itself.
    ("sns arn", "ARN: arn:aws:sns:us-east-1:" + "123456789012" + ":" + "data-inbound-snapshot-topic-x01"),
    # BotFather's README example shape: 9 digits, 31 chars. Documentation, not a token.
    ("botfather readme", "BotFather replies with a token like " + "123456789" + ":" + "AbCdEfGhIjKlMnOpQrStUvWxYz01234"),
    # Telegram's own Bot API docs example: 6 digits, 34 chars, no A. Not a token.
    ("bot api docs example", j("123", "456", ":", "ABC-DEF1234ghIkl-zyx57W2v1u123ew11")),
])
def test_telegram_shape_does_not_take_arns_or_documentation(name: str, text: str):
    # KEY is what quarantines; a 9- or 10-digit id may still read as PHONE, which does not.
    assert "KEY" not in redact(text).hits, name


def test_stripe_publishable_keys_are_not_secrets():
    """pk_live_ is meant to be published. Quarantining a note for it would be a false move."""
    result = redact(j("pk_", "live_", ALNUM24))
    assert result.hits == []


def test_prefixes_are_case_sensitive_and_word_bounded():
    assert redact("HF_HOME=/data/hf_cache_directory_for_models").hits == []
    assert redact("the sendgrid docs say SG.something.short").hits == []
    assert redact(j("x", "hf_", ALNUM24, "Yz01234567")).hits == []  # glued to a word: not the format
    assert redact("id 12345:AAH is a ratio").hits == []  # a bot id has 8 to 10 digits and a 35-char secret
    # Documented case only: an upper-cased prefix is not the vendor's format and is left alone.
    assert redact(j("GH", "O_", ALNUM36)).hits == []


def test_readme_and_security_name_every_format_family():
    """The contract lists exactly what is covered. A format in the code that the docs do not
    name is a claim nobody can check; a format in the docs that the code lacks is a false one."""
    families = {
        "OpenAI", "Anthropic", "Stripe", "AWS", "Google", "GitHub", "GitLab", "Slack", "npm",
        "Hugging Face", "SendGrid", "Telegram", "Discord",
    }
    for doc in ("README.md", "SECURITY.md"):
        text = (ROOT / doc).read_text(encoding="utf-8")
        missing = {f for f in families if f not in text}
        assert not missing, (doc, missing)
        assert "case" in text  # the docs say the match is on the documented case
    named = " ".join(name for name, _ in KEY_FORMATS + KEY_FORMATS_OWN_BOUNDARY + WEBHOOK_FORMATS)
    for family in families:
        assert family in named, family
    # The README's sentence must not claim "and Slack formats" without the webhook.
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"webhook", readme, re.IGNORECASE)


def test_no_file_in_the_tree_holds_a_credential_shaped_literal():
    """GitHub's push protection blocked v0.4.1 on this test file's own fixtures. The redactor
    is the scanner we have: nothing it would redact as KEY or WEBHOOK may sit in the tree.

    Fixtures in the five formats v0.4.0 already covered (sk-, AKIA, AIza, ghp_, github_pat_)
    are already public in the suite and GitHub accepted them; they are exempt. Everything
    added in 0.4.1 is not."""
    from janitor.redact import PATTERNS

    # URL_CREDENTIAL joined in 0.4.7: a `scheme://user:password@host` literal in the tree would be
    # the same kind of fixture; the validator is applied so a placeholder password is not one.
    from janitor.redact import VALIDATORS

    scanners = [(pat, VALIDATORS.get(label)) for label, pat in PATTERNS if label in ("KEY", "WEBHOOK", "URL_CREDENTIAL")]
    public_since_040 = ("sk-", "AKIA", "AIza", "ghp_", "github_pat_")
    offenders = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in (".git", ".venv", "__pycache__", ".pytest_cache") for part in path.parts):
            continue
        if path.relative_to(ROOT).parts[:2] == ("examples", "demo-vault"):
            # The demo vault deliberately holds ONE credential-shaped string, a plainly fake
            # password in a localhost URL, so its scan has a redaction and a quarantine to show.
            # It is fictional throughout and is swept for vendor token shapes by its own test.
            continue
        if path.suffix in (".pyc", ".png", ".jpg"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pat, validator in scanners:
            for m in pat.finditer(text):
                if m.group(0).startswith(public_since_040) or (validator is not None and not validator(m)):
                    continue
                offenders.append((path.relative_to(ROOT).as_posix(), m.group(0)[:12] + "..."))
    assert not offenders, offenders
