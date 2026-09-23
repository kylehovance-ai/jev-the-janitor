"""Local redaction before anything leaves the machine.

Regex redaction is best-effort, not a guarantee. Review the output of a dry run before
pointing the janitor at a vault that matters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Credential formats with a documented shape: a fixed prefix (or, for Telegram, a fixed
# separator) and a run of the secret. One alternative per format so a reader can check the
# list against a vendor's documentation, and so the README can name exactly what is covered.
# Every one of these runs BEFORE the PHONE and CARD patterns, because a Telegram bot token
# starts with a phone-shaped bot id: through 0.4.0 the id became [PHONE] and the secret half
# went out in the clear, and PHONE does not quarantine, so the row looked handled.
# Case-sensitive: every prefix is documented in this case, and a case-blind `hf_` or `SG.`
# would match ordinary text. (Through 0.4.0 the key line was case-blind; no recorded run
# depended on it.) The lookarounds, not \b, bound the match, so a key that ends in `-` or
# `_` is taken whole.
KEY_FORMATS: list[tuple[str, str]] = [
    ("OpenAI, Anthropic", r"sk-[A-Za-z0-9_-]{16,}"),
    ("Stripe secret and restricted keys", r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    ("Stripe webhook signing secret", r"whsec_[A-Za-z0-9]{16,}"),
    ("AWS access key id", r"AKIA[0-9A-Z]{16}"),
    ("Google API key", r"AIza[0-9A-Za-z_-]{30,}"),
    ("Google OAuth client secret", r"GOCSPX-[A-Za-z0-9_-]{20,}"),
    ("GitHub personal, OAuth, user-to-server, server-to-server and refresh tokens", r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ("GitHub fine-grained personal access token", r"github_pat_[A-Za-z0-9_]{20,}"),
    ("GitLab personal access token", r"glpat-[A-Za-z0-9_-]{20,}"),
    ("Slack bot, user, app-config, refresh and legacy tokens", r"xox[baeprs]-[A-Za-z0-9-]{10,}"),
    ("Slack app-level token", r"xapp-\d-[A-Za-z0-9-]{10,}"),
    ("npm access token", r"npm_[A-Za-z0-9]{20,}"),
    ("Hugging Face token", r"hf_[A-Za-z0-9]{20,}"),
    ("SendGrid API key", r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
]

# Formats that need their own boundaries rather than the shared ones below. Each entry is a
# complete regex. Telegram: measured on nine real tokens, a 10-digit id, a colon, a 35-char
# secret starting with A (the published format, and gitleaks' rule). Its own boundaries
# because v0.4.1's shared ones leaked it in the three commonest code contexts: `token:<tok>`
# and an ARN-style `:<tok>` were refused by a `(?<!:)` guard (added against an AWS SNS ARN
# false positive that the 8-to-10-digit id run already excludes on its own, since an account
# id is 12 digits), after which PHONE took the id and the secret half went out; and the Bot
# API URL `https://api.telegram.org/bot<tok>/sendMessage` glues `bot` to the id, which the
# shared alphanumeric lookbehind refused, so the whole token went out. Now: the id may follow
# `/bot` or any non-alphanumeric character (a colon included), may not start inside a longer
# digit run, and the secret may not continue into more token characters. The Bot API docs'
# own example (6 digits, 34 chars, no A) and BotFather's README example (9 digits, 31 chars)
# are not tokens and are left alone on purpose.
KEY_FORMATS_OWN_BOUNDARY: list[tuple[str, str]] = [
    ("Telegram bot token", r"(?:(?<=/bot)|(?<![A-Za-z0-9]))\d{8,10}:A[A-Za-z0-9_-]{34}(?![A-Za-z0-9_-])"),
]

# A webhook URL is a credential: whoever holds it can post as the integration. The whole
# URL is replaced, id and secret together, so no half of it can be quoted back.
WEBHOOK_FORMATS: list[tuple[str, str]] = [
    ("Slack incoming webhook", r"https?://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"),
    ("Discord webhook", r"https?://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
]


def _alternation(formats: list[tuple[str, str]]) -> str:
    return "|".join(shape for _, shape in formats)


PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("KEY", re.compile(r"(?<![A-Za-z0-9])(?:" + _alternation(KEY_FORMATS) + r")(?![A-Za-z0-9])")),
    ("KEY", re.compile(_alternation(KEY_FORMATS_OWN_BOUNDARY))),
    ("WEBHOOK", re.compile(r"(?<![A-Za-z0-9])(?:" + _alternation(WEBHOOK_FORMATS) + r")")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("PEM", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("BEARER", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{12,}")),
    # Quotes around the secret are optional; 0.1.0 required them and missed `key = value` lines.
    ("AWS_SECRET", re.compile(r"(?i)aws(.{0,12})?(secret|access).{0,8}['\"]?[A-Za-z0-9/+=]{20,}['\"]?")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("PHONE", re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


@dataclass
class RedactionResult:
    text: str
    hits: list[str] = field(default_factory=list)

    @property
    def stripped(self) -> bool:
        return bool(self.hits)


def luhn_ok(digits: str) -> bool:
    """Luhn checksum over the digits in ``digits``. Card numbers pass; timestamps and ISBNs do not."""
    d = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x *= 2
            if x > 9:
                x -= 9
        total += x
    return total % 10 == 0


# A match must also pass its validator to be replaced. CARD used to replace any 13-19 digit
# run, which turned millisecond timestamps and ISBNs into [CARD].
ORDER_WORDS = re.compile(r"(?i)\b(order|invoice|ref|reference|sku|ticket|case|id|po|tracking|part|serial)\b\s*(?:#|no\.?|number|:)?\s*$")


def phone_context_ok(m: re.Match[str]) -> bool:
    """A phone-shaped number after 'Order', 'invoice #', 'ticket', 'ref:' is an identifier, not a phone."""
    before = m.string[max(0, m.start() - 24):m.start()]
    return ORDER_WORDS.search(before) is None


CARD_SHAPES = {(13,), (14,), (15,), (16,), (17,), (18,), (19,), (4, 4, 4, 4), (4, 4, 4, 4, 3), (4, 6, 5), (4, 4, 4, 4, 1), (4, 4, 4, 4, 2)}


def card_shape_ok(m: re.Match[str]) -> bool:
    """A card is contiguous, or grouped 4-4-4-4 (16), 4-6-5 (Amex), 4-4-4-4-3 (19). And it passes Luhn.

    Luhn alone lets one 16-digit run in ten through, and a 12-digit AWS account id followed by
    a hyphen and a year (111122223333-2026, say) was one of them on the first live run: it became
    [CARD] in a clients/ path, where the account id is exactly the identifier a reader wants
    intact. 12-then-4 is not a card shape; uniform grouping kills that class without weakening
    the real one.
    """
    digits = m.group(0).strip(" -")
    groups = tuple(len(g) for g in re.split(r"[ -]+", digits) if g)
    # Major industry identifier: every payment card starts with 2 to 6 (Mastercard 2/5, Amex
    # 3, Visa 4, Discover/UnionPay 6). The classic Luhn hole is a run of the same digit, and
    # sixteen zeros (a Linux capability bitmask, CapEff: 0000000000000000) passed both the
    # checksum and the shape rule on the first live run. A leading 0 is never a card.
    return digits[:1] in "23456" and groups in CARD_SHAPES and luhn_ok(digits)


# A match must also pass its validator to be replaced. Validators see the match, so they can
# read the surrounding text.
VALIDATORS = {"CARD": card_shape_ok, "PHONE": phone_context_ok}


def redact(text: str, denylist: list[str] | None = None) -> RedactionResult:
    hits: list[str] = []
    out = text
    for label, pat in PATTERNS:
        validator = VALIDATORS.get(label)

        def _replace(m: re.Match[str], label=label, validator=validator) -> str:
            if validator is not None and not validator(m):
                return m.group(0)
            return f"[{label}]"

        new = pat.sub(_replace, out)
        if new != out:
            hits.append(label)
            out = new
    for name in denylist or []:
        name = name.strip()
        if len(name) < 3:
            continue
        # Whole-word: "Ann" must not turn "Anniversary" into "[NAME]iversary". Lookarounds rather
        # than \b so a name that starts or ends with punctuation still matches at a word edge.
        pat = re.compile(r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])", re.IGNORECASE)
        if pat.search(out):
            hits.append("NAME")
            out = pat.sub("[NAME]", out)
    return RedactionResult(text=out, hits=sorted(set(hits)))


# Any note whose vault-relative path has one of these as a word of a folder name is never
# read for a live call, and its title is never listed as sibling context. Override with
# ``--sensitive-paths`` to match your own vault layout; the list replaces, not extends.
DEFAULT_SENSITIVE_PATH_PARTS: tuple[str, ...] = ("family", "private", "personal", "secrets", "inbox")

_WORDS = re.compile(r"[A-Za-z0-9]+")


def folder_words(segment: str) -> list[str]:
    """The alphanumeric words of one folder name, lowercased: ``'00 Inbox'`` -> ``['00', 'inbox']``."""
    return [w.lower() for w in _WORDS.findall(segment)]


def segment_matches(segment: str, part: str) -> bool:
    """Does folder name ``segment`` carry sensitive name ``part`` as whole words?

    Through 0.4.0 the comparison was exact per folder name, so ``_Inbox``, ``00 Inbox``,
    ``Private Notes`` and ``_private`` were all scanned while ``inbox`` and ``private`` were
    skipped. Underscores, digits, spaces and dashes are how people decorate a folder name,
    not what it means. The name is split into alphanumeric words and the sensitive name has
    to appear as a run of whole words: ``inboxes`` is still not ``inbox`` (the pre-flight
    warns about it), and ``private-equity`` IS ``private`` (skipped, and named in the
    pre-flight as skipped, which is the safe direction to be wrong in). A multi-word part
    such as ``Private Notes`` matches those words in that order.
    """
    want = folder_words(part)
    if not want:
        return False
    have = folder_words(segment)
    n = len(want)
    return any(have[i:i + n] == want for i in range(len(have) - n + 1))


def matching_part(segment: str, parts: tuple[str, ...] | None = None) -> str | None:
    """The first sensitive name that ``segment`` matches, or None."""
    wanted = tuple(p for p in (parts if parts is not None else DEFAULT_SENSITIVE_PATH_PARTS) if p.strip())
    return next((part for part in wanted if segment_matches(segment, part)), None)


def path_is_sensitive(path: str, parts: tuple[str, ...] | None = None) -> bool:
    """Is any FOLDER of this vault-relative path sensitive? The file's own name does not count."""
    folders = path.replace("\\", "/").split("/")[:-1]
    return any(matching_part(segment, parts) is not None for segment in folders)
