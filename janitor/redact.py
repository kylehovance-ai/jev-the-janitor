"""Local redaction before anything leaves the machine.

Regex redaction is best-effort, not a guarantee. Review the output of a dry run before
pointing the janitor at a vault that matters.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from typing import Callable

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
    ("AWS access key id, permanent (AKIA) or temporary (ASIA)", r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
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


# A password inside a URL: `scheme://user:password@host`, or `scheme://:password@host` with
# no user. The scheme is generic (postgres, postgresql+psycopg2, mysql, mongodb+srv, redis,
# rediss, amqp, http, ftp, smtp, ldap, and the two-part `jdbc:mysql://`), because the shape
# is the URL's, not the vendor's. The whole userinfo is replaced, user and password together,
# since the user can be identifying; the scheme stays, and so does everything after the last
# `@` (host, port, path), so the model still sees "a local postgres URL". People paste
# passwords with unencoded `@`, `:`, `#`, `?`, `/` and quotes (`p@ss:w0rd#1`), so the
# password is every non-whitespace character up to the LAST `@` of the run: the user ends at
# the first colon and may not hold `/` (a user precedes the first slash), and only whitespace
# ends the password. That opens one false shape, a URL with a port and a later `@`
# (`http://localhost:8080/x?email=a@b.com` reads as user `localhost`, password `8080/x?email=a`),
# so a "password" that is one to five digits, or a `${PORT}`-style placeholder, followed by
# `/`, `?` or `#` is a port and is not a credential; a user never runs past a `?` or `#`
# (`obsidian://open?vault=Main:Notes@home`); and an IPv6 literal (`http://[::1]:8080/x@y`)
# is not a user. Through 0.4.6
# there was no such rule: a `localhost` or IP host went out in the clear, and a dotted host
# was taken by EMAIL from the password's first character to the end of the host, so `user:`
# was sent, the row read hits=['EMAIL'], and EMAIL does not quarantine.
URL_CREDENTIAL = re.compile(
    r"(?<![A-Za-z0-9+.\-])"
    r"([A-Za-z][A-Za-z0-9+.\-]*(?::[A-Za-z][A-Za-z0-9+.\-]*)?://)"  # 1: scheme, kept
    r"(?!\[)([^\s:/?#]*):(\S+)@"  # 2: user (to the first colon; never past a ? or #), 3: password (to the last @ of the run)
    r"(\S*)"  # 4: host and whatever follows it, kept
)

# A placeholder where the password goes is documentation, not a credential, and is left
# untouched (no hit, no quarantine): template syntax (`${...}` in any case; a bare `$VAR` or
# `%VAR%` only in UPPER_SNAKE, because `$Zq7vR2mW9x` is a password that starts with a
# dollar sign, and an all-caps password that starts with `$` is the residual this leaves;
# `{{ var }}` in any case); a bracketed placeholder (`{DB_PASSWORD}`, `<password>`,
# `[password]`, `<your password here>`: see _bracketed_placeholder); the words `password`,
# `passwd`, `pass`, `pwd`, `secret`, `changeme` and `changeit` in any case; and a run of `x`,
# `*` or dots. `postgres://user:password@localhost` is in every second dev note; quarantining
# each one would bury the review pile. Anything else is a credential, including a default
# such as `guest` with the password `guest`: on a real host that is exactly what must not leave.
URL_PASSWORD_TEMPLATE = re.compile(r"^(?:\$\{[^}]*\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%|\{\{.*\}\})$")
URL_PASSWORD_WORD = re.compile(r"(?i)^(?:password|passwd|pass|pwd|secret|changeme|changeit|x+|\*+|\.{2,}|…+)$")
URL_PASSWORD_WORDS = ("password", "passwd", "pass", "pwd", "secret", "changeme", "changeit")
# One layer of brackets, `{…}`, `<…>` or `[…]`: a placeholder only when what is INSIDE is one.
# Through 0.4.7 any bracketed value was a placeholder, so `{MyRealPassword}` went out with no
# hit and no quarantine. No syntactic rule tells `<password>` from `<MyRealPassword>`, so the
# inside must itself be a placeholder word alone or as a whole word (`<your password here>`),
# an UPPER_SNAKE name (`{DB_PASSWORD}`), or a run of x, * or dots.
URL_PASSWORD_BRACKETED = re.compile(r"^(?:\{(?P<b>[^{}]*)\}|<(?P<a>[^<>]*)>|\[(?P<s>[^\[\]]*)\])$")
URL_PASSWORD_INSIDE_WORD = re.compile(r"(?i)(?<![A-Za-z0-9])(?:" + "|".join(URL_PASSWORD_WORDS) + r")(?![A-Za-z0-9])")
URL_PASSWORD_INSIDE_UPPER = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _bracketed_placeholder(password: str) -> bool:
    m = URL_PASSWORD_BRACKETED.match(password)
    if not m:
        return False
    inside = (m.group("b") or m.group("a") or m.group("s") or "").strip()
    return bool(inside) and (URL_PASSWORD_WORD.match(inside) is not None
                             or URL_PASSWORD_INSIDE_WORD.search(inside) is not None
                             or URL_PASSWORD_INSIDE_UPPER.match(inside) is not None)
# A port, literal or templated, followed by a path, query or fragment: `localhost:8080/x?a@b`
# and `localhost:${PORT}/api/users/@me` are URLs with a later `@`, not credentials. The user
# part likewise stops at `?` or `#` (RFC 3986: both end the authority), which is what keeps
# `obsidian://open?vault=Main:Notes@home` and `x-callback-url://run?name=a:b@c` out: an
# Obsidian vault is where this tool's readers live. A port is a port only when a path, query
# or fragment FOLLOWS it: digits that run straight into the `@` are a password (`root:1234@`,
# `admin:12345@` are exactly the weak defaults dev notes hold; 0.4.7's first cut read them as
# a port). The one shape that costs is the phishing form, an `http://` URL whose
# authority reads `localhost:8080@evil.example.com`, which now counts as a credential and
# quarantines; that is the right side to be wrong on. (Written here without the scheme so
# the tree-scan test in test_redact_formats does not flag this file.)
URL_PORT_NOT_PASSWORD = re.compile(r"^(?:\d{1,5}|\$\{[^}]*\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%)[/?#]")


# A templated user or host: `{user}`, `${HOST}`, `<host>`, `%HOST%`. In an f-string or a template
# URL the other parts are templated too, which is the evidence that a bracketed password is a
# template and not a value: `f"postgres://{user}:{db_pw}@{host}/{db}"` is code, not a leak.
URL_PART_TEMPLATE = re.compile(r"^(?:\{[^{}]*\}|\$\{[^}]*\}|<[^<>]*>|%[A-Za-z_][A-Za-z0-9_]*%)$")


def _templated_neighbours(m: re.Match[str]) -> bool:
    user = m.group(2)
    host = re.split(r"[/:?#]", m.group(4), maxsplit=1)[0]
    return bool(URL_PART_TEMPLATE.match(user)) or bool(URL_PART_TEMPLATE.match(host))


def url_password_is_real(m: re.Match[str]) -> bool:
    """The userinfo is replaced unless the password is a placeholder, the URL around it is a
    template (a templated user or host), or the "password" is really a port."""
    password = m.group(3)
    if URL_PASSWORD_TEMPLATE.match(password) or URL_PASSWORD_WORD.match(password) or _bracketed_placeholder(password):
        return False
    if URL_PASSWORD_BRACKETED.match(password) and _templated_neighbours(m):
        return False
    return URL_PORT_NOT_PASSWORD.match(password) is None


def _alternation(formats: list[tuple[str, str]]) -> str:
    return "|".join(shape for _, shape in formats)


# Where a key may start. Not after a letter or digit (a key glued to a word is not the
# format), EXCEPT after a JSON-escaped control character (a literal backslash and `n`, `r`
# or `t`: the `n` is a letter, and through 0.4.6 `"\nghp_..."` in a pasted JSON string went
# out with no hit) or after a percent-encoded character (`%3D` before a key in a URL-encoded
# form body; `D` is a letter). Each alternative is a fixed-width lookbehind. The Telegram
# shape keeps its own boundaries (KEY_FORMATS_OWN_BOUNDARY), so the ARN exclusion it relies
# on is untouched.
KEY_START = r"(?:(?<![A-Za-z0-9])|(?<=\\[nrt])|(?<=%[0-9A-Fa-f]{2}))"

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # First: a URL's userinfo may hold any of the formats below, and EMAIL must never see it.
    ("URL_CREDENTIAL", URL_CREDENTIAL),
    ("KEY", re.compile(KEY_START + r"(?:" + _alternation(KEY_FORMATS) + r")(?![A-Za-z0-9])")),
    ("KEY", re.compile(_alternation(KEY_FORMATS_OWN_BOUNDARY))),
    ("WEBHOOK", re.compile(KEY_START + r"(?:" + _alternation(WEBHOOK_FORMATS) + r")")),
    # A JWT after `token_` or a JSON escape: `\b` refused an underscore through 0.4.6.
    ("JWT", re.compile(KEY_START + r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")),
    # A terminated block, PEM or PGP (`-----BEGIN PGP PRIVATE KEY BLOCK-----`; through 0.4.6
    # only `PRIVATE KEY-----` exactly). Without an END line anywhere after it (a paste cut
    # short), the block is the BEGIN line and every following line up to the first blank line
    # or the end of the text: key material has no blank lines, and over-taking a line of
    # prose after an unterminated key is the safe way to be wrong.
    ("PEM", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|[^\r\n]*(?:\r?\n[^\r\n]+)*)"
    )),
    ("BEARER", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{12,}")),
    # Quotes around the secret are optional; 0.1.0 required them and missed `key = value` lines.
    # Any run of spaces around the `=` or `:` is allowed; through 0.4.6 the gap between the
    # keyword and the value was eight characters at most, so `aws_secret_access_key   =   ...`
    # (padded, as a linter aligns it) went out with no hit while a single space was caught.
    ("AWS_SECRET", re.compile(r"(?i)aws(.{0,12})?(secret|access).{0,8}?\s*[:=]?\s*['\"]?[A-Za-z0-9/+=]{20,}['\"]?")),
    # The same secrets under the names the SDKs and the CLI print, with no `aws` in front:
    # `"SecretAccessKey": "..."`, `secret_access_key = ...`, `"SessionToken": "..."`,
    # `aws_session_token = ...`. Through 0.4.6 (and 0.4.7's first cut) a standalone line in
    # any of these forms had no hit, and assume-role output was held only by its ASIA id.
    ("AWS_SECRET", re.compile(r"(?i)(?<![A-Za-z0-9])(?:secret[_ -]?access[_ -]?key|session[_ -]?token)\b['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{20,}['\"]?")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    # North American shapes, plus any number written with a leading `+` and country code
    # (`+44 20 7946 0958`): the plus sign is the signal, so no bare-digit international
    # shape is attempted, since that would take dates and ids.
    ("PHONE", re.compile(
        r"(?:(?<![A-Za-z0-9])(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"
        r"|(?<![A-Za-z0-9])\+\d{1,3}(?:[\s.\-]?\d){8,12}(?![0-9]))"
    )),
    # Exactly a card's shape: contiguous, 4-4-4-4 with an optional 1-to-3-digit tail, or
    # 4-6-5. Through 0.4.6 the pattern took any run of digits and separators and then asked
    # the validator, so in `qty 2 4111 1111 1111 1111` the match started at the `2`, the
    # 1-4-4-4-4 shape was refused, and the card inside was never tried: a leading count or
    # year hid any card after it. Now the shape is in the pattern and the scan restarts at
    # the next digit group.
    ("CARD", re.compile(r"\b(?:\d{13,19}|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}(?:[ -]\d{1,3})?|\d{4}[ -]\d{6}[ -]\d{5})\b")),
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
# `case`, `id` and `part` are ordinary English (`in case: call 555-...`, `my cell, id ...`)
# and through 0.4.6 any of them before a number made it an identifier; now they count only
# with an explicit `#`, `no.` or `number` after them. The nouns that name identifiers on
# their own keep the looser rule.
ORDER_WORDS = re.compile(
    r"(?i)\b(?:(?:order|invoice|ref|reference|sku|ticket|po|tracking|serial)\b\s*(?:#|no\.?|number|:)?"
    r"|(?:case|id|part)\b\s*(?:#|no\.?|number))\s*$"
)


def phone_context_ok(m: re.Match[str]) -> bool:
    """A phone-shaped number after 'Order', 'invoice #', 'ticket', 'ref:', 'case #' is an identifier, not a phone."""
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
VALIDATORS = {"CARD": card_shape_ok, "PHONE": phone_context_ok, "URL_CREDENTIAL": url_password_is_real}

# What replaces a match. Most labels replace the whole match with the bracket token; a URL
# keeps its scheme and host around the token, so `postgres://[URL_CREDENTIAL]@localhost/db`
# still reads as a local postgres URL. The `@` stays: the token's `]` is not an email
# character, so EMAIL cannot re-take `[URL_CREDENTIAL]@db.example.com`.
REPLACEMENTS = {"URL_CREDENTIAL": lambda m: f"{m.group(1)}[URL_CREDENTIAL]@{m.group(4)}"}


def _sub_with_retry(pat: re.Pattern[str], text: str, replace: Callable[[re.Match[str]], str | None]) -> str:
    """``pat.sub``, except that a match the validator refuses is retried one character on.

    ``re.sub`` moves past a refused match whole, so in ``qty 2 4111 1111 1111 1111`` the card
    hides behind the count that the pattern took first, and a year before a card did the same.
    (Through 0.4.6 every validated label had this hole.) Here a refusal resumes the search at
    the next character, so the candidate that starts inside the refused span is still tried.
    """
    pieces: list[str] = []
    pos = 0
    while (m := pat.search(text, pos)) is not None:
        token = replace(m)
        if token is None:
            # Refused. Keep the text up to the character after the match's start, and go on from there.
            pieces.append(text[pos:m.start() + 1])
            pos = m.start() + 1
            continue
        pieces.append(text[pos:m.start()])
        pieces.append(token)
        pos = m.end() if m.end() > m.start() else m.start() + 1
    pieces.append(text[pos:])
    return "".join(pieces)


def _apply_patterns(text: str) -> tuple[str, list[str]]:
    hits: list[str] = []
    out = text
    for label, pat in PATTERNS:
        validator = VALIDATORS.get(label)
        replacement = REPLACEMENTS.get(label)

        def _replace(m: re.Match[str], label=label, validator=validator, replacement=replacement) -> str | None:
            if validator is not None and not validator(m):
                return None
            return replacement(m) if replacement is not None else f"[{label}]"

        new = _sub_with_retry(pat, out, _replace) if validator is not None else pat.sub(_replace, out)
        if new != out:
            hits.append(label)
            out = new
    return out, hits


def redact(text: str, denylist: list[str] | None = None) -> RedactionResult:
    out, hits = _apply_patterns(text)
    # Longest entry first: with `Jane` and `Jane Doe` both listed, `Jane` used to win and leave
    # `[NAME] Doe`; `Acme` before `Acme Robotics Ltd` left `Robotics Ltd`. Ties keep the order given.
    for name in sorted(denylist or [], key=lambda n: -len(n.strip())):
        for pat in denylist_patterns(name):
            if pat.search(out):
                hits.append("NAME")
                out = pat.sub("[NAME]", out)
    return RedactionResult(text=out, hits=sorted(set(hits)))


# Denylist entries shorter than this are ignored: a two-letter term matched as a whole word
# would still take ordinary text (`Al`, `Ed`, `Jo` are words as well as names). The CLI
# says so when it loads the file.
MIN_DENYLIST_CHARS = 3

_TOKEN = re.compile(r"\[[A-Z_]+\]")


@functools.lru_cache(maxsize=4096)
def denylist_patterns(name: str) -> tuple[re.Pattern[str], ...]:
    """The compiled patterns for one denylist entry, cached: redact() runs once per sent string.

    Whole-word: "Ann" must not turn "Anniversary" into "[NAME]iversary". Lookarounds rather
    than \b so a name that starts or ends with punctuation still matches at a word edge. A
    multi-word entry matches across any run of whitespace, hyphens or underscores: a newline,
    because hard-wrapped markdown puts "Jane" at the end of one line and "Doe" at the start
    of the next (through 0.4.6 only the exact spacing matched), and `jane-doe.md`,
    `Jane_Doe.md` or `[[jane-doe]]`, because that is how the name reaches a filename and a
    wikilink (through 0.4.10 those left as written while the title read [NAME]). The
    residual is a name run together with no separator, `JaneDoe`: no rule tells it from a
    word, so it is not matched; add it to the denylist as its own entry if it occurs. An entry that itself holds
    something the patterns rewrite (`Jane Doe <jane@example.com>`) is also matched in its
    own redacted form (`Jane Doe <[EMAIL]>`), because the patterns run first and would
    otherwise leave `Jane Doe <` behind; a form that is nothing but tokens is not used.
    """
    name = name.strip()
    if len(name) < MIN_DENYLIST_CHARS:
        return ()
    forms = [name]
    redacted = _apply_patterns(name)[0]
    if redacted != name and len(_TOKEN.sub("", redacted).strip()) >= MIN_DENYLIST_CHARS:
        forms.append(redacted)
    return tuple(
        re.compile(r"(?<![A-Za-z0-9])" + r"[\s_\-]+".join(re.escape(w) for w in form.split()) + r"(?![A-Za-z0-9])", re.IGNORECASE)
        for form in forms
    )


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
