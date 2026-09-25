"""The bill, before consent: how much would leave, what it would cost, and a ceiling.

Estimated from the actual redacted payloads that prepare_vault built, not from a constant
per note. The README's "well under a tenth of a cent" is a 26-note measurement; this is
the number for the vault in front of you. It is the number that decides whether a live
scan of a 20,000-note corpus happens, so it is computed by code and printed, not done
in someone's head.

It is a range, not a point, and both ends are measured, not inferred. The basis is
(payload chars + question chars per call) over the API's input_tokens, because that is what
the estimate divides: the taxonomy's questions ride along with every call (2,086 chars at
the default taxonomy, the questions' wire form; through 0.4.2 a 1,681-char proxy) and the
API counts them. On that basis the first live run of 0.4.0 on 31 real notes (350,090
payload chars, 117,633 tokens, 2026-09-22) came in at 3.53 chars/token overall, and the
first live run on a synthetic test corpus (182 synthetic notes, 287,073 tokens, the same day) at 3.15.
Both sit inside 2.8 to 3.8.

Then the floor was breached, by text that is not notes: the first live run on the 2,000-note
synthetic corpus tier (1,468 notes before it was stopped for an unrelated reason, 2,589,711
payload chars, 2,604,345 tokens, 2026-09-22) measured 2.17 overall, 2.04 to 3.53 per note,
on generated combinatorial filler (ids, hashes, log-like lines) that tokenizes far more
densely than prose. Synthetic, so by the rule above no constant moves on it; but any vault
full of generated logs, ids or code will look like it, and the pessimistic estimate was 22.5%
light (2.17 against the 2.8 anchor; the bill came in 29% over it). So the ceiling does two jobs now: the pre-flight refuses on the estimate, and the run
stops on the meter (scan.meter_check) when the API's own input_tokens have cost more than
the ceiling, whatever the text. With --over-budget the accepted bill's pessimistic end is
the meter's limit, so an accepted bill is never an unbounded one.

Through 0.4.0 the measured line divided payload chars alone by the same tokens, which
printed 2.98 for the 31-note run and 1.83 for the 182-note run, and flagged the second as
outside the range with advice to re-anchor, when the pre-flight's estimate had in fact
bracketed the real bill. Short notes make that error worst, because the fixed question cost
dominates. The earlier anchors before either run (5.37 from invented prose in a capacity
probe, 3.66 inferred from refusals at the character guard) were wrong in the dangerous
direction, and the rule since is that these constants move only on a measurement made on
this basis. The guard refuses on the pessimistic end and prints the optimistic end in the
same breath, so --over-budget is an informed choice. After a live run the measured figure
is printed next to the range and flagged when it falls outside it, which is how these
constants get corrected again when the next corpus disagrees.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from janitor.journal import canonical

if TYPE_CHECKING:
    from janitor.plan import PlanEntry
    from janitor.scan import Prepared

CHARS_PER_TOKEN_LOW = 2.8  # pessimistic: below both runs measured on the estimate's basis (3.15 over 182 short synthetic notes, 3.53 over 31 real ones)
CHARS_PER_TOKEN_HIGH = 3.8  # optimistic: above both runs overall; single real notes went higher, invented prose reached 5.37, but a bill is a sum
# Published input-token price, and measured once against a real invoice: 2026-09-22 UTC,
# $5.04 charged for 118,975,559 input and 8,436,363 output tokens; input-only at this price
# is $4.997, within 0.9%, so the bill prices input only and any output charge is at most
# about $0.005/M. Re-check the dashboard before quoting it after a price change.
PRICE_PER_MILLION_USD = 0.042
# The guard is against a surprise, not a routine run. The reference workload (a real
# 18,738-note vault, 86,397,152 payload chars at the default cap) prints $1.39 to $1.88 and
# projects to about $1.49 at the 31-note ratio; it has never been run live at this version,
# so that is a projection, not a measurement. Headroom at the pessimistic end is 6%.
DEFAULT_MAX_USD = 2.00
LARGEST_FOLDERS = 5


def tokens_for(chars: int, chars_per_token: float) -> int:
    return math.ceil(chars / chars_per_token)


def usd_for(tokens: int) -> float:
    return tokens / 1_000_000 * PRICE_PER_MILLION_USD


def usd(amount: float) -> str:
    """Dollars to the cent, or to the hundredth of a cent under a dime: `$0.01 to $0.01` said nothing.

    Every ceiling print goes through here too (the bill's line, both refusals on both paths,
    the meter's abort), so a ceiling and a spend are never shown to different places:
    "$0.0075 is over the ceiling of $0.01" read as a contradiction.
    """
    return f"${amount:,.2f}" if amount >= 0.10 else f"${amount:,.4f}"


USD_MAX_DECIMALS = 10


def usd_apart(a: float, b: float) -> tuple[str, str]:
    """Two amounts at one precision, widened until the strings differ (or the cap is hit).

    For a spend that passed a ceiling by less than usd() can show: "$0.0058 passed the
    ceiling $0.0058" is true and unreadable; "$0.005801 passed the ceiling $0.005800" is both.
    """
    decimals = 2 if min(a, b) >= 0.10 else 4
    while decimals < USD_MAX_DECIMALS and f"{a:,.{decimals}f}" == f"{b:,.{decimals}f}":
        decimals += 1
    return f"${a:,.{decimals}f}", f"${b:,.{decimals}f}"


@dataclass
class Bill:
    to_send: int = 0
    cached: int = 0
    local: int = 0
    locked: int = 0
    errors: int = 0
    undecodable: int = 0  # finding: not valid UTF-8; never sent
    unreadable_headers: int = 0  # finding: frontmatter that no YAML reader can parse; judged on the body
    age_from_mtime: int = 0  # finding: the age comes from the filesystem (no creation date in the frontmatter, none recorded by a stamp) and would reset on a clone
    dated: int = 0  # notes whose age came from a frontmatter creation stamp
    stamp_dated: int = 0  # notes whose age came from the date the janitor's stamp recorded (0.5.2); it does not reset
    skipped: Counter = field(default_factory=Counter)  # rule -> notes
    payload_chars: int = 0  # canonical JSON of every state that would be sent
    question_chars: int = 0  # the taxonomy text rides along with every call
    folders: Counter = field(default_factory=Counter)  # folder -> payload chars
    folder_notes: Counter = field(default_factory=Counter)
    max_usd: float | None = DEFAULT_MAX_USD

    @property
    def chars(self) -> int:
        return self.payload_chars + self.question_chars * self.to_send

    @property
    def tokens_high(self) -> int:
        """Pessimistic: every note at the dense end of what was measured. The guard uses this."""
        return tokens_for(self.chars, CHARS_PER_TOKEN_LOW)

    @property
    def tokens_low(self) -> int:
        return tokens_for(self.chars, CHARS_PER_TOKEN_HIGH)

    @property
    def usd_high(self) -> float:
        return usd_for(self.tokens_high)

    @property
    def usd_low(self) -> float:
        return usd_for(self.tokens_low)

    @property
    def over_budget(self) -> bool:
        return self.max_usd is not None and self.usd_high > self.max_usd

    def largest_folders(self, n: int = LARGEST_FOLDERS) -> list[tuple[str, int, int]]:
        return [(folder, chars, self.folder_notes[folder]) for folder, chars in self.folders.most_common(n)]


def build_bill(plan: list[PlanEntry], items: list[Prepared], *, question_chars: int = 0,
               max_usd: float | None = DEFAULT_MAX_USD) -> Bill:
    bill = Bill(question_chars=question_chars, max_usd=max_usd)
    for entry in plan:
        if entry.status != "scan":
            bill.skipped[entry.rule] += 1
    for item in items:
        if item.frontmatter_error:
            bill.unreadable_headers += 1
        if item.age_source == "mtime":
            bill.age_from_mtime += 1
        elif item.age_source == "frontmatter":
            bill.dated += 1
        elif item.age_source == "stamp":
            bill.stamp_dated += 1  # through 0.5.2 this fell into neither count and the denominator undercounted
        if item.undecodable is not None:
            bill.undecodable += 1
        elif item.error is not None:
            bill.errors += 1
        elif item.locked:
            bill.locked += 1
        elif item.local is not None:
            bill.local += 1
        elif item.cached_row is not None:
            bill.cached += 1
        else:
            bill.to_send += 1
            chars = len(canonical(item.state or {}))
            bill.payload_chars += chars
            folder = item.rel.rsplit("/", 1)[0] + "/" if "/" in item.rel else "./"
            bill.folders[folder] += chars
            bill.folder_notes[folder] += 1
    return bill


def render_bill(bill: Bill, *, live: bool) -> str:
    """Lines for the pre-flight. A range, labelled an estimate; the ceiling is named."""
    verb = "to send" if live else "a live run would send"
    skipped = sum(bill.skipped.values())
    lines = [
        f"  bill (estimate): {bill.to_send:,} notes {verb}, {bill.cached:,} served from the journal, "
        f"{bill.local:,} decided locally, {bill.locked:,} locked, {skipped:,} skipped, {bill.undecodable:,} undecodable, {bill.errors:,} unreadable",
        f"    payload {bill.payload_chars:,} chars + questions -> ~{bill.tokens_low:,} to {bill.tokens_high:,} input tokens "
        f"({CHARS_PER_TOKEN_HIGH} down to {CHARS_PER_TOKEN_LOW} chars/token, the range measured on real notes), "
        f"~{usd(bill.usd_low)} to {usd(bill.usd_high)} at ${PRICE_PER_MILLION_USD} per million",
    ]
    if bill.unreadable_headers or bill.undecodable:
        lines.append(f"    findings so far: {bill.unreadable_headers:,} note(s) with frontmatter no YAML reader can parse (judged on the body, never restamped), "
                     f"{bill.undecodable:,} not valid UTF-8 (never sent)")
    if bill.age_from_mtime:
        total = bill.age_from_mtime + bill.dated + bill.stamp_dated
        pct = 100 * bill.age_from_mtime / total if total else 0
        lines.append(f"    age: {bill.age_from_mtime:,} of {total:,} readable notes ({pct:.0f}%) take their age from the filesystem "
                     f"(no creation date in their frontmatter, none recorded by a stamp); it resets if this vault is moved, cloned, restored or re-synced"
                     + (f" ({bill.stamp_dated:,} other undated note(s) carry the date the janitor recorded at their first stamp, which does not reset)"
                        if bill.stamp_dated else ""))
    if bill.max_usd is not None:
        state = "OVER" if bill.over_budget else "under"
        lines.append(f"    ceiling {usd(bill.max_usd)}: {state} at the pessimistic end (change it with --max-usd or max_usd in janitor.toml; 0 = none)")
    top = bill.largest_folders()
    if top:
        lines.append("    largest folders by payload:")
        for folder, chars, n in top:
            lines.append(f"      {folder:<40} {chars:>12,} chars {n:>6,} notes")
    return "\n".join(lines)


def over_budget_refusal(bill: Bill) -> str:
    return (f"REFUSED: the pessimistic estimate of {usd(bill.usd_high)} (~{bill.tokens_high:,} input tokens; the optimistic end is "
            f"{usd(bill.usd_low)}) is over the ceiling of {usd(bill.max_usd)}. Nothing was sent. Raise the ceiling with --max-usd, "
            f"or pass --over-budget together with --yes to accept this bill for this run.")


def taxonomy_chars(taxonomy: dict[str, Any]) -> int:
    """How much of the taxonomy's wording rides along with each call: the questions' wire form.

    Through 0.4.2 this was the canonical JSON of the YAML dict (1,681 chars at the default
    taxonomy), a proxy that left out the two instruction sentences then held in Python. It is
    now the serialized questions themselves (2,086 chars), the same bytes the SDK sends.
    """
    from janitor.schema import question_payloads

    return len(canonical(question_payloads(taxonomy)))


def measured_line(rows: list[dict[str, Any]], *, question_chars: int = 0, spend_limit: float | None = None) -> str | None:
    """After a live run: the chars/token the API actually charged, next to the range assumed.

    Uses every fresh vote row that carries the API's input_tokens and its payload size, and
    counts ``question_chars`` once per call on top of the payload, because the estimate did
    and the API did. (Through 0.4.0 this divided the payload alone, so it read low by the
    question share and told the operator to re-anchor when the bill had been right.)
    None when nothing was sent or the client reported no token counts (the fixture does not).
    Says so when the measurement falls outside the assumed range, as a fact about this vault's
    text; the constants move only on a measurement of real notes, and a user does not edit
    this file. ``spend_limit`` is the ceiling the run was metered
    at, as passed to the run (None under --max-usd 0 or offline): the denser-than-notes flag
    says the meter guarded the ceiling only when there was one to guard.
    """
    chars = tokens = notes = 0
    for r in rows:
        if r.get("kind") == "vote" and not r.get("cached") and r.get("judge") == "jev" and r.get("input_tokens"):
            chars += int(r.get("payload_chars") or 0)
            tokens += int(r["input_tokens"])
            notes += 1
    if not tokens or not chars:
        return None
    questions = question_chars * notes
    ratio = (chars + questions) / tokens
    # The range was measured on notes. Text outside it is a fact about this vault, not an
    # instruction to move the constants (a user does not edit bill.py, and by the rule they
    # move only on a measurement of real notes); the meter guards the ceiling when the run
    # was armed with one, and under --max-usd 0 or offline nothing meters the spend.
    if ratio < CHARS_PER_TOKEN_LOW:
        guard = "the ceiling is guarded by the meter, not the estimate" if spend_limit is not None else "no ceiling metered this run"
        flag = f" -- OUTSIDE the assumed range: this text is denser than the notes the range was measured on, so the pre-flight estimate ran light; {guard}"
    elif ratio > CHARS_PER_TOKEN_HIGH:
        flag = " -- OUTSIDE the assumed range: this text is lighter than the notes the range was measured on, so the pre-flight estimate ran high"
    else:
        flag = ""
    return (f"measured: {ratio:.2f} chars/token over {notes:,} sent notes ({chars:,} payload chars + {questions:,} question chars, "
            f"{tokens:,} tokens, {usd(usd_for(tokens))}); the pre-flight assumed {CHARS_PER_TOKEN_HIGH} to {CHARS_PER_TOKEN_LOW} on the same basis{flag}")
