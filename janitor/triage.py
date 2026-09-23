"""Local triage: what code can decide without a model, decided before any request.

Most of a large vault is arithmetic. An empty body, an exact duplicate of a note already
in the plan, a credential that a high-precision regex matched, and a note a person has
locked are all settled here, in code, with tests, and are never sent. Jev is spent on the
ambiguous middle. Every row says which judge decided it: ``judge: local`` or ``judge: jev``.

This is hashes, path rules and regexes. It is not a second classifier, and the offline
keyword client stays a plumbing fake: if a rule here needs to read prose to decide, it
does not belong here.
"""

from __future__ import annotations

from dataclasses import dataclass

from janitor.client import Vote
from janitor.index import IndexedNote, VaultIndex
from janitor.policy import HIGH_PRECISION_SECRETS, Action, decide

LOCAL_MODEL = "local"


@dataclass
class LocalDecision:
    vote: Vote
    action: Action
    rule: str  # which rule fired: empty | duplicate | secret


def _vote(bucket: str, *, persist: float, secret: float = 0.0, duplicate: float = 0.0) -> Vote:
    """A vote with the certainty of arithmetic. Confidence 1.0 keeps it out of the review pile."""
    return Vote(
        bucket=bucket,
        bucket_probabilities={bucket: 1.0},
        bucket_confidence=1.0,
        persist=persist,
        persist_confidence=1.0,
        contains_secret=secret,
        looks_like_duplicate=duplicate,
        records_a_decision=0.0,
        is_actionable=0.0,
        safe_to_leave_in_git=0.0 if secret else 1.0,
        model=LOCAL_MODEL,
    )


def local_decision(item: IndexedNote, index: VaultIndex, own_hits: list[str]) -> LocalDecision | None:
    """Return the local decision for a scanned note, or None when Jev should see it.

    Order matters. A credential is checked first, because a note that holds one is moved
    whatever else is true of it. Then emptiness, then exact duplication (the first copy in
    plan order is canonical and goes to Jev; every later copy is junk by definition of the
    taxonomy's own words, "duplicate noise").
    """
    secrets = [h for h in own_hits if h in HIGH_PRECISION_SECRETS]
    if secrets:
        vote = _vote("needs_review", persist=1.0, secret=1.0)
        action = decide(vote, hits=secrets)  # the same policy path a Jev vote takes; quarantine on local hits
        return LocalDecision(vote, action, "secret")
    if item.empty:
        vote = _vote("junk", persist=0.0)
        return LocalDecision(vote, Action("frontmatter", "empty body or headings only: decided locally"), "empty")
    first = index.exact_duplicate_of(item.rel)
    if first is not None:
        vote = _vote("junk", persist=0.0, duplicate=1.0)
        return LocalDecision(vote, Action("frontmatter", f"exact duplicate of {first}: decided locally"), "duplicate")
    return None
