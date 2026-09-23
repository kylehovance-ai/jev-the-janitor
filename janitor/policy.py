"""Turn Jev votes into local actions. Code owns the thresholds."""

from __future__ import annotations

from dataclasses import dataclass, field

from janitor.client import Vote

# Redaction labels precise enough to act on alone. A hit here is a machine-checkable match
# on a credential format, not a guess about a person. EMAIL, PHONE, CARD and NAME are
# deliberately absent: they false-positive on ordinary prose, and quarantining a note is a
# file move. See redact.PATTERNS.
HIGH_PRECISION_SECRETS: tuple[str, ...] = ("KEY", "WEBHOOK", "JWT", "PEM", "AWS_SECRET", "BEARER")


def bucket_margin(probabilities: dict[str, float]) -> float:
    """Top-1 minus top-2 probability. Near-ties flip between identical calls; the margin says how near."""
    top = sorted(probabilities.values(), reverse=True)
    return round(top[0] - (top[1] if len(top) > 1 else 0.0), 3) if top else 0.0


@dataclass
class Action:
    name: str  # frontmatter | quarantine  (skip_sensitive rows are emitted by scan, not decide)
    reason: str
    review: bool = False
    """The stamped bucket is ``needs_review``; the vote's own pick is kept as ``suggested_bucket``.

    The 0.55 floor used to be a reason string only: a 0.36-versus-0.34 near-tie was stamped
    as a hard ``bucket``, and anything that later grouped notes by ``janitor.bucket`` read
    the coin-flip as a decision. Routing to a human has to be visible in the field the
    human's tools read.
    """
    triggers: list[str] = field(default_factory=list)  # why quarantine fired, for the manifest and the row


def decide(
    vote: Vote,
    *,
    hits: list[str] | None = None,
    secret_threshold: float = 0.7,
    git_unsafe_threshold: float | None = None,
    review_confidence: float = 0.55,
) -> Action:
    """Decide what happens to one note.

    ``hits`` are the local redaction labels for this note. They are checked first and on
    their own: redaction runs before the call, so Jev usually sees ``[KEY]`` rather than the
    key, and asking it to confirm a credential it cannot see is the wrong way round. A file
    move must not depend on the model agreeing.

    ``git_unsafe_threshold`` is opt-in and unset by default. ``safe_to_leave_in_git`` is the
    question that explains the bracket tokens, and POLICY.md has always described quarantine
    in its terms, but a threshold picked without a calibration run is a guess that moves
    people's files. Set it explicitly, or leave it off.
    """
    local = [h for h in (hits or []) if h in HIGH_PRECISION_SECRETS]
    if local:
        return Action("quarantine", f"local redaction hit: {', '.join(local)}",
                      triggers=[f"local:{h}" for h in local])
    if vote.contains_secret >= secret_threshold:
        return Action("quarantine", "contains_secret above threshold", triggers=["contains_secret"])
    if git_unsafe_threshold is not None and vote.safe_to_leave_in_git <= git_unsafe_threshold:
        return Action("quarantine", f"safe_to_leave_in_git at or below {git_unsafe_threshold}",
                      triggers=["safe_to_leave_in_git"])
    if vote.bucket == "needs_review" or vote.bucket_confidence < review_confidence:
        return Action("frontmatter", "low confidence or explicit needs_review", review=True)
    if vote.bucket == "junk" and vote.persist < 0.5:
        return Action("frontmatter", "junk, low persist: marked only, never deleted")
    return Action("frontmatter", "normal vote")
