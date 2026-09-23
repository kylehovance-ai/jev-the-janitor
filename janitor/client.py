"""Talk to TypeSafe Jev. Mockable for tests and --offline fixtures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

# typesafe_sdk is imported only inside TypeSafeJanitorClient so --offline works cold.


@dataclass
class Vote:
    bucket: str
    bucket_probabilities: dict[str, float]
    bucket_confidence: float
    persist: float
    persist_confidence: float
    contains_secret: float
    looks_like_duplicate: float
    records_a_decision: float
    is_actionable: float
    safe_to_leave_in_git: float
    model: str
    input_tokens: int = 0


class JanitorClient(Protocol):
    def vote(self, state: dict[str, Any], questions: dict) -> Vote: ...


class TypeSafeJanitorClient:
    def __init__(self, model: str | None = None) -> None:
        from typesafe_sdk import TypeSafeClient

        kwargs = {}
        if model:
            kwargs["model"] = model
        self._client = TypeSafeClient(**kwargs)

    def vote(self, state: dict[str, Any], questions: dict) -> Vote:
        response = self._client.system_one(state=state, questions=questions)
        return vote_from_response(response)


NOUL_NAMES = ("contains_secret", "looks_like_duplicate", "records_a_decision", "is_actionable", "safe_to_leave_in_git")


def vote_from_response(response: Any) -> Vote:
    """Map a SystemOneResponse onto a Vote.

    The SDK returns one ``answers`` dict keyed by question name; each answer carries a
    ``type`` of ``choice`` / ``score`` / ``noul``. Missing or mistyped answers raise instead
    of being silently defaulted, so a taxonomy/schema mismatch surfaces on the first call.
    """
    answers = response.answers
    expected = {"bucket": "choice", "persist": "score", **{n: "noul" for n in NOUL_NAMES}}
    missing = [name for name in expected if name not in answers]
    if missing:
        raise ValueError(f"Jev response is missing answers for: {', '.join(missing)}")
    for name, kind in expected.items():
        got = getattr(answers[name], "type", None)
        if got != kind:
            raise ValueError(f"Jev answer {name!r} has type {got!r}, expected {kind!r}")

    bucket = answers["bucket"]
    persist = answers["persist"]
    usage = getattr(response, "usage", None)
    return Vote(
        bucket=str(bucket.choice),
        bucket_probabilities={str(k): float(v) for k, v in bucket.probabilities.items()},
        bucket_confidence=float(bucket.confidence),
        persist=float(persist.score),
        persist_confidence=float(persist.confidence),
        contains_secret=float(answers["contains_secret"].noul),
        looks_like_duplicate=float(answers["looks_like_duplicate"].noul),
        records_a_decision=float(answers["records_a_decision"].noul),
        is_actionable=float(answers["is_actionable"].noul),
        safe_to_leave_in_git=float(answers["safe_to_leave_in_git"].noul),
        model=str(getattr(response, "model", "") or "jev-latest"),
        input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
    )


class FixtureClient:
    """Deterministic stand-in so CI and --offline work without a key."""

    def vote(self, state: dict[str, Any], questions: dict) -> Vote:
        title = str(state.get("title") or "").lower()
        excerpt = str(state.get("excerpt") or "").lower()
        blob = f"{title} {excerpt}"
        if "[key]" in blob or "secret" in blob or "sk-" in blob or "akia" in blob:
            bucket = "needs_review"
            secret = 0.97
        elif "tired" in blob or "coffee" in blob or "scratch" in blob or "todo later" in blob or "asdf" in blob:
            bucket = "ephemeral"
            secret = 0.02
        elif "lorem ipsum" in blob or not excerpt.strip():
            bucket = "junk"
            secret = 0.01
        elif ("nightly" in blob or "daily run" in blob or "run report" in blob or "digest" in blob) and ("scan" in blob or "report" in blob or "digest" in blob):
            bucket = "log_entry"
            secret = 0.03
        elif "we decided" in blob or "decision:" in blob:
            bucket = "project_decision"
            secret = 0.03
        elif "```" in blob or "benchmark" in blob or "pytest" in blob:
            bucket = "code_note"
            secret = 0.02
        elif "https://" in blob or "see also" in blob:
            bucket = "reference"
            secret = 0.02
        else:
            bucket = "durable_memory"
            secret = 0.04
        persist = {"junk": 0.1, "ephemeral": 0.6, "needs_review": 1.1, "log_entry": 0.9, "code_note": 1.7, "project_decision": 1.9, "durable_memory": 2.0, "reference": 1.4}.get(bucket, 1.0)
        return Vote(
            bucket=bucket,
            bucket_probabilities={bucket: 0.86},
            bucket_confidence=0.8,
            persist=persist,
            persist_confidence=0.75,
            contains_secret=secret,
            looks_like_duplicate=0.12 if "duplicate" in blob else 0.05,
            records_a_decision=0.88 if bucket == "project_decision" else 0.2,
            is_actionable=0.7 if bucket == "project_decision" else 0.3,
            safe_to_leave_in_git=0.1 if secret > 0.5 else 0.8,
            model="fixture",
            input_tokens=0,
        )
