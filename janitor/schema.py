"""Load a question set from YAML and build TypeSafe questions from it.

Everything Jev is asked lives in the YAML: the instructions of every question, the options
of every Choice, the levels of every Score. Through 0.4.2 the two instruction sentences of
the Choice and the Score were Python strings here, so the fingerprint stamped on every vote
covered the options and the nouls but not those sentences. Since 0.4.3 the fingerprint covers
all wording, because the file holds all of it, and ``question_payloads`` is the one place
the wire form of a question set is built: the SDK objects are made from it, the bill
measures it, and a test compares it byte for byte with what the SDK serializes.

The format describes a whole question set, not one tool's questions, so a different caller
can bring its own Choice, Scores and Nouls in the same file shape::

    questions:
      bucket:
        type: choice
        instructions: Which vault bucket should this note live in? ...
        options:
          durable_memory: A standing fact ...
      persist:
        type: score
        instructions: How worth keeping is this note ...?
        levels:
          - drop ...
          - park ...
      contains_secret:
        type: noul
        instructions: Does this note contain credentials ...?

The vault scan requires ``bucket`` (a Choice), ``persist`` (a Score) and the five nouls in
``REQUIRED_NOULS``; ``load_taxonomy`` checks for them. A file in the 0.4.x layout
(``buckets`` / ``persist`` / ``nouls`` at the top level) is still accepted and is upgraded
in memory with the two instruction sentences that were built in, so an existing custom
taxonomy produces exactly the wire it did; its fingerprint, being a hash of that file,
does not cover those two sentences. Convert it to the ``questions`` layout to close that.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

DEFAULT_TAXONOMY = Path(__file__).resolve().parent / "taxonomies" / "vault_memory.yaml"  # inside the package, so a wheel ships it
MAX_CHOICE_OPTIONS = 255  # measured: 256 -> 400 "Too many choices"
MAX_SCORE_LEVELS = 10  # measured: 25 -> 400 "Too many score levels"
REQUIRED_NOULS = ("contains_secret", "looks_like_duplicate", "records_a_decision", "is_actionable", "safe_to_leave_in_git")
QUESTION_TYPES = ("choice", "score", "noul")

# The two sentences that were Python strings through 0.4.2. Kept only to upgrade a taxonomy
# file in the old layout to the same wire it always produced.
LEGACY_INSTRUCTIONS = {
    "bucket": "Which vault bucket should this note live in? Judge the note itself, not the filename, unless the body is empty.",
    "persist": "How worth keeping is this note as long-term vault memory?",
}


def taxonomy_fingerprint(path: Path | None = None) -> str:
    """Short content hash of the taxonomy file, stamped next to every vote.

    The wording in the YAML is the whole knowledge base for this task, and votes move when
    it changes. Without this a historical stamp is uninterpretable after any edit.
    """
    target = path or DEFAULT_TAXONOMY
    # Normalize line endings so a CRLF checkout on Windows fingerprints the same as LF elsewhere.
    text = target.read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _upgrade_legacy(data: dict[str, Any], target: Path) -> dict[str, Any]:
    """The 0.4.x layout to the ``questions`` layout, with the built-in sentences filled in."""
    if not data.get("buckets"):
        raise ValueError(f"taxonomy missing buckets: {target}")
    if not isinstance(data.get("persist"), list):
        raise ValueError(f"taxonomy needs an ordered 'persist' rubric with at least two levels: {target}")
    questions: dict[str, Any] = {
        "bucket": {"type": "choice", "instructions": LEGACY_INSTRUCTIONS["bucket"], "options": dict(data["buckets"])},
        "persist": {"type": "score", "instructions": LEGACY_INSTRUCTIONS["persist"], "levels": list(data["persist"])},
    }
    for name, instructions in (data.get("nouls") or {}).items():
        questions[name] = {"type": "noul", "instructions": instructions}
    return {"questions": questions}


def _validate(questions: dict[str, Any], target: Path) -> None:
    for name, q in questions.items():
        if not isinstance(q, dict) or q.get("type") not in QUESTION_TYPES:
            raise ValueError(f"question '{name}' needs a type in {QUESTION_TYPES}: {target}")
        if not isinstance(q.get("instructions"), str) or not q["instructions"].strip():
            raise ValueError(f"question '{name}' needs instructions: {target}")
        # API limits measured 2026-09-21: a Choice accepts at most 255 options, a Score at most 10 levels.
        # Rejecting here means a bad taxonomy fails before the pre-flight, not on the first request.
        if q["type"] == "choice":
            if not isinstance(q.get("options"), dict) or not q["options"]:
                raise ValueError(f"choice '{name}' needs a mapping of options: {target}")
            if len(q["options"]) > MAX_CHOICE_OPTIONS:
                raise ValueError(f"choice '{name}' has {len(q['options'])} options; the API accepts at most {MAX_CHOICE_OPTIONS} options in a Choice: {target}")
        elif q["type"] == "score":
            if not isinstance(q.get("levels"), list) or len(q["levels"]) < 2:
                raise ValueError(f"score '{name}' needs an ordered list of at least two levels: {target}")
            if len(q["levels"]) > MAX_SCORE_LEVELS:
                raise ValueError(f"score '{name}' has {len(q['levels'])} levels; the API accepts at most {MAX_SCORE_LEVELS} levels in a Score: {target}")


def load_question_set(path: Path) -> dict[str, Any]:
    """Any question set in the ``questions`` layout (or the 0.4.x layout), validated against the API limits only."""
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or not data:
        raise ValueError(f"taxonomy is empty: {path}")
    if "questions" not in data:
        data = _upgrade_legacy(data, path)
    questions = data["questions"]
    if not isinstance(questions, dict) or not questions:
        raise ValueError(f"taxonomy needs a 'questions' mapping: {path}")
    _validate(questions, path)
    out: dict[str, Any] = {"questions": questions}
    # Which Choice the review floor applies to (records path). Default: the first Choice in the
    # file. Named here so behaviour does not silently depend on file order.
    review = data.get("review_choice")
    if review is not None:
        if questions.get(review, {}).get("type") != "choice":
            raise ValueError(f"review_choice {review!r} is not a choice in this question set: {path}")
        out["review_choice"] = review
    return out


def review_choice(question_set: dict[str, Any]) -> str | None:
    """The Choice the review floor applies to: the declared one, else the first Choice in the file, else None."""
    declared = question_set.get("review_choice")
    if declared:
        return str(declared)
    return next((name for name, q in question_set["questions"].items() if q["type"] == "choice"), None)


def load_taxonomy(path: Path | None = None) -> dict[str, Any]:
    """The vault scan's question set: ``bucket``, ``persist`` and the five required nouls must be present."""
    target = path or DEFAULT_TAXONOMY
    data = load_question_set(target)
    questions = data["questions"]
    if questions.get("bucket", {}).get("type") != "choice":
        raise ValueError(f"taxonomy missing buckets: the vault scan needs a choice named 'bucket': {target}")
    if questions.get("persist", {}).get("type") != "score":
        raise ValueError(f"taxonomy needs an ordered 'persist' rubric with at least two levels: {target}")
    missing = [n for n in REQUIRED_NOULS if questions.get(n, {}).get("type") != "noul"]
    if missing:
        raise ValueError(f"taxonomy missing nouls {missing}: {target}")
    return data


def buckets(taxonomy: dict[str, Any]) -> dict[str, str]:
    return taxonomy["questions"]["bucket"]["options"]


def persist_levels(taxonomy: dict[str, Any]) -> list[str]:
    return taxonomy["questions"]["persist"]["levels"]


def nouls(taxonomy: dict[str, Any]) -> dict[str, str]:
    return {name: q["instructions"] for name, q in taxonomy["questions"].items() if q["type"] == "noul"}


def question_payloads(taxonomy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The wire form of every question, in file order, without the SDK.

    This is what the SDK serializes for each question object (``model_dump``), so it is
    what the bill counts as riding along with every call, and what the offline path can
    fingerprint and measure without importing the SDK.
    """
    out: dict[str, dict[str, Any]] = {}
    for name, q in taxonomy["questions"].items():
        if q["type"] == "choice":
            out[name] = {"type": "choice", "instructions": q["instructions"], "criteria": dict(q["options"])}
        elif q["type"] == "score":
            out[name] = {"type": "score", "instructions": q["instructions"], "criteria": list(q["levels"])}
        else:
            out[name] = {"type": "noul", "instructions": q["instructions"]}
    return out


def build_questions(taxonomy: dict[str, Any]) -> dict[str, Any]:
    """The typed SDK questions, one per entry of the file, in file order. Live mode only; ``--offline`` never calls this."""
    try:
        from typesafe_sdk import Choice, Noul, Score
    except ImportError as exc:
        raise RuntimeError(
            "Live mode needs the TypeSafe SDK. Install it with: pip install 'jev-the-janitor[jev]' "
            "(or pass --offline to use the fixture client, which is not Jev)."
        ) from exc
    built: dict[str, Any] = {}
    for name, payload in question_payloads(taxonomy).items():
        if payload["type"] == "choice":
            built[name] = Choice(instructions=payload["instructions"], criteria=payload["criteria"])
        elif payload["type"] == "score":
            built[name] = Score(instructions=payload["instructions"], criteria=payload["criteria"])
        else:
            built[name] = Noul(instructions=payload["instructions"])
    return built
