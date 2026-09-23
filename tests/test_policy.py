from janitor.client import Vote
from janitor.policy import decide


def _vote(**kwargs) -> Vote:
    base = dict(
        bucket="durable_memory",
        bucket_probabilities={"durable_memory": 0.9},
        bucket_confidence=0.85,
        persist=1.8,
        persist_confidence=0.8,
        contains_secret=0.02,
        looks_like_duplicate=0.05,
        records_a_decision=0.2,
        is_actionable=0.3,
        safe_to_leave_in_git=0.9,
        model="fixture",
    )
    base.update(kwargs)
    return Vote(**base)


def test_secret_quarantines():
    action = decide(_vote(contains_secret=0.91))
    assert action.name == "quarantine"


def test_low_confidence_stamps_review():
    action = decide(_vote(bucket="needs_review", bucket_confidence=0.4))
    assert action.name == "frontmatter"
    assert "needs_review" in action.reason or "confidence" in action.reason
