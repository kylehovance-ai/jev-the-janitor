"""The review pile and the lock: a human decision that survives the next scan.

The pile is written only where the operator says (--review-pile FILE), never by default.
A note with janitor.locked: true is skipped entirely: no request, no rewrite, no new at.
"""

from pathlib import Path

import frontmatter

from janitor import cli
from janitor.client import FixtureClient, Vote
from janitor.scan import scan_vault

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"


class LowConfidence(FixtureClient):
    """Every vote is a near-tie, so every judged note lands in the pile."""

    def vote(self, state, questions):
        v = super().vote(state, questions)
        return Vote(**{**v.__dict__, "bucket_confidence": 0.36, "bucket_probabilities": {v.bucket: 0.36, "ephemeral": 0.34}})


def _vault(tmp_path: Path) -> Path:
    vault = tmp_path / "vault"
    (vault / "notes").mkdir(parents=True)
    (vault / "notes" / "maybe.md").write_text("# Maybe\n\ncould be anything\n", encoding="utf-8")
    (vault / "notes" / "leak.md").write_text(f"# Leak\n\n{KEY}\n", encoding="utf-8")
    (vault / "notes" / "done.md").write_text("---\njanitor:\n  bucket: durable_memory\n  locked: true\n---\n# Done\n\na person read this\n", encoding="utf-8")
    return vault


def test_nothing_is_written_unless_asked(tmp_path: Path, monkeypatch):
    vault = _vault(tmp_path)
    monkeypatch.setattr(cli, "FixtureClient", LowConfidence)
    before = sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*"))
    assert cli.main([str(vault), "--offline"]) == 0
    assert sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*")) == before
    assert not list(tmp_path.rglob("review*.md"))


def test_pile_lists_review_and_quarantine_as_wikilinks_and_counts_locked(tmp_path: Path, monkeypatch, capsys):
    vault = _vault(tmp_path)
    monkeypatch.setattr(cli, "FixtureClient", LowConfidence)
    pile = tmp_path / "out" / "review.md"
    assert cli.main([str(vault), "--offline", "--review-pile", str(pile)]) == 0
    assert f"review pile: {pile}" in capsys.readouterr().err
    text = pile.read_text(encoding="utf-8")
    assert text.startswith("# jev-janitor review pile: 2 notes under vault/ (1 already locked and skipped)")
    assert "- [[notes/maybe]] suggested `" in text and "confidence 0.36, margin 0.02 (jev)" in text
    assert "- [[notes/leak]] quarantine: local redaction hit: KEY (not moved (dry run))" in text
    assert "done" not in text.split("\n", 3)[3]  # the locked note is counted, not listed
    assert "locked: true" in text  # the instruction to close the loop


def test_locked_note_survives_apply_and_shrinks_the_pile(tmp_path: Path, monkeypatch):
    vault = _vault(tmp_path)
    monkeypatch.setattr(cli, "FixtureClient", LowConfidence)
    done_before = (vault / "notes" / "done.md").read_bytes()
    assert cli.main([str(vault), "--offline", "--apply"]) == 0
    assert (vault / "notes" / "done.md").read_bytes() == done_before  # no new `at`, nothing rewritten
    stamped = frontmatter.load(vault / "notes" / "maybe.md", encoding="utf-8").metadata["janitor"]
    assert stamped["bucket"] == "needs_review" and stamped["suggested_bucket"]
    # the person decides: keeps the suggestion, locks it
    text = (vault / "notes" / "maybe.md").read_text(encoding="utf-8")
    (vault / "notes" / "maybe.md").write_text(text.replace("  bucket: needs_review\n", "  bucket: durable_memory\n  locked: true\n"), encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(vault, client=LowConfidence(), offline=True, apply=True)}
    assert rows["notes/maybe.md"]["action"] == "skip_locked" and rows["notes/done.md"]["action"] == "skip_locked"
    assert frontmatter.load(vault / "notes" / "maybe.md", encoding="utf-8").metadata["janitor"]["bucket"] == "durable_memory"
