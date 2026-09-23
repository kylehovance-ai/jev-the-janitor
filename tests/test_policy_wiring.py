"""POLICY.md describes what happens to a note. These lock the parts that were only prose.

An outside review of public 0.1.1 (findings 3, 4, 5): five of the six questions were measured,
printed and then ignored by ``decide``; the 0.55 floor was a reason string rather than a
label; and the report had no excerpt field although SECURITY.md told people to read it.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import frontmatter
import pytest

from janitor.client import Vote
from janitor.policy import HIGH_PRECISION_SECRETS, decide
from janitor.scan import build_state, scan_vault


def _vote(**kwargs) -> Vote:
    base = dict(
        bucket="durable_memory",
        bucket_probabilities={"durable_memory": 0.9, "log_entry": 0.05},
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


# --- finding 3: the local hit is the trigger, not the model's agreement -------------------

@pytest.mark.parametrize("label", HIGH_PRECISION_SECRETS)
def test_local_secret_hit_quarantines_even_when_jev_says_no(label: str):
    """Redaction runs before the call, so Jev sees `[KEY]`, not the key. It cannot confirm
    what it was never shown, and a file move must not wait for it to agree."""
    action = decide(_vote(contains_secret=0.01, safe_to_leave_in_git=0.99), hits=[label])
    assert action.name == "quarantine"
    assert action.triggers == [f"local:{label}"]


@pytest.mark.parametrize("label", ["EMAIL", "PHONE", "CARD", "NAME", "SSN"])
def test_soft_hits_never_move_a_file(label: str):
    """These patterns false-positive on ordinary prose. An order number is not a reason to
    move somebody's note."""
    assert decide(_vote(), hits=[label]).name == "frontmatter"


def test_git_unsafe_is_off_until_somebody_picks_a_number():
    """0.55 was picked on a calibration set. An unmeasured threshold that moves files is a
    guess, so it stays unset until a run picks it."""
    vote = _vote(safe_to_leave_in_git=0.18)
    assert decide(vote).name == "frontmatter"
    assert decide(vote, git_unsafe_threshold=0.3).name == "quarantine"
    assert decide(vote, git_unsafe_threshold=0.3).triggers == ["safe_to_leave_in_git"]


def test_a_neighbours_secret_cannot_move_this_note(tmp_path: Path):
    """The reported hit list covers everything that leaves, including sibling titles. The
    quarantine decision reads only this note's own title and body."""
    note = tmp_path / "innocent.md"
    note.write_text("# Innocent\n\nNothing here at all.\n", encoding="utf-8")
    from janitor.frontmatter import load_note

    state, hits, own_hits = build_state(
        load_note(note), ["sk-abcdefghijklmnopqrstuvwxyz012345 leaked"], None, rel_path="innocent.md"
    )
    assert "KEY" in hits, "a key in a sibling title must be reported"
    assert "KEY" not in own_hits, "and must not be attributed to this note"
    assert "[KEY]" in state["other_note_titles"][0], "and must still be redacted before it leaves"
    assert decide(_vote(), hits=own_hits).name == "frontmatter"


# --- finding 4: a near-tie is not a decision ----------------------------------------------

def test_low_confidence_is_stamped_as_needs_review(tmp_path: Path):
    """A 0.36-vs-0.34 coin flip used to be written as a hard `bucket`, so anything that
    later grouped notes by `janitor.bucket` read it as settled."""
    from janitor.apply import stamp

    note = tmp_path / "n.md"
    note.write_text("# N\n\nbody\n", encoding="utf-8")
    vote = _vote(bucket="ephemeral", bucket_confidence=0.36,
                 bucket_probabilities={"ephemeral": 0.36, "durable_memory": 0.34})
    action = decide(vote)
    assert action.review is True
    stamp(note, vote, action, taxonomy="abc123")

    meta = frontmatter.load(note, encoding="utf-8").metadata["janitor"]
    assert meta["bucket"] == "needs_review", "the floor must reach the field a human's tools read"
    assert meta["suggested_bucket"] == "ephemeral", "the model's pick is kept, not lost"
    assert meta["bucket_margin"] == 0.02
    assert meta["action"] == "frontmatter", "a near-tie is not moved"


def test_a_confident_note_carries_no_suggested_bucket(tmp_path: Path):
    from janitor.apply import stamp

    note = tmp_path / "n.md"
    note.write_text("# N\n\nbody\n", encoding="utf-8")
    stamp(note, _vote(), decide(_vote()), taxonomy="abc123")
    meta = frontmatter.load(note, encoding="utf-8").metadata["janitor"]
    assert meta["bucket"] == "durable_memory"
    assert "suggested_bucket" not in meta


def test_a_second_identical_apply_does_not_touch_the_file(tmp_path: Path):
    """`at` used to be rewritten unconditionally, so a re-scan dirtied every note in git."""
    note = tmp_path / "n.md"
    note.write_text("# N\n\nan ordinary durable note about routing rules\n", encoding="utf-8")
    scan_vault(tmp_path, offline=True, apply=True)
    first = note.read_bytes()
    rows = scan_vault(tmp_path, offline=True, apply=True)
    assert note.read_bytes() == first, "identical vote rewrote the note"
    assert [r for r in rows if r.get("path") == "n.md"][0]["applied"] == "unchanged"


# --- finding 5: the operator can see what left --------------------------------------------

def test_the_row_shows_what_was_sent(tmp_path: Path):
    (tmp_path / "n.md").write_text("# N\n\nreach me at a.b@example.com about routing\n", encoding="utf-8")
    row = [r for r in scan_vault(tmp_path, offline=True) if r.get("path") == "n.md"][0]
    assert row["title_sent"] == "N"
    assert "EMAIL" in row["redacted"] and "EMAIL" in row["redacted_own"]
    assert "sent" not in row, "the payload is opt-in"


def test_show_payload_reaches_the_report_and_never_the_journal(tmp_path: Path):
    vault = tmp_path / "v"
    vault.mkdir()
    (vault / "n.md").write_text("# N\n\nrouting rules that persist\n", encoding="utf-8")
    journal = tmp_path / "j"
    out = subprocess.run(
        [sys.executable, "-m", "janitor", str(vault), "--offline", "--json",
         "--show-payload", "--journal", str(journal)],
        capture_output=True, text=True, cwd=Path(__file__).resolve().parent.parent,
    )
    assert out.returncode == 0, out.stderr
    rows = json.loads(out.stdout)
    sent = [r for r in rows if r.get("path") == "n.md"][0]["sent"]
    assert "routing rules that persist" in sent["excerpt"], "SECURITY.md says to read the excerpt"

    written = [line for f in journal.rglob("*.jsonl") for line in f.read_text(encoding="utf-8").splitlines()]
    assert written, "the journal was not written; this test would pass vacuously"
    assert not any("sent" in json.loads(line) for line in written), (
        "redacted vault text was written outside the vault; spec v0.2 section 9 forbids it"
    )


def test_stdout_carries_the_report_and_nothing_else(tmp_path: Path):
    """An --offline run must still say what it looked at, and it must say it on stderr."""
    vault = tmp_path / "v"
    vault.mkdir()
    (vault / "n.md").write_text("# N\n\nbody\n", encoding="utf-8")
    (vault / "_Inbox").mkdir()
    (vault / "_Inbox" / "m.md").write_text("# M\n\nbody\n", encoding="utf-8")
    out = subprocess.run(
        [sys.executable, "-m", "janitor", str(vault), "--offline", "--json"],
        capture_output=True, text=True, cwd=Path(__file__).resolve().parent.parent,
    )
    assert out.returncode == 0, out.stderr
    json.loads(out.stdout)  # stdout is the report and only the report
    assert "_Inbox" in out.stderr, "the skipped-folder list (an _Inbox is 'inbox' since 0.4.1) is the reason to run offline first"
    assert "notes" in out.stderr.lower()


def test_the_consent_prompt_is_not_part_of_the_report(monkeypatch, capsys):
    """It landed on stdout, in the middle of a --json run."""
    from janitor import cli

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("y\n"))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    assert cli.confirm("Send these notes to TypeSafe? [y/N] ") is True
    captured = capsys.readouterr()
    assert "TypeSafe" not in captured.out
    assert "TypeSafe" in captured.err
