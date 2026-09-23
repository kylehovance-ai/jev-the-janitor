"""The scan diff: what moved between two journals, computed from the journals alone.

Built against synthetic journals; the corpus will demonstrate it. No excerpt is read
or stored anywhere in this path.
"""

import json
import os
from pathlib import Path

import pytest

from janitor import cli
from janitor.client import FixtureClient, Vote
from janitor.diff import Snapshot, diff_as_rows, diff_snapshots, list_journals, load_snapshot, render_diff
from janitor.journal import vault_id

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"


def _snap(name: str, rows: dict, taxonomy: str = "aaa", model: str = "jev-1") -> Snapshot:
    return Snapshot(path=Path(name), header={"taxonomy": taxonomy, "model_requested": model, "started": "t"}, rows=rows)


def vote(bucket, *, conf=0.8, suggested=None, action="frontmatter", dup=None, truncated=False, findings=(), judge="jev"):
    return {"kind": "vote", "bucket": bucket, "confidence": conf, "suggested_bucket": suggested, "action": action,
            "exact_duplicate_of": dup, "truncated": truncated, "findings": list(findings), "judge": judge, "reason": "r", "applied": None}


def test_every_category_on_synthetic_rows():
    before = _snap("a", {
        "same.md": vote("durable_memory"),
        "moved.md": vote("durable_memory"),
        "into.md": vote("durable_memory"),
        "out.md": vote("needs_review", conf=0.4, suggested="log_entry"),
        "leak.md": vote("durable_memory"),
        "freed.md": vote("needs_review", action="quarantine"),
        "copy.md": vote("durable_memory"),
        "grew.md": vote("durable_memory", truncated=False),
        "fixed.md": vote("durable_memory", findings=["unreadable_frontmatter"]),
        "gone.md": vote("junk"),
        "lock.md": vote("durable_memory"),
    })
    after = _snap("b", {
        "same.md": vote("durable_memory"),
        "moved.md": vote("log_entry", judge="jev"),
        "into.md": vote("needs_review", conf=0.41, suggested="durable_memory"),
        "out.md": vote("log_entry", conf=0.9),
        "leak.md": vote("needs_review", action="quarantine") | {"reason": "local redaction hit: KEY", "applied": "quarantine:_janitor/quarantine/leak.md"},
        "freed.md": vote("durable_memory"),
        "copy.md": vote("junk", dup="same.md", judge="local"),
        "grew.md": vote("durable_memory", truncated=True),
        "fixed.md": vote("durable_memory"),
        "new.md": vote("durable_memory", findings=["unreadable_frontmatter"]),
        "lock.md": {"kind": "skip", "skipped": "locked", "action": "skip_locked", "judge": "local"},
        "broken.md": {"kind": "error", "action": "error", "error": "ValueError"},
        # Arrivals are judged by their own row. Through 0.4.0 these three were bare paths under "new notes".
        "arrived-leak.md": vote("needs_review", action="quarantine") | {"reason": "local redaction hit: KEY"},
        "arrived-copy.md": vote("junk", dup="same.md", judge="local"),
        "arrived-review.md": vote("needs_review", conf=0.3, suggested="log_entry"),
        "arrived-locked.md": {"kind": "skip", "skipped": "locked", "action": "skip_locked", "judge": "local"},
    }, taxonomy="bbb")
    d = diff_snapshots(before, after)
    assert d.unchanged == 1 and d.gone == ["gone.md"]
    assert d.new == ["arrived-copy.md", "arrived-leak.md", "arrived-locked.md", "arrived-review.md", "broken.md", "new.md"]
    assert [c["path"] for c in d.bucket_changed] == ["copy.md", "freed.md", "into.md", "leak.md", "moved.md", "out.md"]
    assert [c["path"] for c in d.into_review] == ["into.md", "arrived-review.md"] and d.into_review[0]["suggested"] == "durable_memory"
    assert d.into_review[1] == {"path": "arrived-review.md", "was": None, "suggested": "log_entry", "confidence": 0.3, "new": True}
    assert [c["path"] for c in d.out_of_review] == ["out.md"] and d.out_of_review[0]["now"] == "log_entry"
    assert [c["path"] for c in d.quarantined] == ["leak.md", "arrived-leak.md"] and d.released == ["freed.md"]
    assert d.quarantined[1] == {"path": "arrived-leak.md", "reason": "local redaction hit: KEY", "applied": None, "new": True}
    assert d.new_duplicates == [{"path": "copy.md", "of": "same.md"}, {"path": "arrived-copy.md", "of": "same.md", "new": True}]
    assert d.crossed_cap == [{"path": "grew.md", "truncated": True}]
    assert d.findings_fixed == ["fixed.md"] and d.findings_new == ["new.md"]
    assert dict(d.findings_before) == {"unreadable_frontmatter": 1} and dict(d.findings_after) == {"unreadable_frontmatter": 1}
    assert d.locked_since == ["lock.md", "arrived-locked.md"] and d.errors_after == ["broken.md"]
    assert d.wording_changed and not d.model_changed

    text = render_diff(d)
    assert "NOTE: the taxonomy wording changed" in text
    assert "notes: 10 in both (1 with the same decision), 6 new, 1 gone" in text
    assert "bucket changed (6):" in text and "moved.md" in text and "durable_memory -> log_entry" in text
    assert "into review (2):" in text and "out of review (1):" in text
    assert "arrived-review.md" in text and "new note, suggested log_entry at 0.3" in text
    assert "quarantined since (2):" in text and "local redaction hit: KEY" in text
    assert "arrived-leak.md" in text and "new note, local redaction hit: KEY (not moved: dry run)" in text
    assert "new exact duplicates (2):" in text and "new note, of same.md" in text
    assert "crossed the excerpt cap (1):" in text and "now cut at the cap" in text
    assert "locked since (2):" in text
    assert "findings: unreadable_frontmatter 1 -> 1" in text and "findings fixed (1):" in text
    assert "errors in the second run (1):" in text
    assert "excerpt" not in json.dumps(diff_as_rows(d)).replace("crossed_cap", "").replace("excerpt cap", "")


def test_render_caps_long_lists_and_json_has_them_all():
    before = _snap("a", {f"n{i}.md": vote("durable_memory") for i in range(50)})
    after = _snap("b", {f"n{i}.md": vote("log_entry") for i in range(50)})
    d = diff_snapshots(before, after)
    text = render_diff(d, limit=5)
    assert "bucket changed (50):" in text and "... and 45 more (--json has every row)" in text
    assert len(diff_as_rows(d)["bucket_changed"]) == 50


class Flip(FixtureClient):
    """Second run votes everything log_entry at low confidence."""

    def vote(self, state, questions):
        v = super().vote(state, questions)
        return Vote(**{**v.__dict__, "bucket": "log_entry", "bucket_confidence": 0.4, "bucket_probabilities": {"log_entry": 0.4, "durable_memory": 0.38}})


def _vault(tmp_path: Path) -> Path:
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "a.md").write_text("# A\n\nalpha body\n", encoding="utf-8")
    (vault / "b.md").write_text("# B\n\nbeta body\n", encoding="utf-8")
    (vault / "gone.md").write_text("# Gone\n\ngoodbye body\n", encoding="utf-8")
    return vault


def test_cli_diff_of_the_two_newest_journals(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path)
    assert cli.main([str(vault), "--offline"]) == 0
    # the vault changes and the judge changes its mind
    (vault / "gone.md").unlink()
    (vault / "c.md").write_text("# C\n\ngamma body\n", encoding="utf-8")
    (vault / "copy.md").write_text("# Copy\n\nalpha body\n", encoding="utf-8")
    (vault / "leak.md").write_text(f"# Leak\n\n{KEY}\n", encoding="utf-8")
    monkeypatch.setattr(cli, "FixtureClient", Flip)
    assert cli.main([str(vault), "--offline"]) == 0
    capsys.readouterr()

    assert cli.main([str(vault), "--diff"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("scan diff: run-")
    assert "notes: 2 in both (0 with the same decision), 3 new, 1 gone" in out
    assert "bucket changed (2):" in out and "durable_memory -> log_entry" in out
    assert "into review (3):" in out and "c.md" in out  # a, b flipped; c arrived at low confidence
    assert "new notes (3):" in out and "copy.md" in out and "leak.md" in out
    assert "gone (1):" in out and "gone.md" in out
    # The two arrivals that matter most are named for what the scan decided, not just as paths.
    # Reproduced on a synthetic test corpus, v1 -> v2, before this: 5 planted new duplicate pairs and a new
    # note holding a token were listed under "new notes" and nowhere else.
    assert "new exact duplicates (1):" in out and "copy.md" in out and "new note, of a.md" in out
    assert "quarantined since (1):" in out and "leak.md" in out and "new note, local redaction hit: KEY (not moved: dry run)" in out

    assert cli.main([str(vault), "--diff", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["wording_changed"] is False and len(data["bucket_changed"]) == 2
    assert "excerpt" not in json.dumps(data)


def test_cli_diff_against_a_named_journal(tmp_path: Path, capsys):
    vault = _vault(tmp_path)
    assert cli.main([str(vault), "--offline"]) == 0
    (vault / "a.md").write_text("# A\n\nalpha body changed\n", encoding="utf-8")
    assert cli.main([str(vault), "--offline"]) == 0
    journals = list_journals(Path(os.environ["JEV_JANITOR_CACHE_DIR"]) / "journals" / vault_id(vault))
    assert len(journals) == 2
    capsys.readouterr()
    assert cli.main([str(vault), "--diff", str(journals[0])]) == 0
    assert journals[0].name in capsys.readouterr().out.splitlines()[0]


def test_cli_diff_refuses_without_two_journals(tmp_path: Path):
    vault = _vault(tmp_path)
    with pytest.raises(SystemExit, match="needs two journals"):
        cli.main([str(vault), "--diff"])
    assert cli.main([str(vault), "--offline"]) == 0
    with pytest.raises(SystemExit, match="needs two journals"):
        cli.main([str(vault), "--diff"])
    with pytest.raises(SystemExit, match="--journal off has none"):
        cli.main([str(vault), "--diff", "--journal", "off"])


def test_diff_reads_no_note(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path)
    assert cli.main([str(vault), "--offline"]) == 0
    assert cli.main([str(vault), "--offline"]) == 0
    from janitor import index as index_module

    def boom(path):
        raise AssertionError(f"--diff opened {path}")

    monkeypatch.setattr(index_module, "load_note", boom)
    assert cli.main([str(vault), "--diff"]) == 0
    snap = load_snapshot(list_journals(Path(os.environ["JEV_JANITOR_CACHE_DIR"]) / "journals" / vault_id(vault))[-1])
    assert set(snap.rows) == {"a.md", "b.md", "gone.md"}
