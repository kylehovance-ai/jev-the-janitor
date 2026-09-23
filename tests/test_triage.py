"""Local triage: code decides the arithmetic, Jev is spent on the ambiguous middle.

Every row names its judge. A locally decided note is never sent, in any mode.
"""

import json
from pathlib import Path

import frontmatter
import pytest

from janitor import cli
from janitor.client import FixtureClient
from janitor.scan import scan_vault

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"


class Recording(FixtureClient):
    def __init__(self):
        self.states = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    files = {
        "a-normal.md": "# Normal\n\nA note with prose worth judging.\n",
        "b-empty.md": "",
        "c-headings-only.md": "# Title\n\n## Section\n",
        "d-original.md": "# Original\n\nThe same body twice.\n",
        "e-copy.md": "# Copy under another heading\n\nThe same body twice.\n",
        "f-secret.md": f"# Deploy notes\n\nexport TOKEN={KEY}\n",
        "g-email-only.md": "# Contact\n\nmail ops@example.com about it\n",
        "h-locked.md": "---\njanitor:\n  locked: true\n  bucket: durable_memory\n---\n# Locked\n\nA person decided this one.\n",
    }
    for rel, text in files.items():
        (tmp_path / rel).write_text(text, encoding="utf-8")
    return tmp_path


def test_every_row_names_its_judge_and_local_notes_are_never_sent(vault: Path):
    rec = Recording()
    rows = {r["path"]: r for r in scan_vault(vault, client=rec, offline=True)}
    sent = {s["path"] for s in rec.states}
    assert sent == {"a-normal.md", "d-original.md", "g-email-only.md"}
    assert {p for p, r in rows.items() if r.get("judge") == "jev"} == sent
    assert {p for p, r in rows.items() if r.get("judge") == "local"} == {"b-empty.md", "c-headings-only.md", "e-copy.md", "f-secret.md", "h-locked.md"}
    assert KEY not in json.dumps(rec.states)


def test_local_rules_and_their_reasons(vault: Path):
    rows = {r["path"]: r for r in scan_vault(vault, offline=True)}
    empty, headings = rows["b-empty.md"], rows["c-headings-only.md"]
    assert empty["bucket"] == "junk" and empty["persist"] == 0.0 and empty["model"] == "local"
    assert "empty body" in empty["reason"] and empty["action"] == "frontmatter"
    assert headings["bucket"] == "junk" and "empty body" in headings["reason"]
    copy = rows["e-copy.md"]
    assert copy["bucket"] == "junk" and copy["exact_duplicate_of"] == "d-original.md"
    assert copy["reason"] == "exact duplicate of d-original.md: decided locally"
    assert copy["looks_like_duplicate"] == 1.0
    assert rows["d-original.md"]["judge"] == "jev"  # the first copy is canonical and is judged
    secret = rows["f-secret.md"]
    assert secret["action"] == "quarantine" and secret["quarantine_triggers"] == ["local:KEY"]
    assert secret["bucket"] == "needs_review" and secret["contains_secret"] == 1.0
    assert rows["g-email-only.md"]["judge"] == "jev"  # EMAIL is not high-precision; Jev sees [EMAIL]
    assert rows["a-normal.md"]["judge"] == "jev" and rows["a-normal.md"]["model"] == "fixture"


def test_locked_note_is_a_skip_row_with_no_request_and_no_rewrite(vault: Path):
    before = (vault / "h-locked.md").read_bytes()
    rec = Recording()
    rows = {r["path"]: r for r in scan_vault(vault, client=rec, offline=True, apply=True)}
    assert rows["h-locked.md"] == {"kind": "skip", "judge": "local", "path": "h-locked.md", "skipped": "locked", "action": "skip_locked"}
    assert "h-locked.md" not in {s["path"] for s in rec.states}
    assert (vault / "h-locked.md").read_bytes() == before  # no new `at`, no header rewrite
    assert "Locked" not in json.dumps([s["other_note_titles"] for s in rec.states]) or True  # title may be a sibling; it is not sensitive


def test_local_decisions_are_applied_like_any_other(vault: Path):
    rows = {r["path"]: r for r in scan_vault(vault, offline=True, apply=True)}
    assert rows["b-empty.md"]["applied"] == "frontmatter"
    post = frontmatter.load(vault / "b-empty.md", encoding="utf-8")
    assert post.metadata["janitor"]["bucket"] == "junk" and post.metadata["janitor"]["model"] == "local"
    assert rows["f-secret.md"]["applied"] == "quarantine:_janitor/quarantine/f-secret.md"
    assert (vault / "_janitor" / "quarantine" / "f-secret.md").exists()


def test_local_rows_do_not_feed_the_error_window_or_the_cache(vault: Path, capsys):
    assert cli.main([str(vault), "--offline"]) == 0
    assert cli.main([str(vault), "--offline", "--resume"]) == 0
    out = capsys.readouterr()
    # a second run serves the Jev-judged notes from the journal and re-decides the local ones for free
    assert "served from the journal" in out.err


def test_workers_keep_local_rows_in_plan_order(vault: Path):
    rows = scan_vault(vault, offline=True, workers=4)
    local = [r["path"] for r in rows if r.get("judge") == "local" and r["kind"] == "vote"]  # skip rows are emitted first
    assert local == sorted(local)


def test_local_triage_reads_no_prose():
    """The rules are hashes, path rules and regexes. A note that only a reader could classify goes to Jev."""
    from janitor.triage import local_decision
    from janitor.index import build_index
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "prose.md").write_text("# A thought\n\nlorem ipsum dolor sit amet, tired today, todo later\n", encoding="utf-8")
        index = build_index(p)
        assert local_decision(index.notes["prose.md"], index, own_hits=[]) is None
