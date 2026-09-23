"""--excerpt-chars: how much of each note leaves the machine. Default 16,000 since 0.2.1.

The excerpt is part of the hashed state, so changing the cap changes the cache key for
exactly the notes whose sent text changes. Redaction still runs before the cut. The
pre-flight names the cap, loudly when it is not the default. Notes over the hard guard are
cut there with a warning instead of producing a 400.
"""

import json
import os
from pathlib import Path

import pytest

from janitor import cli
from janitor.client import FixtureClient
from janitor.frontmatter import HARD_EXCERPT_CAP, MAX_EXCERPT
from janitor.journal import read_journal, vault_id
from janitor.scan import plan_vault, preflight_summary, prepare_vault, scan_vault


class Recording(FixtureClient):
    def __init__(self):
        self.states = []

    def vote(self, s, q):
        self.states.append(s)
        return super().vote(s, q)


def _vault(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "short.md").write_text("# Short\n\nfits under every cap\n", encoding="utf-8")
    (tmp_path / "long.md").write_text("# Long\n\n" + ("preamble filler. " * 100) + "\n\n" + ("x" * MAX_EXCERPT) + "\nMIDDLE-SENTINEL " + ("x" * 3500) + "\nTAIL-SENTINEL\n", encoding="utf-8")
    return tmp_path


def test_default_is_unchanged():
    assert MAX_EXCERPT == 16000
    assert cli.PROFILE_DEFAULTS["excerpt_chars"][0] == "16000"  # resolved by apply_profile when neither flag nor janitor.toml sets it
    assert cli.parse_excerpt_chars("16000") == 16000


def test_default_run_cuts_at_the_default_cap(tmp_path: Path):
    rec = Recording()
    scan_vault(_vault(tmp_path), client=rec, offline=True)
    long = next(s for s in rec.states if s["path"] == "long.md")
    assert len(long["excerpt"]) == 16000 and "MIDDLE-SENTINEL" not in long["excerpt"]


def test_full_sends_whole_note(tmp_path: Path):
    rec = Recording()
    rows = scan_vault(_vault(tmp_path), client=rec, offline=True, excerpt_chars=0)
    long = next(s for s in rec.states if s["path"] == "long.md")
    assert "MIDDLE-SENTINEL" in long["excerpt"] and "TAIL-SENTINEL" in long["excerpt"]
    row = next(r for r in rows if r["path"] == "long.md")
    assert row["truncated"] is False and row["excerpt_chars"] == len(long["excerpt"])


def test_custom_cap(tmp_path: Path):
    rec = Recording()
    rows = scan_vault(_vault(tmp_path), client=rec, offline=True, excerpt_chars=MAX_EXCERPT + 4000)
    long = next(s for s in rec.states if s["path"] == "long.md")
    assert len(long["excerpt"]) == MAX_EXCERPT + 4000 and "MIDDLE-SENTINEL" in long["excerpt"] and "TAIL-SENTINEL" not in long["excerpt"]
    assert next(r for r in rows if r["path"] == "long.md")["truncated"] is True
    assert next(r for r in rows if r["path"] == "short.md")["truncated"] is False


def test_redaction_still_runs_before_the_cut_at_a_larger_cap(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    body = "# K\n\n" + ("y " * 1500) + "sk-abcdefghijklmnopqrstuvwxyz012345 and ops@example.com\n"
    (tmp_path / "k.md").write_text(body, encoding="utf-8")
    rec = Recording()
    # local_triage=False: with triage on, a KEY hit is quarantined locally and nothing is sent at all.
    # This test is about the excerpt that WOULD leave, which still matters for --show-payload and EMAIL-class hits.
    scan_vault(tmp_path, client=rec, offline=True, excerpt_chars=0, local_triage=False)
    ex = rec.states[0]["excerpt"]
    assert "[KEY]" in ex and "[EMAIL]" in ex and "sk-" not in ex and "example.com" not in ex


def test_hard_guard_truncates_with_flag_instead_of_400(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "huge.md").write_text("# Huge\n\n" + ("word " * 40000) + "END-SENTINEL\n", encoding="utf-8")  # ~200k chars
    root, plan, items, _ = prepare_vault(tmp_path, excerpt_chars=0)
    item = items[0]
    assert len(item.state["excerpt"]) == HARD_EXCERPT_CAP and "END-SENTINEL" not in item.state["excerpt"]
    assert item.truncated and item.guard_truncated
    text = preflight_summary(root, plan, excerpt_chars=0, guard_truncated=1)
    assert "WARNING: 1 note(s) exceed the 60,000-character guard" in text


# --- the cache key --------------------------------------------------------------------------

def test_cap_change_moves_keys_only_for_notes_whose_sent_text_changes(tmp_path: Path):
    vault = _vault(tmp_path)
    k1200 = {r["path"]: r["key"] for r in scan_vault(vault, offline=True, excerpt_chars=1200)}  # an explicit small cap, not the default
    kfull = {r["path"]: r["key"] for r in scan_vault(vault, offline=True, excerpt_chars=0)}
    k3000 = {r["path"]: r["key"] for r in scan_vault(vault, offline=True, excerpt_chars=3000)}
    assert k1200["short.md"] == kfull["short.md"] == k3000["short.md"]  # same text sent: same vote is the right vote
    assert len({k1200["long.md"], kfull["long.md"], k3000["long.md"]}) == 3  # different text sent: never served across caps


def test_resume_at_a_different_cap_revotes_only_long_notes_and_says_so(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path / "v")
    assert cli.main([str(vault), "--offline"]) == 0
    capsys.readouterr()

    class Counting(FixtureClient):
        paths = []

        def vote(self, s, q):
            Counting.paths.append(s["path"])
            return super().vote(s, q)

    monkeypatch.setattr(cli, "FixtureClient", Counting)
    assert cli.main([str(vault), "--offline", "--resume", "--excerpt-chars", "full"]) == 0
    err = capsys.readouterr().err
    assert Counting.paths == ["long.md"]
    assert "excerpt_cap: 16000 -> 0" in err
    assert "1 already voted and unchanged" in err and "1 new or changed" in err
    assert "EXCERPT: WHOLE NOTES" in err


# --- pre-flight and CLI --------------------------------------------------------------------

def test_preflight_names_the_cap(tmp_path: Path):
    root, plan = plan_vault(_vault(tmp_path))
    assert "excerpt: the first 16,000 characters of each note after redaction (default)" in preflight_summary(root, plan)
    assert "EXCERPT: WHOLE NOTES" in preflight_summary(root, plan, excerpt_chars=0)
    assert "EXCERPT: the first 5,000 characters" in preflight_summary(root, plan, excerpt_chars=5000)


def test_cli_plan_shows_whole_note_consent_line(tmp_path: Path, capsys):
    vault = _vault(tmp_path)
    assert cli.main([str(vault), "--plan", "--excerpt-chars", "full"]) == 0
    assert "EXCERPT: WHOLE NOTES" in capsys.readouterr().out


def test_cli_rejects_bad_values():
    with pytest.raises(SystemExit):
        cli.parse_excerpt_chars("abc")
    with pytest.raises(SystemExit):
        cli.parse_excerpt_chars("50")
    assert cli.parse_excerpt_chars("full") == 0 and cli.parse_excerpt_chars("0") == 0 and cli.parse_excerpt_chars("5000") == 5000


def test_journal_header_records_the_cap(tmp_path: Path):
    vault = _vault(tmp_path / "v")
    assert cli.main([str(vault), "--offline", "--excerpt-chars", "full"]) == 0
    j = sorted((Path(os.environ["JEV_JANITOR_CACHE_DIR"]) / "journals" / vault_id(vault)).glob("run-*.jsonl"))[-1]
    header, rows, _ = read_journal(j)
    assert header["excerpt_cap"] == 0
    assert next(r for r in rows if r.get("path") == "long.md")["truncated"] is False


def test_readme_states_the_default_and_the_flag():
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
    assert "the first 16,000 characters of the body after local redaction by default" in readme
    assert "`--excerpt-chars N` sends the first N, `--excerpt-chars full` sends whole notes" in readme
