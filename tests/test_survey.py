"""Survey first, full scan second: a stratified, deterministic sample the judge sees, and nothing else.

Nobody lets an unknown tool make 20,000 calls over their private notes on first contact.
"""

import json
import os
from pathlib import Path

from janitor import cli
from janitor.client import FixtureClient
from janitor.journal import read_journal, vault_id
from janitor.scan import prepare_vault
from janitor.survey import length_band, stratum_of, survey_sample

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"


class Recording(FixtureClient):
    states = []

    def vote(self, state, questions):
        Recording.states.append(state)
        return super().vote(state, questions)


def _vault(tmp_path: Path) -> Path:
    vault = tmp_path / "vault"
    for folder in ("notes", "projects", "archive"):
        (vault / folder).mkdir(parents=True)
        for i in range(12):
            words = ("w " * (30 if i % 3 == 0 else 300 if i % 3 == 1 else 2500)).strip()
            created = "2026-09-20" if i % 2 else "2023-01-01"
            (vault / folder / f"{folder[0]}{i:02d}.md").write_text(f"---\ncreated: {created}\n---\n# {folder} {i}\n\n{words} {folder} {i}\n", encoding="utf-8")
    (vault / "notes" / "empty.md").write_text("", encoding="utf-8")
    (vault / "notes" / "leak.md").write_text(f"# leak\n\n{KEY}\n", encoding="utf-8")
    (vault / "notes" / "locked.md").write_text("---\njanitor:\n  locked: true\n---\n# locked\n\nlocked body words\n", encoding="utf-8")
    return vault


def test_sample_is_stratified_deterministic_and_skips_what_the_judge_would_not_see(tmp_path: Path):
    vault = _vault(tmp_path)
    _, plan, items, _ = prepare_vault(vault)
    survey = survey_sample(items, 12, seed="s")
    assert survey.requested == 12 and len(survey.items) == 12 and survey.eligible == 36
    assert {it.rel for it in survey.items}.isdisjoint({"notes/empty.md", "notes/leak.md", "notes/locked.md"})
    assert len(survey.strata) == 12 and len(survey.population) == 18  # 3 folders x 3 lengths x 2 ages exist; 12 drawn, one each
    assert all(n == 1 for n in survey.strata.values())
    assert [it.rel for it in survey.items] == sorted(it.rel for it in survey.items)  # plan order
    again = survey_sample(prepare_vault(vault)[2], 12, seed="s")
    assert [it.rel for it in again.items] == [it.rel for it in survey.items]  # same seed, same sample
    other = survey_sample(prepare_vault(vault)[2], 12, seed="t")
    assert [it.rel for it in other.items] != [it.rel for it in survey.items]  # a different vault id draws differently


def test_round_robin_gives_every_stratum_one_before_any_gets_two(tmp_path: Path):
    vault = _vault(tmp_path)
    _, plan, items, _ = prepare_vault(vault)
    survey = survey_sample(items, 20, seed="s")
    assert len(survey.items) == 20
    assert set(survey.strata.values()) == {1, 2} and sum(1 for n in survey.strata.values() if n == 2) == 2  # 18 strata: 18 ones, then 2 seconds
    big = survey_sample(items, 500, seed="s")
    assert len(big.items) == 36  # capped at what is eligible


def test_bands():
    assert [length_band(w) for w in (0, 99, 100, 499, 500, 1999, 2000, 50000)] == ["stub", "stub", "short", "short", "medium", "medium", "long", "long"]


def test_cli_survey_sends_only_the_sample_and_journals_it(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path)
    monkeypatch.setattr(cli, "FixtureClient", Recording)
    Recording.states = []
    assert cli.main([str(vault), "--offline", "--survey", "9"]) == 0
    out, err = capsys.readouterr()
    assert "SURVEY: 9 of 36 judge-eligible notes, drawn across 9 strata" in err
    assert "bill (estimate): 9 notes a live run would send" in err
    assert len(Recording.states) == 9
    assert "survey: 9 notes judged across 9 strata" in err and "per stratum (folder, length, age)" in err
    assert "edit the taxonomy, re-run the survey, and compare; then scan in full." in err
    journals = sorted((Path(os.environ["JEV_JANITOR_CACHE_DIR"]) / "journals" / vault_id(vault)).glob("run-*.jsonl"))
    header, rows, _ = read_journal(journals[-1])
    assert header["survey"] == 9 and sum(1 for r in rows if r["kind"] == "vote") == 9

    # the full scan that follows serves the surveyed votes from the journal and sends the rest
    Recording.states = []
    assert cli.main([str(vault), "--offline", "--resume"]) == 0
    err = capsys.readouterr().err
    assert "9 already voted and unchanged" in err
    assert len(Recording.states) == 36 - 9


def test_survey_default_size_and_plan(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert cli.main([str(vault), "--plan", "--survey"]) == 0
    out = capsys.readouterr().out
    assert "SURVEY: 36 of 36 judge-eligible notes" in out  # 75 requested, 36 exist
    assert cli.main([str(vault), "--offline", "--survey", "5", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert sum(1 for r in rows if r["kind"] == "vote" and r["judge"] == "jev") == 5


def test_stratum_of_uses_top_folder_and_banded_facts(tmp_path: Path):
    vault = _vault(tmp_path)
    _, plan, items, _ = prepare_vault(vault)
    by = {it.rel: it for it in items}
    assert stratum_of(by["notes/n00.md"]) == ("notes/", "stub", "age1000")
    assert stratum_of(by["archive/a01.md"]) == ("archive/", "short", "age1")  # created 2026-09-20; today is after 2026-09-21
    assert stratum_of(by["projects/p02.md"])[1] == "long"
