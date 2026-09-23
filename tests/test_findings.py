"""A header that will not parse is a fact about the vault, not a failure of the run.

Through 0.3.0 `status: blocked: waiting on review` raised in the YAML parser, became an
error row, was never judged and was retried forever on --resume. Agents write headers
like that, and every YAML-aware tool goes blind to those notes. The scan now reports them
as findings: the note is judged on its body, the row names the problem, the pre-flight
counts them, and --apply leaves the header alone because a header we cannot read is one
we must not rewrite. A file that is not UTF-8 is the other finding: never sent, never
retried, listed.
"""

import json
from pathlib import Path

import pytest

from janitor import cli
from janitor.client import FixtureClient
from janitor.frontmatter import load_note, parse_frontmatter, split_frontmatter
from janitor.scan import scan_vault

BROKEN = "---\ntitle: Planning\nstatus: blocked: waiting on review\nclient: ACME-CODE-99\n---\n# Planning\n\nthe body is fine and says something\n"


class Recording(FixtureClient):
    def __init__(self):
        self.states = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    (tmp_path / "broken.md").write_text(BROKEN, encoding="utf-8")
    (tmp_path / "scalar.md").write_text("---\njust a string\n---\n# Scalar\n\nbody of the scalar note\n", encoding="utf-8")
    (tmp_path / "ok.md").write_text("---\ntitle: Fine\n---\n# Fine\n\nordinary body\n", encoding="utf-8")
    (tmp_path / "latin1.md").write_bytes(b"# caf\xe9\n\nnot utf-8\n")
    return tmp_path


def test_parser_reports_instead_of_raising():
    meta, body, err = parse_frontmatter(BROKEN)
    assert meta == {} and err.startswith("YAML: ") and "mapping values are not allowed" in err
    assert body == "# Planning\n\nthe body is fine and says something\n"  # the header text is not in the body
    meta, body, err = parse_frontmatter("---\njust a string\n---\nbody\n")
    assert err == "frontmatter is a str, not a mapping" and body == "body\n"
    assert parse_frontmatter("---\ntitle: x\n---\nbody\n") == ({"title": "x"}, "body\n", None)
    with pytest.raises(ValueError, match="refusing to rewrite"):
        split_frontmatter(BROKEN)  # the writer's parser still refuses


def test_broken_header_is_judged_on_its_body_and_its_values_never_leave(vault: Path):
    note = load_note(vault / "broken.md")
    assert note.frontmatter_error and note.keys == [] and note.title == "Planning"
    rec = Recording()
    rows = {r["path"]: r for r in scan_vault(vault, client=rec, offline=True)}
    assert "broken.md" in {s["path"] for s in rec.states}  # judged
    assert "ACME-CODE-99" not in json.dumps(rec.states) and "blocked" not in json.dumps(rec.states)
    row = rows["broken.md"]
    assert row["kind"] == "vote" and row["findings"] == ["unreadable_frontmatter"]
    assert row["frontmatter_error"].startswith("YAML: ")
    assert rows["scalar.md"]["findings"] == ["unreadable_frontmatter"] and "not a mapping" in rows["scalar.md"]["frontmatter_error"]
    assert rows["ok.md"]["findings"] == [] and rows["ok.md"]["frontmatter_error"] is None


def test_undecodable_file_is_a_skip_row_never_sent_never_retried(vault: Path):
    rec = Recording()
    rows = {r["path"]: r for r in scan_vault(vault, client=rec, offline=True)}
    assert "latin1.md" not in {s["path"] for s in rec.states}
    row = rows["latin1.md"]
    assert row["kind"] == "skip" and row["skipped"] == "undecodable" and row["findings"] == ["undecodable"]
    assert "not valid UTF-8" in row["detail"]
    assert not any(r["kind"] == "error" for r in rows.values())  # nothing here is a run failure


def test_apply_leaves_an_unreadable_header_alone_but_still_quarantines_a_secret(vault: Path):
    (vault / "leak.md").write_text("---\nbad: [yaml\n---\n# Leak\n\nsk-abcdefghijklmnopqrstuvwxyz012345\n", encoding="utf-8")
    before = {name: (vault / name).read_bytes() for name in ("broken.md", "scalar.md")}
    rows = {r["path"]: r for r in scan_vault(vault, offline=True, apply=True)}
    assert rows["broken.md"]["applied"] == "unchanged: frontmatter unreadable"
    assert rows["scalar.md"]["applied"] == "unchanged: frontmatter unreadable"
    assert all((vault / name).read_bytes() == before[name] for name in before)  # byte-identical, no janitor block
    assert rows["ok.md"]["applied"] == "frontmatter"
    assert rows["leak.md"]["applied"] == "quarantine:_janitor/quarantine/leak.md"  # a move needs no parse
    assert not (vault / "leak.md").exists()


def test_cli_prints_the_findings_and_the_preflight_counts_them(vault: Path, capsys):
    assert cli.main([str(vault), "--offline"]) == 0
    out, err = capsys.readouterr()
    assert "finding: frontmatter unreadable: YAML:" in out
    assert "finding: not valid UTF-8" in out
    assert "findings so far: 2 note(s) with frontmatter no YAML reader can parse" in err and "1 not valid UTF-8" in err
    assert "findings: 2 note(s) have frontmatter no YAML reader can parse and 1 are not valid UTF-8" in err
    assert cli.main([str(vault), "--offline", "--resume"]) == 0
    err = capsys.readouterr().err
    assert "0 previous errors: will be retried" in err  # findings are not errors; nothing to retry


def test_findings_are_in_the_json_report(vault: Path, capsys):
    assert cli.main([str(vault), "--offline", "--json"]) == 0
    rows = {r["path"]: r for r in json.loads(capsys.readouterr().out)}
    assert rows["broken.md"]["findings"] == ["unreadable_frontmatter"]
    assert rows["latin1.md"]["findings"] == ["undecodable"]


def test_the_parser_message_never_quotes_the_header(tmp_path: Path):
    """PyYAML's str(exc) includes the source snippet it choked on. That is raw frontmatter, and
    the message goes on the row and into a journal outside the vault. Structure only."""
    import os
    from janitor.journal import vault_id

    (tmp_path / "leak.md").write_text("---\napi_key: sk-ant-SECRETVALUE1234567890: oops\nclient: ACME-CONFIDENTIAL-99: note\n---\n# Leak\n\nbody\n", encoding="utf-8")
    (tmp_path / "alias.md").write_text("---\nref: *SECRETALIAS\n---\n# Alias\n\nbody\n", encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, offline=True)}
    msg = rows["leak.md"]["frontmatter_error"]
    assert msg.startswith("YAML: ") and "mapping values are not allowed" in msg and "line 2 column" in msg
    assert "SECRET" not in msg and "ACME" not in msg and "api_key" not in msg and "client" not in msg
    assert "SECRETALIAS" not in rows["alias.md"]["frontmatter_error"]  # a quoted token is redacted or absent
    assert cli.main([str(tmp_path), "--offline"]) == 0
    journal = sorted((Path(os.environ["JEV_JANITOR_CACHE_DIR"]) / "journals" / vault_id(tmp_path)).glob("run-*.jsonl"))[-1]
    text = journal.read_text(encoding="utf-8")
    assert "SECRETVALUE" not in text and "ACME-CONFIDENTIAL" not in text and "SECRETALIAS" not in text


def test_journal_carries_the_redacted_title_only(tmp_path: Path):
    """Nothing in the tool consumed the raw title, and a name the operator denylisted must not sit
    in a file outside the vault. The path stays raw: it is how the owner finds the note."""
    import os
    from janitor.journal import vault_id

    (tmp_path / "meeting.md").write_text("# Call with Ada Lovelace about ops@example.com\n\nbody\n", encoding="utf-8")
    (tmp_path / "names.txt").write_text("Ada Lovelace\n", encoding="utf-8")
    assert cli.main([str(tmp_path), "--offline", "--denylist", str(tmp_path / "names.txt")]) == 0
    journal = sorted((Path(os.environ["JEV_JANITOR_CACHE_DIR"]) / "journals" / vault_id(tmp_path)).glob("run-*.jsonl"))[-1]
    text = journal.read_text(encoding="utf-8")
    assert "Lovelace" not in text and "ops@example.com" not in text
    assert '"title_sent":"Call with [NAME] about [EMAIL]"' in text  # the journal is compact canonical JSON
    assert '"title":' not in text
    assert "meeting.md" in text
