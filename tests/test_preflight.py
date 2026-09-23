"""The membrane is visible before it is crossed.

``plan_vault`` is the one place that decides what is read; the pre-flight prints it; the CLI
refuses to send anything in live mode without confirmation.
"""

import io
from pathlib import Path

import pytest

from janitor import cli
from janitor import scan as scan_module
from janitor.scan import near_misses, plan_vault, preflight_summary, scan_vault


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    files = [
        "notes/alpha.md",
        "notes/bravo.md",
        "projects/garden/plan.md",
        "family/mom.md",
        "Private/keys.md",
        "_Inbox/verdicts.md",
        "Inbox_/old.md",
        "inboxes/stale.md",
        ".secrets/token.md",
        ".obsidian/workspace.md",
        "_janitor/quarantine/held.md",
        "notes/.draft.md",
    ]
    for rel in files:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"# {rel}\n\nbody\n", encoding="utf-8")
    return tmp_path


def _status(entries, rel):
    return next(e for e in entries if e.rel == rel).status


def test_plan_classifies_every_note(vault: Path):
    root, entries = plan_vault(vault)
    assert root == vault.resolve()
    assert len(entries) == 12
    assert _status(entries, "notes/alpha.md") == "scan"
    assert _status(entries, "projects/garden/plan.md") == "scan"
    assert _status(entries, "family/mom.md") == "skip_sensitive"
    assert _status(entries, "Private/keys.md") == "skip_sensitive"
    assert _status(entries, ".secrets/token.md") == "skip_hidden"
    assert _status(entries, ".obsidian/workspace.md") == "skip_hidden"
    assert _status(entries, "notes/.draft.md") == "skip_hidden"
    assert _status(entries, "_janitor/quarantine/held.md") == "skip_janitor"


def test_whole_word_match_skips_decorated_inbox_and_warns_on_inboxes(vault: Path):
    """Through 0.4.0 the match was exact per folder name and '_Inbox' was scanned with a warning.
    Since 0.4.1 the folder name's whole words are matched: '_Inbox' and 'Inbox_' are 'inbox' and
    are skipped; 'inboxes' is a different word, scanned, and named by the pre-flight."""
    _, entries = plan_vault(vault)
    assert _status(entries, "_Inbox/verdicts.md") == "skip_sensitive"
    assert _status(entries, "Inbox_/old.md") == "skip_sensitive"
    assert _status(entries, "inboxes/stale.md") == "scan"
    assert near_misses(entries) == [("inboxes", "inbox")]


def test_custom_sensitive_parts_close_the_near_miss(vault: Path):
    _, entries = plan_vault(vault, sensitive_parts=("family", "private", "_inbox", "inbox_"))
    assert _status(entries, "_Inbox/verdicts.md") == "skip_sensitive"
    assert _status(entries, "Inbox_/old.md") == "skip_sensitive"
    assert near_misses(entries, ("family", "private", "_inbox", "inbox_")) == []


def test_hidden_folders_are_skipped_by_the_dot_rule_not_the_list(vault: Path):
    _, entries = plan_vault(vault, sensitive_parts=())
    assert _status(entries, ".secrets/token.md") == "skip_hidden"
    _, entries = plan_vault(vault, include_sensitive=True)
    assert _status(entries, ".secrets/token.md") == "skip_hidden"


def test_include_sensitive_scans_listed_folders_only(vault: Path):
    _, entries = plan_vault(vault, include_sensitive=True)
    assert _status(entries, "family/mom.md") == "scan"
    assert _status(entries, ".secrets/token.md") == "skip_hidden"
    assert _status(entries, "_janitor/quarantine/held.md") == "skip_janitor"


def test_scan_follows_the_plan_exactly(vault: Path):
    _, entries = plan_vault(vault)
    rows = scan_vault(vault, offline=True)
    scanned = {r["path"] for r in rows if "bucket" in r}
    skipped = {r["path"] for r in rows if r.get("skipped")}
    assert scanned == {e.rel for e in entries if e.status == "scan"}
    assert skipped == {e.rel for e in entries if e.status == "skip_sensitive"}
    assert not any(".secrets" in r["path"] or "_janitor" in r["path"] for r in rows)


def test_summary_names_folders_rules_and_near_misses(vault: Path):
    root, entries = plan_vault(vault)
    text = preflight_summary(root, entries)
    assert "4 of 12 notes" in text
    assert "will be sent to TypeSafe" in text
    assert "notes/" in text and "projects/garden/" in text
    assert "family/" in text and "sensitive path part 'family'" in text
    assert "Private/" in text and "sensitive path part 'Private'" in text
    # A whole-word match is named as skipped, so an over-match is visible in the same list.
    assert "_Inbox/" in text and "sensitive path part '_Inbox'" in text
    assert "Inbox_/" in text and "sensitive path part 'Inbox_'" in text
    assert ".secrets/" in text and "starts with '.'" in text
    assert "_janitor/quarantine/" in text and "janitor working folder" in text
    assert "WARNING" in text
    assert "'inboxes' contains 'inbox' but will be scanned" in text
    assert "'_Inbox' contains" not in text
    assert "vault" not in text.split("\n")[0].lower() or root.name in text


def test_summary_offline_says_nothing_leaves(vault: Path):
    root, entries = plan_vault(vault)
    text = preflight_summary(root, entries, live=False)
    assert "nothing leaves the machine" in text
    assert "TypeSafe" not in text.split("\n")[0]


def test_cli_plan_needs_no_key_and_sends_nothing(vault: Path, capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr(scan_module, "TypeSafeJanitorClient", _Boom)
    rc = cli.main([str(vault), "--plan"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pre-flight" in out and "'inboxes' contains 'inbox'" in out


class _Boom:
    def __init__(self, *a, **k):
        raise AssertionError("a live client was constructed before confirmation")


def test_cli_live_refuses_without_confirmation(vault: Path, capsys, monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "not-a-real-key")
    monkeypatch.setattr(scan_module, "TypeSafeJanitorClient", _Boom)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))  # not a tty: cannot consent
    with pytest.raises(SystemExit) as exc:
        cli.main([str(vault)])
    assert "Nothing was sent" in str(exc.value)
    err = capsys.readouterr().err
    assert "pre-flight" in err


def test_cli_live_prompt_declined(vault: Path, monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "not-a-real-key")
    monkeypatch.setattr(scan_module, "TypeSafeJanitorClient", _Boom)
    monkeypatch.setattr(cli, "confirm", lambda prompt: False)
    with pytest.raises(SystemExit):
        cli.main([str(vault)])


def test_cli_offline_does_not_prompt(vault: Path, capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr(cli, "confirm", lambda prompt: (_ for _ in ()).throw(AssertionError("prompted in offline mode")))
    rc = cli.main([str(vault), "--offline", "--json"])
    assert rc == 0
    assert '"skip_sensitive"' in capsys.readouterr().out


def test_cli_yes_still_prints_summary(vault: Path, capsys, monkeypatch):
    """--yes suppresses only the question. The record of what was sent is not optional."""
    monkeypatch.setenv("TYPESAFE_API_KEY", "not-a-real-key")
    monkeypatch.setattr(cli, "confirm", lambda prompt: (_ for _ in ()).throw(AssertionError("prompted with --yes")))

    class _Halt(Exception):
        pass

    def _boom(*a, **k):
        raise _Halt()

    # Without the SDK installed, build_questions raises before the client is constructed.
    # This test is about the summary, so neutralise both so it passes under ".[dev]" alone.
    monkeypatch.setattr(cli, "build_questions", lambda taxonomy: {})
    monkeypatch.setattr(cli, "TypeSafeJanitorClient", _boom)
    with pytest.raises(_Halt):
        cli.main([str(vault), "--yes"])
    err = capsys.readouterr().err
    assert "pre-flight" in err and "folders included" in err and "'inboxes' contains 'inbox'" in err
