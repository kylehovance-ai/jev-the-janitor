"""The path named on the command line is tested by the sensitive-path rules too.

0.1.1 closed the single-file door: `jev-janitor vault/family/mom.md` was skipped. The
directory door stayed open through 0.2.0: `jev-janitor vault/family` scanned mom.md,
because whatever is named becomes the root and the root's own name is never a
vault-relative segment. A shell loop over folders walked straight through it. And under
--include-sensitive a sensitive note's title reached the other sensitive notes in its
folder as sibling context, which the README says never happens.

The comparison is local, against absolute folder names; the absolute path never leaves.
"""

import json
from pathlib import Path

import pytest

from janitor import cli
from janitor.client import FixtureClient
from janitor.scan import plan_vault, preflight_summary, root_refusal, scan_vault

MOM_TITLE = "Mom Zebra Diagnosis"
DAD_TITLE = "Dad Okapi Ledger"


class RecordingClient(FixtureClient):
    def __init__(self) -> None:
        self.states: list[dict] = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    files = {
        "family/mom.md": f"# {MOM_TITLE}\n\nFAMILY-BODY-SENTINEL\n",
        "family/dad.md": f"# {DAD_TITLE}\n\nbody of dad\n",
        "family/2024/reunion.md": "# Reunion Plans\n\nNESTED-FAMILY-SENTINEL\n",
        "notes/x.md": "# Ordinary\n\nbody of x\n",
        "notes/y.md": "# Sibling Y\n\nbody of y\n",
        "_janitor/quarantine/held.md": "# Held Secret\n\nsk-abcdefghijklmnopqrstuvwxyz012345\n",
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


def test_directory_target_inside_a_sensitive_folder_is_skipped(vault: Path):
    root, entries = plan_vault(vault / "family")
    assert root == (vault / "family").resolve()
    assert {e.rel: e.status for e in entries} == {"2024/reunion.md": "skip_sensitive", "dad.md": "skip_sensitive", "mom.md": "skip_sensitive"}
    assert all("sensitive path part 'family'" in e.rule for e in entries)
    client = RecordingClient()
    rows = scan_vault(vault / "family", client=client, offline=True)
    assert {r["action"] for r in rows} == {"skip_sensitive"}
    assert client.states == []


def test_nested_directory_target_under_a_sensitive_folder_is_skipped(vault: Path):
    _, entries = plan_vault(vault / "family" / "2024")
    assert [(e.rel, e.status) for e in entries] == [("reunion.md", "skip_sensitive")]
    client = RecordingClient()
    scan_vault(vault / "family" / "2024", client=client, offline=True)
    assert client.states == []


def test_directory_target_matches_case_insensitively_and_custom_parts(vault: Path):
    (vault / "Clients" / "acme").mkdir(parents=True)
    (vault / "Clients" / "acme" / "brief.md").write_text("# Acme Brief\n\nbody\n", encoding="utf-8")
    _, entries = plan_vault(vault / "Clients" / "acme", sensitive_parts=("clients",))
    assert entries[0].status == "skip_sensitive" and "sensitive path part 'Clients'" in entries[0].rule
    # The custom list replaces the default: family is not in it, so the family folder scans.
    _, entries = plan_vault(vault / "family", sensitive_parts=("clients",))
    assert {e.status for e in entries} == {"scan"}


def test_directory_target_preflight_and_plan_flag_name_the_folder(vault: Path, capsys, monkeypatch):
    root, entries = plan_vault(vault / "family")
    text = preflight_summary(root, entries)
    assert "0 of 3 notes" in text and "sensitive path part 'family'" in text
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert cli.main([str(vault / "family"), "--plan"]) == 0
    out = capsys.readouterr().out
    assert "0 of 3 notes" in out and "sensitive path part 'family'" in out


def test_directory_target_with_include_sensitive_sends_bodies_but_no_sibling_titles(vault: Path):
    client = RecordingClient()
    rows = scan_vault(vault / "family", client=client, offline=True, include_sensitive=True)
    assert sorted(r["path"] for r in rows) == ["2024/reunion.md", "dad.md", "mom.md"]
    assert all("bucket" in r for r in rows)
    assert len(client.states) == 3
    assert all(s["other_note_titles"] == [] for s in client.states)
    blob = json.dumps([s["other_note_titles"] for s in client.states])
    assert MOM_TITLE not in blob and DAD_TITLE not in blob


def test_sensitive_titles_never_reach_sensitive_siblings_even_from_the_vault_root(vault: Path):
    """Through 0.2.0, `jev-janitor ./vault --include-sensitive` listed dad.md's title as
    sibling context for mom.md: both were planned as 'scan', so both were in the pool."""
    client = RecordingClient()
    scan_vault(vault, client=client, offline=True, include_sensitive=True)
    by_path = {s["path"]: s for s in client.states}
    assert by_path["family/mom.md"]["other_note_titles"] == []
    assert by_path["family/dad.md"]["other_note_titles"] == []
    assert by_path["notes/x.md"]["other_note_titles"] == ["Sibling Y"]  # ordinary folders keep their siblings
    blob = json.dumps([s["other_note_titles"] for s in client.states])
    assert MOM_TITLE not in blob and DAD_TITLE not in blob


def test_directory_target_inside_the_janitor_folder_is_skipped(vault: Path):
    """Quarantined notes hold the secrets that were moved out of the way. Naming that
    folder directly must not send them, with or without --include-sensitive."""
    for include in (False, True):
        _, entries = plan_vault(vault / "_janitor" / "quarantine", include_sensitive=include)
        assert [(e.rel, e.status) for e in entries] == [("held.md", "skip_janitor")]
        client = RecordingClient()
        scan_vault(vault / "_janitor" / "quarantine", client=client, offline=True, include_sensitive=include)
        assert client.states == []


def test_vault_that_lives_under_a_sensitive_ancestor_is_skipped_loudly(tmp_path: Path):
    """Fail closed. The pre-flight shows 0 of N and names the segment; --sensitive-paths or
    --include-sensitive is the way through, and both are explicit."""
    home = tmp_path / "personal" / "vault"
    (home / "notes").mkdir(parents=True)
    (home / "notes" / "a.md").write_text("# A\n\nbody\n", encoding="utf-8")
    root, entries = plan_vault(home)
    assert [(e.rel, e.status) for e in entries] == [("notes/a.md", "skip_sensitive")]
    assert "sensitive path part 'personal'" in entries[0].rule
    assert "0 of 1 notes" in preflight_summary(root, entries)
    _, entries = plan_vault(home, sensitive_parts=("family",))
    assert entries[0].status == "scan"


def test_vault_under_a_sensitive_ancestor_refuses_with_exit_1_and_names_the_remedy(tmp_path: Path, capsys, monkeypatch):
    """A run that judged nothing must not report success: on a schedule nobody reads the
    pre-flight, and exit 0 would be green forever. The refusal names both ways through."""
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    home = tmp_path / "personal" / "vault"
    (home / "notes").mkdir(parents=True)
    (home / "notes" / "a.md").write_text("# A\n\nbody\n", encoding="utf-8")

    assert cli.main([str(home), "--offline"]) == cli.EXIT_REFUSED
    err = capsys.readouterr().err
    assert "REFUSED: the folder you named lives under 'personal'" in err
    assert "--include-sensitive" in err
    assert "--sensitive-paths family,private,secrets,inbox to drop 'personal'" in err

    assert cli.main([str(home), "--plan"]) == 0  # --plan is the reading command; it shows the refusal and exits 0
    assert "REFUSED" in capsys.readouterr().out

    assert cli.main([str(home), "--offline", "--include-sensitive"]) == 0
    assert cli.main([str(home), "--offline", "--sensitive-paths", "family,private,secrets,inbox"]) == 0
    assert cli.main([str(home), "--offline", "--sensitive-paths", ""]) == 0


def test_own_name_and_single_file_keep_the_quiet_skip(vault: Path, capsys, monkeypatch):
    """`./vault/family` is the note-taker's own statement about those notes: skipped, exit 0,
    like `./vault` skipping family/. So is a single file. Only an ANCESTOR of a directory refuses."""
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert root_refusal(vault / "family") is None
    assert root_refusal(vault / "family" / "mom.md") is None
    assert cli.main([str(vault / "family"), "--offline"]) == 0
    assert "REFUSED" not in capsys.readouterr().err
    assert root_refusal(vault / "family" / "2024") is not None  # 'family' sits above the folder named
    assert root_refusal(vault / "family" / "2024", include_sensitive=True) is None
    assert root_refusal(vault / "family" / "2024", sensitive_parts=("clients",)) is None


def test_the_root_hit_never_leaves_the_machine(vault: Path):
    """The absolute path is compared locally; the state carries only vault-relative paths."""
    client = RecordingClient()
    scan_vault(vault / "family", client=client, offline=True, include_sensitive=True)
    blob = json.dumps(client.states)
    assert str(vault) not in blob and vault.name not in blob
    assert {s["path"] for s in client.states} == {"2024/reunion.md", "dad.md", "mom.md"}


def test_obsidian_marker_tells_taxonomy_from_mount_point(tmp_path: Path, capsys, monkeypatch):
    """With .obsidian/ at the vault root, position stops being a guess: a sensitive name inside
    the vault is the note-taker's taxonomy (quiet skip), one above the root is the mount (refuse)."""
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    from janitor.plan import vault_root

    # Case 1: a vault mounted somewhere harmless, with a sensitive folder inside it.
    vault = tmp_path / "Obsidian"
    (vault / ".obsidian").mkdir(parents=True)
    (vault / "family" / "2024").mkdir(parents=True)
    (vault / "family" / "2024" / "reunion.md").write_text("# Reunion\n\nbody\n", encoding="utf-8")
    assert vault_root(vault / "family" / "2024") == vault and vault_root(tmp_path) is None
    # family is taxonomy, even two levels above the folder named -> quiet skip, exit 0 (0.3.0 refused here)
    assert root_refusal(vault / "family" / "2024") is None
    assert cli.main([str(vault / "family" / "2024"), "--offline"]) == 0
    err = capsys.readouterr().err
    assert "REFUSED" not in err and "0 of 1 notes" in err
    # without the marker the old rule stands: anything above the folder named counts as above
    (vault / ".obsidian").rmdir()
    assert root_refusal(vault / "family" / "2024") is not None

    # Case 2: a vault mounted under a sensitive folder name: the marker says it is the mount -> refuse
    home = tmp_path / "personal" / "Obsidian"
    (home / ".obsidian").mkdir(parents=True)
    (home / "work").mkdir()
    (home / "work" / "plan.md").write_text("# Plan\n\nbody\n", encoding="utf-8")
    refusal = root_refusal(home / "work")
    assert refusal is not None and "'personal'" in refusal
    assert cli.main([str(home), "--offline"]) == cli.EXIT_REFUSED
    assert "lives under 'personal'" in capsys.readouterr().err
