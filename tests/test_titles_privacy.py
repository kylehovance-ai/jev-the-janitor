"""``other_note_titles`` must never carry a sensitive note's title off the machine.

Asserts on the state dict handed to the client, not on printed output.
"""

import json
from pathlib import Path

import pytest

from janitor.client import FixtureClient
from janitor.scan import scan_vault

SENSITIVE_TITLE = "Zebra Quilt Diagnosis"
QUARANTINED_TITLE = "Quarantined Qux Ledger"


class RecordingClient(FixtureClient):
    def __init__(self) -> None:
        self.states: list[dict] = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    files = {
        "family/mom.md": f"# {SENSITIVE_TITLE}\n\nnot for the cloud\n",
        "private/keys.md": "# Private Vault Passphrases\n\nnope\n",
        "notes/alpha.md": "# Alpha note\n\nordinary\n",
        "notes/bravo.md": "# Bravo note\n\nordinary too\n",
        "notes/.hidden.md": "# Hidden Dotfile Note\n\nskip\n",
        "other/charlie.md": "# Charlie note\n\nelsewhere\n",
        "_janitor/quarantine/qux.md": f"# {QUARANTINED_TITLE}\n\nheld\n",
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


def _titles_for(client: RecordingClient, path_fragment: str) -> list[str]:
    for state in client.states:
        if state["path"].replace("\\", "/").endswith(path_fragment):
            return state["other_note_titles"]
    raise AssertionError(f"no state recorded for {path_fragment}")


def test_sensitive_titles_never_leave(vault: Path):
    client = RecordingClient()
    scan_vault(vault, client=client, offline=True)
    blob = json.dumps(client.states)
    assert SENSITIVE_TITLE not in blob
    assert "Private Vault Passphrases" not in blob
    assert QUARANTINED_TITLE not in blob
    assert "Hidden Dotfile Note" not in blob


def test_sensitive_titles_never_leave_even_with_include_sensitive(vault: Path):
    client = RecordingClient()
    scan_vault(vault, client=client, offline=True, include_sensitive=True)
    for state in client.states:
        assert SENSITIVE_TITLE not in state["other_note_titles"]
        assert "Private Vault Passphrases" not in state["other_note_titles"]
    # The family note itself is scanned now, and sees no titles from other folders.
    assert _titles_for(client, "family/mom.md") == []


def test_titles_are_scoped_to_the_notes_own_folder(vault: Path):
    client = RecordingClient()
    scan_vault(vault, client=client, offline=True)
    assert _titles_for(client, "notes/alpha.md") == ["Bravo note"]
    assert _titles_for(client, "notes/bravo.md") == ["Alpha note"]
    assert _titles_for(client, "other/charlie.md") == []


def test_sibling_titles_are_redacted(tmp_path: Path):
    """0.1.0 sent sibling titles raw, bypassing both the regexes and the denylist."""
    (tmp_path / "a.md").write_text("# A\n\nbody\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("# Call Ada Lovelace at ops@example.com\n\nbody\n", encoding="utf-8")
    client = RecordingClient()
    scan_vault(tmp_path, client=client, offline=True, denylist=["Ada Lovelace"])
    assert _titles_for(client, "a.md") == ["Call [NAME] at [EMAIL]"]
    blob = json.dumps(client.states)
    assert "Lovelace" not in blob and "ops@example.com" not in blob
