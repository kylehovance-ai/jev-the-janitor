"""The ``path`` sent to Jev is vault-relative and posix on every platform.

This one field carries both the privacy contract (no OS username, no directory tree) and
the cross-platform contract (JSON output is identical on Windows and POSIX).
"""

from pathlib import Path, PurePosixPath

from janitor.client import FixtureClient
from janitor.scan import scan_vault


class RecordingClient(FixtureClient):
    def __init__(self) -> None:
        self.states: list[dict] = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


def _vault(tmp_path: Path) -> Path:
    (tmp_path / "projects" / "deep").mkdir(parents=True)
    (tmp_path / "projects" / "deep" / "note.md").write_text("# Deep note\n\nbody\n", encoding="utf-8")
    (tmp_path / "top.md").write_text("# Top note\n\nbody of the top note\n", encoding="utf-8")
    return tmp_path


def test_state_path_is_relative_posix(tmp_path: Path):
    vault = _vault(tmp_path)
    client = RecordingClient()
    scan_vault(vault, client=client, offline=True)
    sent = sorted(state["path"] for state in client.states)
    assert sent == ["projects/deep/note.md", "top.md"]
    for p in sent:
        assert not Path(p).is_absolute()
        assert not PurePosixPath(p).is_absolute()
        assert "\\" not in p
        assert str(vault) not in p


def test_report_path_matches_state_path(tmp_path: Path):
    vault = _vault(tmp_path)
    client = RecordingClient()
    rows = scan_vault(vault, client=client, offline=True)
    assert sorted(row["path"] for row in rows) == sorted(state["path"] for state in client.states)


def test_single_file_scan_sends_bare_name(tmp_path: Path):
    vault = _vault(tmp_path)
    client = RecordingClient()
    scan_vault(vault / "projects" / "deep" / "note.md", client=client, offline=True)
    assert client.states[0]["path"] == "note.md"
