from pathlib import Path

from janitor.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "notes"


def test_offline_scan_json(capsys):
    rc = main([str(FIXTURES), "--offline", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "project_decision" in out
    assert "ephemeral" in out
    assert "needs_review" in out
    assert "sk-" not in out
    assert "skip_sensitive" in out
