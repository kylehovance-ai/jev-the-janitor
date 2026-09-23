from pathlib import Path

from janitor.scan import scan_vault

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "notes"


def test_offline_scan_buckets():
    rows = scan_vault(FIXTURES, offline=True)
    by_path = {row["path"]: row for row in rows if "bucket" in row}
    assert by_path["secret-leak.md"]["bucket"] == "needs_review"
    assert by_path["secret-leak.md"]["action"] == "quarantine"
    assert by_path["ephemeral-scratch.md"]["bucket"] == "ephemeral"
    assert by_path["junk-lorem.md"]["bucket"] == "junk"
    assert by_path["project-decision.md"]["bucket"] == "project_decision"
    assert by_path["code-note.md"]["bucket"] == "code_note"
    assert by_path["durable-plot-fee.md"]["bucket"] == "durable_memory"
    assert by_path["reference-link.md"]["bucket"] == "reference"
    assert by_path["nightly-run-log.md"]["bucket"] == "log_entry"
    assert by_path["code-note.md"]["bucket_margin"] == 0.86  # fixture client reports a single probability
    assert list(by_path["code-note.md"]["bucket_probabilities"]) == ["code_note"]
    skipped = {row["path"]: row for row in rows if row.get("skipped")}
    assert "family/private-skip-me.md" in skipped
    assert skipped["family/private-skip-me.md"]["action"] == "skip_sensitive"
