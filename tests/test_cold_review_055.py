"""0.5.5: the pre-launch cold review of 0.5.4, each finding reproduced on 8bb082e before it was fixed.

B2  a model change made --resume send notes the pre-flight had counted as served;
M1  the denylist missed dot-, slash- and dash-joined names;
L4  `Authorization: Basic <base64>` left as written beside a redacted Bearer;
L9  --show-payload put a `sent` object on rows that are never sent;
M2  a redirected run on a cp1252 console crashed on a non-Latin filename;
H1  --apply resets the file-system creation time (disclosed, not changed);
L1  the toml example quoted a stale estimate.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from janitor.bill import build_bill
from janitor.client import FixtureClient
from janitor.redact import redact
from janitor.scan import ScanAborted, prepare_vault, scan_vault

ROOT = Path(__file__).resolve().parent.parent
NL = chr(10)


class NewModel(FixtureClient):
    """The API now answers with another model version than the journal's votes came from."""

    def __init__(self):
        self.calls = 0

    def vote(self, s, q):
        self.calls += 1
        v = super().vote(s, q)
        v.model = "fixture-2"
        return v


def _drift_vault(root: Path, n_old: int, n_new: int, workers: int):
    # Two folders: sibling titles are per folder and part of the state, so new notes beside the
    # old ones would change every old key and the pre-flight would rightly count them all.
    (root / "old").mkdir(parents=True)
    (root / "aaa-new").mkdir()
    for i in range(n_old):
        (root / "old" / f"old{i:02d}.md").write_text(f"# Old {i}{NL}{NL}an old body about topic {i} with its own words {i * 7}{NL}", encoding="utf-8")
    first = scan_vault(root, offline=True, workers=workers)
    cache = {r["key"]: r for r in first if r.get("kind") == "vote"}
    for i in range(n_new):  # the folder sorts first, so the new model is revealed before any cached note is reached
        (root / "aaa-new" / f"new{i:02d}.md").write_text(f"# New {i}{NL}{NL}a new body about subject {i} with different words {i * 3}{NL}", encoding="utf-8")
    return cache


@pytest.mark.parametrize("workers,n_new", [(1, 1), (8, 33)])  # 33 >= 8 * 4 + 1: the in-flight window fills
def test_a_run_never_sends_a_note_the_preflight_did_not_count(tmp_path: Path, workers: int, n_new: int):
    """B2. 24 cached notes, n_new fresh ones sorted first, the model string changed between runs.
    0.5.4: the pre-flight counted n_new to send; the run sent 24 + n_new (25 at 1 worker, 57 at 8).
    Now: the first fresh vote reveals the change and the run stops; what was already in flight
    drains and is recorded; the cached notes are neither sent nor served."""
    vault = tmp_path / "v"
    cache = _drift_vault(vault, 24, n_new, workers)
    _, plan, items, _ = prepare_vault(vault, cache=cache, model_requested="fixture")  # the pre-flight's own count
    counted = build_bill(plan, items).to_send
    assert counted == n_new
    client = NewModel()
    with pytest.raises(ScanAborted) as info:
        scan_vault(vault, client=client, offline=True, cache=cache, workers=workers)
    rows = info.value.rows
    votes = [r for r in rows if r.get("kind") == "vote"]
    fresh = [r for r in votes if not r["cached"]]
    assert info.value.reason == "model-drift"
    assert client.calls == len(fresh) <= counted, "sent more than the pre-flight counted"
    assert all(r["path"].startswith("aaa-new/") for r in fresh)
    assert not [r for r in votes if r["cached"]], "no cached note is served after the change is known"
    assert "--no-cache" in str(info.value) and "--trust-cache-across-models" in str(info.value)
    # both ways on, each with the count the pre-flight would give for it
    trusted = scan_vault(vault, client=NewModel(), offline=True, cache=cache, workers=workers, trust_cache_across_models=True)
    tv = [r for r in trusted if r.get("kind") == "vote"]
    assert sum(1 for r in tv if not r["cached"]) == n_new and sum(1 for r in tv if r["cached"]) == 24
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "a run never sends a note the pre-flight did not count as sent" in readme


def test_the_model_drift_stop_persists_across_a_plain_resume(tmp_path: Path, monkeypatch, capsys):
    """B2, r2. After the model-drift stop the stopped run's journal holds one vote from the new
    model, so a plain --resume found both models in the chain, never saw the change again, and
    served every old-model vote with 0 calls (the 0.5.5 first cut). Now it refuses before the
    consent question with the same two ways on; after a --trust run ends normally, later resumes
    serve as the owner chose."""
    from janitor import cli
    vault = tmp_path / "v"
    (vault / "old").mkdir(parents=True)
    (vault / "aaa-new").mkdir()
    for i in range(24):
        (vault / "old" / f"old{i:02d}.md").write_text(f"# Old {i}{NL}{NL}an old body about topic {i} with its own words {i * 7}{NL}", encoding="utf-8")
    base = [str(vault), "--offline", "--journal", "vault", "--json"]
    assert cli.main(base) == 0  # run 1: 24 votes from the fixture model, journaled
    capsys.readouterr()
    (vault / "aaa-new" / "new00.md").write_text("# New" + NL + NL + "a new body about a new subject" + NL, encoding="utf-8")
    client = NewModel()
    monkeypatch.setattr(cli, "FixtureClient", lambda: client)
    assert cli.main(base + ["--resume"]) == 2  # run 2: the new note reveals the model change; the run stops
    out, err = capsys.readouterr()
    assert "ABORTED" in err and "model" in err and client.calls == 1
    client.calls = 0
    assert cli.main(base + ["--resume"]) == 1  # run 3: the natural reaction; refused, nothing served, nothing sent
    out, err = capsys.readouterr()
    assert client.calls == 0 and out.strip() == "" and "stopped because the API's model changed" in err
    assert "--no-cache" in err and "--trust-cache-across-models" in err and "Nothing was sent" in err
    assert cli.main(base + ["--resume", "--trust-cache-across-models"]) == 0  # run 4: the owner chooses
    rows = [r for r in json.loads(capsys.readouterr().out) if r.get("kind") == "vote"]
    # the 24 old-model votes and the new note's own vote, which the stopped run had recorded: nothing to send
    assert sum(1 for r in rows if r["cached"]) == 25 and sum(1 for r in rows if not r["cached"]) == 0 and client.calls == 0
    assert cli.main(base + ["--resume"]) == 0  # run 5: the trust run ended normally; a plain resume serves as chosen
    rows = [r for r in json.loads(capsys.readouterr().out) if r.get("kind") == "vote"]
    assert sum(1 for r in rows if r["cached"]) == 25
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "The stop persists: a plain `--resume` after it refuses before the consent question" in readme


def test_denylist_matches_across_dots_slashes_and_dashes_and_names_its_residuals():
    """M1. With entry `Mara Quill`, the joined forms below left as written through 0.5.4."""
    for text in ("Mara.Quill", "Mara/Quill", "Mara–Quill", "Mara—Quill", "mara.quill", "Mara-Quill", "Mara_Quill", "Mara" + NL + "Quill"):
        assert redact(text, denylist=["Mara Quill"]).text == "[NAME]", text
    assert redact("see Mara.Quill's note and [[mara/quill]]", denylist=["Mara Quill"]).text == "see [NAME]'s note and [[[NAME]]]"
    # the documented residuals: not matched, named in both docs
    for text in ("MaraQuill", "Quill, Mara", "**Mara** Quill"):
        assert redact(text, denylist=["Mara Quill"]).text == text, text
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    for doc in (readme, security):
        assert "`JaneDoe`" in doc and "`Doe, Jane`" in doc and "`**Jane** Doe`" in doc
    assert "is the residual no rule can tell from a word" not in readme


def test_authorization_basic_is_redacted_and_quarantined_like_bearer(tmp_path: Path):
    """L4. `Authorization: Basic dXNlcjpzM2NyZXRQYXNz` (base64 user:password) left as written through 0.5.4."""
    for text in ("Authorization: Basic dXNlcjpzM2NyZXRQYXNz", "authorization: basic dXNlcjpzM2NyZXRQYXNz", "Basic YWRtaW46aHVudGVyMg=="):
        r = redact(text)
        assert "[BEARER]" in r.text and r.hits == ["BEARER"], text
    assert redact("Authorization: Bearer abcdefghijklmnop1234").text == "Authorization: [BEARER]"
    # r2: in header context any base64 run is a credential, the all-letter unpadded "user:pass" included,
    # and the header prefix is kept
    assert redact("Authorization: Basic dXNlcjpwYXNz").text == "Authorization: [BEARER]"
    assert redact("authorization: basic dXNlcjpwYXNz").text == "authorization: [BEARER]"
    assert redact('Authorization="Basic dXNlcjpwYXNz"').text == 'Authorization="[BEARER]"'
    assert redact("Authorization = 'Basic YWRtaW46YWRtaW4='").text == "Authorization = '[BEARER]'"
    assert redact("-H 'Authorization: Basic a2F0ZTpvcmNoYXJk' https://example.com").text == "-H 'Authorization: [BEARER]' https://example.com"
    (tmp_path / "userpass.md").write_text("# Login" + NL + NL + "Authorization: Basic dXNlcjpwYXNz" + NL, encoding="utf-8")
    up = {r["path"]: r for r in scan_vault(tmp_path, offline=True)}["userpass.md"]
    assert up["action"] == "quarantine" and "local:BEARER" in up["quarantine_triggers"]
    # "Basic" is an ordinary word: prose after it is not a credential
    for prose in ("a Basic understanding of the flow", "Basic configuration", "the Basic Authentication chapter"):
        assert redact(prose).text == prose and redact(prose).hits == []
    (tmp_path / "n.md").write_text("# API note" + NL + NL + "curl -H 'Authorization: Basic dXNlcjpzM2NyZXRQYXNz' https://example.com" + NL, encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, offline=True)}
    assert rows["n.md"]["action"] == "quarantine" and "local:BEARER" in rows["n.md"]["quarantine_triggers"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "`Authorization: Basic` credentials" in readme and "`Authorization: Basic` credentials" in security


def test_show_payload_puts_sent_only_on_rows_that_leave(tmp_path: Path, capsys):
    """L9. An empty note, an exact duplicate and a locally quarantined note are never sent; through
    0.5.4 their rows still carried a `sent` object under --show-payload."""
    from janitor import cli
    (tmp_path / "a.md").write_text("# A" + NL + NL + "the same body twice" + NL, encoding="utf-8")
    (tmp_path / "b.md").write_text("# B" + NL + NL + "the same body twice" + NL, encoding="utf-8")
    (tmp_path / "empty.md").write_text("# Empty" + NL, encoding="utf-8")
    (tmp_path / "leak.md").write_text("# Leak" + NL + NL + "key sk-" + "a" * 40 + NL, encoding="utf-8")
    assert cli.main([str(tmp_path), "--offline", "--json", "--show-payload", "--journal", "off"]) == 0
    rows = {r["path"]: r for r in json.loads(capsys.readouterr().out) if r.get("kind") == "vote"}
    assert rows["a.md"]["judge"] == "jev" and isinstance(rows["a.md"]["sent"], dict) and rows["a.md"]["sent"]["title"] == "A"
    for local in ("b.md", "empty.md", "leak.md"):
        assert rows[local]["judge"] == "local" and "sent" in rows[local] and rows[local]["sent"] is None, local
    assert rows["leak.md"]["action"] == "quarantine"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "is never sent, so its row says `sent: null`" in readme


def test_a_redirected_run_survives_a_non_latin_filename_on_a_cp1252_console(tmp_path: Path):
    """M2. `jev-janitor vault --offline > out.txt` on a stock Windows console (cp1252) exited 1 with
    UnicodeEncodeError on `日記.md`, after the journal was written. The streams now escape what
    the console cannot encode. Forced here with PYTHONIOENCODING, so it runs on every platform."""
    vault = tmp_path / "v"
    vault.mkdir()
    (vault / "日記.md").write_text("# Diary" + NL + NL + "a body about the day" + NL, encoding="utf-8")
    (vault / "plain.md").write_text("# Plain" + NL + NL + "another body" + NL, encoding="utf-8")
    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONUTF8="0")
    out = tmp_path / "out.txt"
    with open(out, "wb") as fh:
        proc = subprocess.run([sys.executable, "-m", "janitor.cli", str(vault), "--offline", "--journal", "off"],
                              stdout=fh, stderr=subprocess.PIPE, env=env, cwd=str(ROOT), timeout=120)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")[-600:]
    text = out.read_bytes().decode("cp1252")
    assert "\\u65e5\\u8a18.md" in text and "plain.md" in text  # the name survives as its escape, nothing is dropped


def test_apply_resets_the_file_system_creation_time_and_the_readme_says_so(tmp_path: Path):
    """H1. The atomic write makes the stamped note a new file; the OS creation stamp moves to the
    run's time. Measured on Windows; disclosed, with the remedy, not changed."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "A stamp resets the note's file-system creation time." in readme
    assert "measured on Windows" in readme and "give your notes a `created:` key before the first `--apply`" in readme
    if sys.platform != "win32":
        pytest.skip("st_birthtime semantics are measured on Windows only")
    def birth(p: Path) -> float:  # Windows: st_birthtime from 3.12; on 3.11 st_ctime is the creation time
        st = os.stat(p)
        return getattr(st, "st_birthtime", st.st_ctime)

    note = tmp_path / "n.md"
    note.write_text("# N" + NL + NL + "body for the birth time probe" + NL, encoding="utf-8")
    before = birth(note)
    time.sleep(1.1)
    scan_vault(tmp_path, offline=True, apply=True)
    assert birth(note) - before >= 1.0


def test_the_toml_example_quotes_the_current_reference_estimate():
    """L1. The example config still said $0.68 to $0.99 for the 18,738-note vault; the README and
    bill.py say $1.39 to $1.88."""
    example = (ROOT / "janitor.toml.example").read_text(encoding="utf-8")
    assert "$1.39 to $1.88" in example and "$0.68" not in example
    assert "$1.39 to $1.88" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "$1.39 to $1.88" in (ROOT / "janitor" / "bill.py").read_text(encoding="utf-8")
