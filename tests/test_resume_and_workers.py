"""Resume, cache and workers: reading the journal back and running with a pool.

Resume serves a note from the journal only when today's key equals the row's key; error
rows are retried; the consent gate still holds when anything is sent and is skipped only
when nothing is; model drift stops the cache; N workers keep one writer.
"""

import json
import os
import threading
import time
from pathlib import Path

import pytest

from janitor import cli
from janitor import scan as scan_module
from janitor.client import FixtureClient
from janitor.journal import journal_dir_for, read_journal, vault_id
from janitor.resume import load_resume, newest_journal
from janitor.scan import scan_vault
from janitor.schema import DEFAULT_TAXONOMY


def _vault(root: Path, n: int = 6) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (root / f"n{i}.md").write_text(f"# Note {i}\n\nbody {i}\n", encoding="utf-8")
    return root


class Counting(FixtureClient):
    def __init__(self):
        self.calls = 0
        self.paths = []
        self.lock = threading.Lock()

    def vote(self, state, questions):
        with self.lock:
            self.calls += 1
            self.paths.append(state["path"])
        return super().vote(state, questions)


class RaisesOn(Counting):
    def __init__(self, bad):
        super().__init__()
        self.bad = set(bad)

    def vote(self, state, questions):
        if state["path"] in self.bad:
            with self.lock:
                self.calls += 1
            raise ValueError("boom")
        return super().vote(state, questions)


def _journals(vault: Path):
    d = Path(os.environ["JEV_JANITOR_CACHE_DIR"]) / "journals" / vault_id(vault)
    return sorted(d.glob("run-*.jsonl"), key=lambda p: (p.stat().st_mtime_ns, p.name))


# --- resume ---------------------------------------------------------------------------------

def test_resume_serves_cached_and_retries_errors(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path / "v")
    first = RaisesOn({"n3.md"})
    monkeypatch.setattr(cli, "FixtureClient", lambda: first)
    assert cli.main([str(vault), "--offline"]) == 2
    assert first.calls == 6
    j1 = _journals(vault)[-1]
    capsys.readouterr()  # drop the first run's output

    second = Counting()
    monkeypatch.setattr(scan_module, "FixtureClient", lambda: second)
    monkeypatch.setattr(cli, "FixtureClient", lambda: second)
    rc = cli.main([str(vault), "--offline", "--resume", "--json"])
    assert rc == 0
    out, err = capsys.readouterr()
    rows = {r["path"]: r for r in json.loads(out)}
    assert second.calls == 1 and second.paths == ["n3.md"]  # only the error was sent
    assert rows["n3.md"]["kind"] == "vote" and rows["n3.md"]["cached"] is False
    assert all(rows[f"n{i}.md"]["cached"] for i in (0, 1, 2, 4, 5))
    assert "5 already voted and unchanged" in err and "1 previous errors: will be retried" in err
    j2 = _journals(vault)[-1]
    header, _, _ = read_journal(j2)
    assert header["resumed_from"] == str(j1)


def test_resume_after_taxonomy_change_serves_nothing(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path / "v", 3)
    assert cli.main([str(vault), "--offline"]) == 0
    tax = tmp_path / "tax.yaml"
    src = DEFAULT_TAXONOMY
    tax.write_text(src.read_text(encoding="utf-8").replace("Scratch,", "Scratch or"), encoding="utf-8")
    client = Counting()
    monkeypatch.setattr(cli, "FixtureClient", lambda: client)
    assert cli.main([str(vault), "--offline", "--resume", "--taxonomy", str(tax)]) == 0
    assert client.calls == 3  # zero cache hits: every key changed with the wording
    err = capsys.readouterr().err
    assert "taxonomy:" in err and "0 already voted" in err


def test_resume_after_note_edit_above_cap_revotes_that_note_only(tmp_path: Path, monkeypatch):
    vault = _vault(tmp_path / "v", 3)
    assert cli.main([str(vault), "--offline"]) == 0
    (vault / "n1.md").write_text("# Note 1\n\nbody 1 EDITED\n", encoding="utf-8")
    client = Counting()
    monkeypatch.setattr(cli, "FixtureClient", lambda: client)
    assert cli.main([str(vault), "--offline", "--resume"]) == 0
    assert client.paths == ["n1.md"]


def test_resume_consent_still_asked_when_anything_is_sent(tmp_path: Path, monkeypatch):
    vault = _vault(tmp_path / "v", 3)
    assert cli.main([str(vault), "--offline"]) == 0
    (vault / "n2.md").write_text("# Note 2\n\nchanged\n", encoding="utf-8")
    monkeypatch.setenv("TYPESAFE_API_KEY", "not-a-real-key")
    monkeypatch.setattr(cli, "confirm", lambda prompt: False)
    monkeypatch.setattr(cli, "build_questions", lambda taxonomy: {})
    with pytest.raises(SystemExit) as exc:
        cli.main([str(vault), "--resume", "--model", "fixture"])  # model 'fixture' keeps the offline keys valid
    assert "Nothing was sent" in str(exc.value)


def test_resume_skips_consent_when_nothing_to_send(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path / "v", 3)
    assert cli.main([str(vault), "--offline"]) == 0
    capsys.readouterr()
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)  # no key needed when nothing leaves
    monkeypatch.setattr(cli, "confirm", lambda prompt: (_ for _ in ()).throw(AssertionError("asked with nothing to send")))
    monkeypatch.setattr(cli, "TypeSafeJanitorClient", lambda model=None: (_ for _ in ()).throw(AssertionError("client built with nothing to send")))
    rc = cli.main([str(vault), "--resume", "--model", "fixture", "--json"])
    assert rc == 0
    out, err = capsys.readouterr()
    assert all(r["cached"] for r in json.loads(out))
    assert "nothing to send" in err


def test_no_cache_flag_resends_everything_but_still_journals(tmp_path: Path, monkeypatch):
    vault = _vault(tmp_path / "v", 3)
    assert cli.main([str(vault), "--offline"]) == 0
    client = Counting()
    monkeypatch.setattr(cli, "FixtureClient", lambda: client)
    assert cli.main([str(vault), "--offline", "--resume", "--no-cache"]) == 0
    assert client.calls == 3
    assert len(_journals(vault)) == 2


def test_model_drift_stops_serving_cache(tmp_path: Path):
    vault = _vault(tmp_path / "v", 4)
    first = scan_vault(vault, offline=True)
    cache = {r["key"]: r for r in first}

    class NewModel(FixtureClient):
        def vote(self, s, q):
            v = super().vote(s, q)
            v.model = "fixture-2"
            return v

    # n0 cached, n1 fresh (edited): the fresh vote reveals a new model; n2, n3 must then be re-voted, not served.
    (vault / "n1.md").write_text("# Note 1\n\nedited\n", encoding="utf-8")
    rows = scan_vault(vault, client=NewModel(), offline=True, cache=cache)
    by = {r.get("path"): r for r in rows if r.get("kind") == "vote"}
    events = [r for r in rows if r.get("kind") == "event"]
    assert by["n0.md"]["cached"] is True
    assert by["n1.md"]["cached"] is False
    assert by["n2.md"]["cached"] is False and by["n3.md"]["cached"] is False
    assert events and events[0]["event"] == "model_drift"
    rows2 = scan_vault(vault, client=NewModel(), offline=True, cache=cache, trust_cache_across_models=True)
    assert {r["path"]: r["cached"] for r in rows2 if r.get("kind") == "vote"}["n2.md"] is True


def test_newest_journal_prefers_interrupted_run(tmp_path: Path):
    d = tmp_path / "j"
    d.mkdir()
    (d / "run-20260101T000000-aaaa.jsonl").write_text('{"kind":"run","run":"aaaa"}\n{"kind":"vote","path":"x","key":"k"}\n', encoding="utf-8")
    (d / "run-20260102T000000-bbbb.jsonl").write_text('{"kind":"run","run":"bbbb"}\n{"kind":"vote","path":"x","key":"k"}\n{"kind":"end"}\n', encoding="utf-8")
    assert newest_journal(d).name.endswith("aaaa.jsonl")  # bbbb completed; aaaa is the interrupted one
    (d / "run-20260103T000000-cccc.jsonl").write_text('{"kind":"run","run":"cccc"}\n{"kind":"end"}\n', encoding="utf-8")
    assert newest_journal(d).name.endswith("aaaa.jsonl")


def test_journal_info_needs_no_key(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path / "v", 3)
    assert cli.main([str(vault), "--offline"]) == 0
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert cli.main([str(vault), "--journal-info", "--model", "fixture"]) == 0
    out = capsys.readouterr().out
    assert "journal:" in out and "3 of 3 notes would be served" in out


# --- workers --------------------------------------------------------------------------------

def test_default_workers_is_8_and_documented():
    assert cli.PROFILE_DEFAULTS["workers"][0] == 8  # resolved by apply_profile when neither flag nor janitor.toml sets it
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
    assert "the default is 8 and 16 is the measured optimum" in readme


class Slow(Counting):
    def vote(self, state, questions):
        time.sleep(0.02)
        return super().vote(state, questions)


def test_workers_produce_the_same_rows_and_one_writer(tmp_path: Path):
    vault = _vault(tmp_path / "v", 40)
    seq = {r["path"]: r for r in scan_vault(vault, client=Slow(), offline=True)}
    writer_threads = set()

    def on_row(row):
        writer_threads.add(threading.get_ident())

    t0 = time.perf_counter()
    par_rows = scan_vault(vault, client=Slow(), offline=True, workers=8, on_row=on_row)
    par = {r["path"]: r for r in par_rows}
    assert set(par) == set(seq) and len(par_rows) == 40
    for p in seq:
        assert par[p]["bucket"] == seq[p]["bucket"] and par[p]["key"] == seq[p]["key"]
    assert writer_threads == {threading.get_ident()}  # every row emitted from the calling thread
    assert time.perf_counter() - t0 < 40 * 0.02  # faster than sequential


def test_workers_journal_is_well_formed(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path / "v", 30)
    monkeypatch.setattr(cli, "FixtureClient", Slow)
    assert cli.main([str(vault), "--offline", "--workers", "6", "--json"]) == 0
    j = _journals(vault)[-1]
    header, rows, torn = read_journal(j)
    assert not torn and header["workers"] == 6
    assert sorted(r["path"] for r in rows if r["kind"] == "vote") == sorted(f"n{i}.md" for i in range(30))
    assert rows[-1]["kind"] == "end"
    out = json.loads(capsys.readouterr().out)
    assert [r["path"] for r in out] == sorted(r["path"] for r in out)  # output sorted by path regardless of completion order


def test_workers_error_rows_and_exit_code(tmp_path: Path, monkeypatch):
    vault = _vault(tmp_path / "v", 20)
    monkeypatch.setattr(cli, "FixtureClient", lambda: RaisesOn({"n5.md", "n7.md"}))
    assert cli.main([str(vault), "--offline", "--workers", "4", "--quiet"]) == 2
    _, rows, _ = read_journal(_journals(vault)[-1])
    assert sorted(r["path"] for r in rows if r["kind"] == "error") == ["n5.md", "n7.md"]
