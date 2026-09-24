"""The run journal: append-as-you-go, error rows, progress, cache key, state-version pin.

Progress, checkpoint, resume, retry and cache are one feature: rows on disk as they finish.
This is step 1 (writing and reading). Resume is step 2 and is not tested here.
"""

from janitor import frontmatter
import json
import os
from pathlib import Path

import pytest

from janitor import cli
from janitor.client import FixtureClient, Vote
from janitor.journal import (
    STATE_VERSION,
    Journal,
    cache_key,
    journal_dir_for,
    read_journal,
    state_sources_digest,
    vault_id,
)
from janitor.scan import ScanAborted, scan_vault

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "notes"

# Pinned on purpose. If this fails, something that shapes the outgoing state changed
# (build_state, redact.py, build_questions, MAX_EXCERPT). Bump STATE_VERSION in
# janitor/journal.py and update this digest in the same commit; a cached vote from the
# old state version is not the same measurement.
# Re-pinned 2026-09-22 WITHOUT bumping STATE_VERSION, which the comment above tells you to
# do. The exception is deliberate and was measured: build_state's source changed (sibling
# titles are now redacted through a list whose hits are kept), but the object that leaves
# the machine did not. All twelve fixture notes produce a byte-identical canonical state on
# ae34f6d and on this branch; only the reported hit list grew. Bumping the version would
# have invalidated every cached vote in an 18,890-note vault to record a change in what we
# print. If you re-pin this line, say which of the two happened.
# Re-pinned 2026-09-22 WITH a bump to 6: graph facts and redacted aliases joined the state.
# Every cached vote from version 5 is a miss on purpose; the object that leaves the machine
# is different, so the vote is a different measurement.
# Re-pinned 2026-09-22 WITH a bump to 7: age_days is now creation age, not last-touched. The
# digest also grew to cover the index's facts, note_age_days and the bands, because the age
# defect changed a sent value without tripping this wire while only build_state was watched.
# Re-pinned 2026-09-22 WITH a bump to 8: whole-word denylist, PHONE ignoring order numbers, and
# sibling titles ranked by overlap and cut at 80 chars all change what leaves.
# Re-pinned 2026-09-22 WITH a bump to 9: CARD requires a card shape, and is_orphan is unknown
# on a vault that barely links. Both from the first live run of 0.4.0.
# Re-pinned 2026-09-22 WITH a bump to 10: CARD requires a payment-network first digit.
# Re-pinned 2026-09-22 WITH a bump to 11: sixteen more credential formats are redacted (a
# Telegram bot token used to leave as [PHONE]:<secret>), and the key line is case-sensitive.
# Any note holding one of them now sends a different excerpt.
# Re-pinned 2026-09-22 WITH a bump to 12: Telegram tokens after a bare colon and inside Bot API
# URLs are now redacted; v0.4.1 sent them. A note holding one sends a different excerpt.
# Re-pinned 2026-09-22 WITHOUT a bump (still 12): the questions moved from Python strings into
# the taxonomy file and question_payloads joined the digest, with no wording change. Measured:
# state plus serialized questions byte-identical for all 192 notes of a synthetic test corpus before
# and after (947,020 bytes). The taxonomy fingerprint changed (65bd5bfc7207 -> be00a24c7a68)
# because the file did; the wire did not.
# Re-pinned 2026-09-22 WITHOUT a bump (still 12): build_record_state (jev-records) joined the
# digest. New source, new sent object for a new kind of input; the vault's build_state and
# everything it sends are untouched, so every vault cache key is still the same measurement.
# Re-pinned 2026-09-23 WITHOUT a bump (still 12): two lines of a docstring in redact.py changed
# (the illustrative account id in card_shape_ok is now a synthetic one); no pattern, code path
# or sent byte changed, and the redaction suite passes unchanged.
# Re-pinned 2026-09-24 WITH a bump to 13 (0.4.7, one bump for the release): a password inside a
# URL is redacted whole, user included, before EMAIL runs (0.4.6 sent a localhost or IP one in
# the clear and let EMAIL take the password-and-host of a dotted one); the vault-relative path
# and the frontmatter key names are redacted like the title (0.4.6 sent both as written);
# sibling titles are cut after redaction, not before; and the redactor catches ASIA key ids,
# PGP and unterminated private-key blocks, keys after JSON escapes and percent-encoding, JWTs
# after an underscore, padded AWS secret lines, cards after a leading digit group, denylist
# entries across whitespace and in their own redacted form, phones after `case`/`id`/`part`
# and with a leading `+`. Every note holding any of these sends a different state, and the
# path and key names are in every state, so a note whose path or keys hold nothing sends
# the same bytes as before; the bump makes the whole 0.4.6 cache a miss on purpose, because
# a vote on a state that was later found to leak is not the measurement 0.4.7 makes.
# Re-pinned 2026-09-24 WITHOUT a further bump (still 13, same release), for the rest of 0.4.7:
# a credential-shaped filename stem is kept whole as the fallback title; a note whose own
# title holds a credential is dropped from every sibling list; AWS secrets and session tokens
# named without `aws` are taken; `obsidian://open?vault=Main:Notes@home`-style URLs are not
# credentials; and a one-to-five-digit password that runs straight into the `@` is a
# password, not a port. Each moves a sent state only for a note 0.4.6 was already leaking, or
# one 0.4.7's first cut would have wrongly quarantined; 13 already invalidates the 0.4.6 cache.
# Re-pinned 2026-09-24 WITHOUT a bump (still 13): a comment in redact.py was reworded; no
# pattern, code path or sent byte changed, and the redaction suite passes unchanged.
# Re-pinned 2026-09-24 WITHOUT a bump (still 13), 0.4.8: a single-file scan now ranks its sibling
# titles by overlap like a directory scan (only single-file states change, and their keys change
# on their own); a bracketed value is a placeholder only when what is inside is one (a note
# holding `{MyRealPassword}` in a URL now sends [URL_CREDENTIAL] and is quarantined; 0.4.7 sent
# it); the error-rate abort string and the survey header changed (not sent). Measured: the
# fixture vault's ten canonical states are byte-identical under the published 0.4.7 and this tree.
# Re-pinned 2026-09-24 WITHOUT a bump (still 13), 0.4.8 second cut: under --apply the writer thread
# stamps or quarantines right before it records the row (workers no longer touch disk), and a
# bracketed URL password next to a templated user or host reads as a template. Nothing sent
# changes for any note that 0.4.7 did not already leak.
RECORDED_STATE_SOURCES_DIGEST = "13c51f5a6c3a9b8c"
RECORDED_STATE_VERSION = 13


def test_state_version_is_bumped_when_state_sources_change():
    assert state_sources_digest() == RECORDED_STATE_SOURCES_DIGEST, (
        "what leaves the machine changed: bump STATE_VERSION and re-pin RECORDED_STATE_SOURCES_DIGEST"
    )
    assert STATE_VERSION == RECORDED_STATE_VERSION


# --- writing ------------------------------------------------------------------------------

def _vault(tmp_path: Path, n: int = 3) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (tmp_path / f"n{i}.md").write_text(f"# Note {i}\n\nbody {i}\n", encoding="utf-8")
    return tmp_path


def test_journal_header_rows_footer_and_incremental_append(tmp_path: Path):
    vault = _vault(tmp_path)
    jpath = tmp_path / "j" / "run.jsonl"
    journal = Journal(jpath, {"run": "abc", "taxonomy": "x"})
    seen_line_counts = []

    def on_row(row):
        journal.append(row)
        seen_line_counts.append(len(jpath.read_text(encoding="utf-8").splitlines()))

    rows = scan_vault(vault, offline=True, on_row=on_row)
    journal.close({"rows": len(rows), "errors": 0})
    # each row was on disk before the next note started: header + k rows after k notes
    assert seen_line_counts == [2, 3, 4]
    header, jrows, torn = read_journal(jpath)
    assert header["kind"] == "run" and header["run"] == "abc" and header["schema"] == 1
    assert [r["kind"] for r in jrows] == ["vote", "vote", "vote", "end"]
    assert not torn
    assert all("excerpt" not in r and "other_note_titles" not in r for r in jrows)  # decisions, not state


def test_journal_rows_carry_key_time_and_ms(tmp_path: Path):
    vault = _vault(tmp_path, 1)
    row = scan_vault(vault, offline=True)[0]
    assert row["kind"] == "vote"
    assert len(row["key"]) == 24 and row["cached"] is False
    assert row["at"].endswith("Z") and isinstance(row["ms"], int)


def test_torn_last_line_is_dropped_with_flag(tmp_path: Path):
    jpath = tmp_path / "run.jsonl"
    jpath.write_text('{"kind":"run","run":"a"}\n{"kind":"vote","path":"x"}\n{"kind":"vote","pa', encoding="utf-8")
    header, rows, torn = read_journal(jpath)
    assert header["run"] == "a" and [r["path"] for r in rows] == ["x"] and torn
    jpath.write_text('{"kind":"run","run":"a"}\n{"kind":"vote","path":"x"}\n', encoding="utf-8")
    assert read_journal(jpath)[2] is False


# --- error rows ---------------------------------------------------------------------------

class RaisesOn(FixtureClient):
    def __init__(self, bad_paths):
        self.bad = set(bad_paths)

    def vote(self, state, questions):
        if state["path"] in self.bad:
            raise ValueError(f"Jev response is missing answers for: persist ({state['path']})")
        return super().vote(state, questions)


def test_one_bad_response_does_not_discard_the_run(tmp_path: Path):
    vault = _vault(tmp_path, 3)
    rows = scan_vault(vault, client=RaisesOn({"n1.md"}), offline=True)
    kinds = [(r["path"], r["kind"]) for r in rows]
    assert kinds == [("n0.md", "vote"), ("n1.md", "error"), ("n2.md", "vote")]
    err = rows[1]
    assert err["action"] == "error" and err["error"] == "ValueError" and "persist" in err["detail"]
    assert "excerpt" not in err and "state" not in err


def test_error_rate_stop_after_window(tmp_path: Path):
    vault = _vault(tmp_path, 60)
    bad = {f"n{i}.md" for i in range(0, 60, 3)}  # every third note fails: 33% > 20%
    with pytest.raises(ScanAborted) as exc:
        scan_vault(vault, client=RaisesOn(bad), offline=True)
    assert "notes sent so far failed" in str(exc.value)  # a running total once the window is full, not "the first 50"
    assert len(exc.value.rows) >= 50  # rows so far are carried, not lost


def test_cli_error_rows_exit_2_and_json_stays_clean(tmp_path: Path, capsys, monkeypatch):
    vault = _vault(tmp_path, 3)
    monkeypatch.setattr(cli, "FixtureClient", lambda: RaisesOn({"n2.md"}))
    rc = cli.main([str(vault), "--offline", "--json"])
    assert rc == cli.EXIT_ERRORS == 2
    out, err = capsys.readouterr()
    rows = json.loads(out)  # stdout must parse as JSON with progress and journal lines on stderr
    assert [r["kind"] for r in rows] == ["vote", "vote", "error"]
    assert "journal:" in err and "failed" in err


def test_cli_success_exit_0(tmp_path: Path, capsys):
    vault = _vault(tmp_path, 2)
    assert cli.main([str(vault), "--offline"]) == 0


# --- location: outside the vault by default, so a dry run stays byte-identical -------------

def test_default_journal_is_outside_the_vault_and_dry_run_leaves_vault_untouched(tmp_path: Path, capsys):
    vault = _vault(tmp_path / "vault", 2)
    before = sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*"))
    assert cli.main([str(vault), "--offline"]) == 0
    after = sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*"))
    assert after == before
    cache = Path(os.environ["JEV_JANITOR_CACHE_DIR"]) / "journals" / vault_id(vault)
    journals = list(cache.glob("run-*.jsonl"))
    assert len(journals) == 1
    header, rows, torn = read_journal(journals[0])
    assert header["vault_id"] == vault_id(vault) and header["janitor"] and header["taxonomy"]
    assert rows[-1]["kind"] == "end" and rows[-1]["exit"] == 0
    assert f"journal: {journals[0]}" in capsys.readouterr().err


def test_journal_vault_option_writes_only_under_janitor_runs(tmp_path: Path):
    vault = _vault(tmp_path / "vault", 2)
    assert cli.main([str(vault), "--offline", "--journal", "vault"]) == 0
    written = sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*") if p.is_file() and not p.name.endswith(".md"))
    assert len(written) == 1 and written[0].startswith("_janitor/runs/run-")


def test_journal_off_writes_nothing(tmp_path: Path):
    vault = _vault(tmp_path / "vault", 2)
    assert cli.main([str(vault), "--offline", "--journal", "off"]) == 0
    assert not list(Path(os.environ["JEV_JANITOR_CACHE_DIR"]).rglob("*.jsonl"))
    assert not (vault / "_janitor").exists()


def test_journal_dir_resolution(tmp_path: Path):
    root = tmp_path / "v"
    assert journal_dir_for(root, "off") is None
    assert journal_dir_for(root, "vault") == root / "_janitor" / "runs"
    assert journal_dir_for(root, str(tmp_path / "elsewhere")) == tmp_path / "elsewhere"
    assert journal_dir_for(root, None).name == vault_id(root)


# --- cache key: hash exactly what is sent --------------------------------------------------

def test_cache_key_covers_state_taxonomy_version_and_model():
    state = {"title": "T", "path": "a.md", "frontmatter_keys": [], "excerpt": "x", "other_note_titles": ["B"]}
    base = cache_key(state, "tax1", "jev-latest")
    assert cache_key(dict(state), "tax1", "jev-latest") == base
    assert cache_key({**state, "excerpt": "x [NAME]"}, "tax1", "jev-latest") != base  # denylist edit changes excerpt
    assert cache_key({**state, "other_note_titles": ["B", "C"]}, "tax1", "jev-latest") != base  # sibling added
    assert cache_key({**state, "path": "b.md"}, "tax1", "jev-latest") != base  # renamed
    assert cache_key(state, "tax2", "jev-latest") != base  # wording changed
    assert cache_key(state, "tax1", "jev-1.13") != base  # model requested changed


def test_edit_below_the_cap_keeps_the_key(tmp_path: Path):
    # Words are in the state to two significant figures, so a few extra words below the cap
    # on a note this size (3,300 -> still 3,300) keep the key. On a five-word note they would not.
    body = "# T\n\n" + ("word " * (frontmatter.MAX_EXCERPT // 5 + 100))
    (tmp_path / "n.md").write_text(body + "\nTAIL ONE\n", encoding="utf-8")
    k1 = scan_vault(tmp_path, offline=True)[0]["key"]
    (tmp_path / "n.md").write_text(body + "\nTAIL TWO, edited below the cap\n", encoding="utf-8")
    k2 = scan_vault(tmp_path, offline=True)[0]["key"]
    assert k1 == k2  # Jev would see the same excerpt, so the same vote is the right vote


# --- sibling titles memoized from the plan ------------------------------------------------

def test_flat_folder_parses_each_note_exactly_once(tmp_path: Path, monkeypatch):
    """The index reads each note once. 0.1.x re-globbed the folder per note (~81 parses each);
    0.2.0 memoized titles per folder (twice each); the index is the single read."""
    from janitor import index as index_module

    for i in range(200):
        (tmp_path / f"n{i:03d}.md").write_text(f"# Note {i}\n\nbody\n", encoding="utf-8")
    calls = {"n": 0}
    real = index_module.load_note

    def counting(path):
        calls["n"] += 1
        return real(path)

    monkeypatch.setattr(index_module, "load_note", counting)
    rows = scan_vault(tmp_path, offline=True)
    assert len(rows) == 200
    assert calls["n"] == 200


def test_memoized_titles_match_collect_titles_semantics(tmp_path: Path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x.md").write_text("# X\n\nbody\n", encoding="utf-8")
    (tmp_path / "a" / "y.md").write_text("# Y\n\nbody of y\n", encoding="utf-8")
    (tmp_path / "family").mkdir()
    (tmp_path / "family" / "z.md").write_text("# Zebra Secret\n\nbody of z\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("# B\n\nbody of b\n", encoding="utf-8")

    class Rec(FixtureClient):
        def __init__(self):
            self.states = []

        def vote(self, s, q):
            self.states.append(s)
            return super().vote(s, q)

    rec = Rec()
    scan_vault(tmp_path, client=rec, offline=True)
    by = {s["path"]: s["other_note_titles"] for s in rec.states}
    assert by["a/x.md"] == ["Y"] and by["a/y.md"] == ["X"] and by["b.md"] == []
    assert "Zebra" not in json.dumps(rec.states)
