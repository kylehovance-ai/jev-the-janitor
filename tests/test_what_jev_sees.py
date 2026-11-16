"""0.5.9: docs/what-jev-sees.md is pinned to the code it describes.

The page names the state's seven fields, its defaults and the questions, and shows one real state
from the demo vault. Each of those is a claim, so each is compared here with the code: the field
names with build_state's keys, the numbers with the constants and the taxonomy, and the example
with a fresh state built from examples/demo-vault.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from janitor.frontmatter import HARD_EXCERPT_CAP, MAX_EXCERPT, MAX_TITLES, load_note
from janitor.index import MAX_TITLE_CHARS
from janitor.scan import build_state, prepare_vault
from janitor.schema import REQUIRED_NOULS, load_taxonomy

ROOT = Path(__file__).resolve().parent.parent
PAGE = (ROOT / "docs" / "what-jev-sees.md").read_text(encoding="utf-8")
NL = chr(10)
WORDS = {5: "five", 7: "seven", 9: "nine"}
EXAMPLE_PATH = "Areas/Health/Running.md"


def _section(title: str) -> str:
    return PAGE.split(NL + "## " + title + NL)[1].split(NL + "## ")[0]


def _table_fields() -> list[str]:
    return re.findall(r"^\| `([a-z_]+)` \|", _section("The state: exactly seven fields"), re.M)


def _state_of_a_real_note(tmp_path: Path) -> dict:
    (tmp_path / "n.md").write_text("---" + NL + "aliases: [x]" + NL + "---" + NL + "# N" + NL + NL + "body" + NL, encoding="utf-8")
    state, _, _ = build_state(load_note(tmp_path / "n.md"), ["Other"], None, rel_path="n.md", aliases=["x"],
                              facts={"words": 1})
    return state


def _example() -> dict:
    block = re.search(r"```json" + NL + r"(.*?)" + NL + "```", _section("An example"), re.S).group(1)
    return json.loads(block)


def _fresh_demo_state() -> dict:
    _, _, items, _ = prepare_vault(ROOT / "examples" / "demo-vault")
    return next(it.state for it in items if it.rel == EXAMPLE_PATH)


def test_the_pages_seven_field_names_are_build_states_keys_exactly(tmp_path: Path):
    state = _state_of_a_real_note(tmp_path)
    assert _table_fields() == list(state.keys())  # the same names, in the order build_state writes them
    assert len(state) == 7 and "## The state: exactly seven fields" in PAGE


def test_the_pages_graph_keys_are_the_nine_the_index_sends():
    graph_row = next(line for line in _section("The state: exactly seven fields").splitlines() if line.startswith("| `graph` |"))
    listed = re.findall(r"`([a-z_]+)`", graph_row.split("exactly nine keys:")[1])
    fresh = _fresh_demo_state()["graph"]
    assert listed == list(fresh.keys()) and len(listed) == 9


def test_the_pages_numbers_are_the_constants_and_the_taxonomy():
    defaults = _section("The defaults")
    assert f"the first {MAX_EXCERPT:,} characters of the redacted body (`MAX_EXCERPT`)" in defaults and MAX_EXCERPT == 16_000
    assert f"up to the {HARD_EXCERPT_CAP:,}-character hard guard (`HARD_EXCERPT_CAP`)" in defaults and HARD_EXCERPT_CAP == 60_000
    assert f"Up to {MAX_TITLES} sibling titles are sent (`MAX_TITLES`), each cut to {MAX_TITLE_CHARS} characters (`MAX_TITLE_CHARS`)" in defaults
    assert (MAX_TITLES, MAX_TITLE_CHARS) == (80, 80)
    table = _section("The state: exactly seven fields")
    assert f"at most {MAX_TITLES}, each redacted and then cut to {MAX_TITLE_CHARS} characters" in table
    assert f"exactly {WORDS[len(_fresh_demo_state()['graph'])]} keys:" in table
    questions = load_taxonomy()["questions"]
    nouls = [name for name, q in questions.items() if q["type"] == "noul"]
    asked = _section("The questions")
    assert f"the {WORDS[len(questions)]} questions in" in asked and len(questions) == 7
    assert f"the `bucket` choice, the `persist` score and {WORDS[len(nouls)]} nouls" in asked
    assert questions["bucket"]["type"] == "choice" and questions["persist"]["type"] == "score"
    assert re.findall(r"`([a-z_]+)`", asked.split("nouls (")[1].split(")")[0]) == nouls and set(nouls) == set(REQUIRED_NOULS)


def test_the_examples_keys_are_a_fresh_demo_vault_states_keys():
    example, fresh = _example(), _fresh_demo_state()
    assert list(example.keys()) == list(fresh.keys())
    assert list(example["graph"].keys()) == list(fresh["graph"].keys())
    assert example == fresh  # and, the note being short and untrimmed, the whole state verbatim
    assert f"the note `{EXAMPLE_PATH}`" in PAGE


# --- 0.6.0: "What never leaves", one behavioural test per bullet, offline, no key ----------------
# Each test builds a small invented vault and reads what was actually handed to the client (a
# recording FixtureClient) or the --show-payload `sent` objects, and checks the phrases of its own
# bullet that it proves. Older gates that prove part of a bullet are named beside it.
# 0.6.1: tightened so each test fails if its bullet were false (an outside audit's v0.6.0 items 20-31).

from datetime import datetime, timedelta, timezone  # noqa: E402

import pytest  # noqa: E402

from janitor import cli  # noqa: E402
from janitor import index as index_module  # noqa: E402
from janitor.client import FixtureClient  # noqa: E402
from janitor.index import banded_age  # noqa: E402
from janitor.plan import plan_vault  # noqa: E402
from janitor.policy import HIGH_PRECISION_SECRETS  # noqa: E402
from janitor.redact import path_is_sensitive, redact  # noqa: E402
from janitor.scan import scan_vault  # noqa: E402
from tests.test_redact_numbers_together import WIDEN_SENTENCE  # noqa: E402

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"  # invented; the same shape tests/test_survey.py uses
# One invented single-line sample per credential label (the AWS one is AWS's documented example key).
CREDENTIALS = {
    "KEY": KEY,
    # the two URL-shaped ones are built here, so no file in the tree holds one whole (test_redact_formats)
    "WEBHOOK": "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24,
    "JWT": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "PEM": "-----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEA",
    "AWS_SECRET": "aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    "BEARER": "Bearer abcdefghijklmnopqrstuvwxyz0123456789",
    "URL_CREDENTIAL": "postgres://admin:" + "hunter2pass" + "@db.example.com/app",
}


class Recording(FixtureClient):
    def __init__(self) -> None:
        super().__init__()
        self.states: list[dict] = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _note(root: Path, rel: str, front: list[str], body: str) -> Path:
    head = ["---", *front, "---"] if front else []
    return _write(root, rel, NL.join([*head, body, ""]))


def _sent(vault: Path, **kwargs) -> dict[str, dict]:
    """The states the client received, by path."""
    rec = Recording()
    scan_vault(vault, client=rec, offline=True, **kwargs)
    return {s["path"]: s for s in rec.states}


def _rows(vault: Path, capsys, *extra: str) -> dict[str, dict]:
    assert cli.main([str(vault), "--offline", "--json", "--journal", "off", "--quiet", *extra]) == 0
    return {r["path"]: r for r in json.loads(capsys.readouterr().out)}


def _spy_load_note(monkeypatch) -> list[str]:
    """Every path the index opens, by vault-relative posix form of its last three parts."""
    opened: list[str] = []
    real = index_module.load_note

    def load(path: Path):
        opened.append(path.as_posix())
        return real(path)

    monkeypatch.setattr(index_module, "load_note", load)
    return opened


def _never_leaves_bullets() -> list[str]:
    return re.findall(r"^- \*\*(.+?)\*\*", _section("What never leaves"), re.M)


def _bullet(lead: str) -> str:
    """The whole text of the bullet whose bold lead is ``lead``, flattened to one line."""
    for line in _section("What never leaves").splitlines():
        if line.startswith(f"- **{lead}**"):
            return line
    raise AssertionError(f"no bullet {lead!r}")


def _today():
    return datetime.now(timezone.utc).date()  # the date the index ages notes by


def _band_for(days_ago: int) -> int:
    return banded_age(days_ago)


def test_frontmatter_values_other_than_title_aliases_and_creation_dates_never_leave(tmp_path: Path):
    today = _today()
    recent, old, ancient = (today - timedelta(days=10)), (today - timedelta(days=400)), (today - timedelta(days=2000))
    assert len({_band_for(10), _band_for(400), _band_for(2000), _band_for(0)}) == 4  # four distinct bands, so each source is told apart
    notes = {
        # the earliest creation key wins; `modified` (a different band again) does not feed it
        "Garden/earliest.md": (["title: Garden plan", "aliases: [Beds]", f"created: {recent}", f"date: {old}",
                                f"modified: {ancient}", "owner: quokka-marmalade", "tags: [zebra-quartz]", "rating: 4711"], "# Heading" + NL + NL + "body text one", 400),
        "Garden/date.md": ([f"date: {old}", f"modified: {ancient}"], "# D" + NL + NL + "body two", 400),
        "Garden/created_at.md": ([f"created_at: {old}", f"updated: {ancient}"], "# C" + NL + NL + "body three", 400),
        "Garden/creation_date.md": ([f"creation_date: {old}", f"modified: {ancient}"], "# CD" + NL + NL + "body four", 400),
        "Garden/stamped.md": (["janitor:", "  bucket: junk", f"  created_from_mtime: {old}", f"modified: {ancient}"], "# S" + NL + NL + "body five", 400),
        "Garden/alias.md": (["alias: Single alias"], "# A" + NL + NL + "body six", 0),  # no creation key: the mtime, today
    }
    for rel, (front, body, _) in notes.items():
        _note(tmp_path, rel, front, body)
    sent = _sent(tmp_path)
    wire = json.dumps(sent)
    for value in ("quokka-marmalade", "zebra-quartz", "4711", "junk", str(recent), str(old), str(ancient)):
        assert value not in wire, value  # values stay local; the dates arrive only as bands
    for rel, (_, _, days) in notes.items():
        assert sent[rel]["graph"]["age_days"] == _band_for(days), rel
    first = sent["Garden/earliest.md"]
    assert first["title"] == "Garden plan" and first["aliases"] == ["Beds"]  # the frontmatter title wins over the H1
    assert first["frontmatter_keys"] == ["aliases", "created", "date", "modified", "owner", "rating", "tags", "title"]
    assert sent["Garden/alias.md"]["aliases"] == ["Single alias"]  # `alias` is read when there is no `aliases`
    assert "Garden plan" in sent["Garden/date.md"]["other_note_titles"] and "Heading" not in json.dumps(sent["Garden/date.md"])
    text = _bullet("Frontmatter values")
    for phrase in ("a non-empty `title` string becomes the state's `title`", "this note's entry in other notes' `other_note_titles`",
                   "`aliases`, or `alias` when there is no `aliases` key", "the earliest parseable `created`, `date`, `created_at` or `creation_date`",
                   "or else the date in `janitor.created_from_mtime`", "as a band of days, never as the date itself", "the key names only"):
        assert phrase in text, phrase


def test_the_absolute_path_never_leaves(tmp_path: Path):
    """tests/test_state_path.py is the gate for the relative posix path; this pins the page's bullet."""
    _write(tmp_path, "Areas/n.md", "# N" + NL + NL + "body" + NL)
    state = _sent(tmp_path)["Areas/n.md"]
    wire = json.dumps(state)
    assert state["path"] == "Areas/n.md"
    assert str(tmp_path) not in wire and tmp_path.as_posix() not in wire and tmp_path.name not in wire
    assert "The state's `path` is relative to the vault." in _bullet("The absolute path.")


def test_hidden_notes_inside_the_scan_are_never_opened_and_the_named_cases_are_exact(tmp_path: Path, monkeypatch):
    """tests/test_preflight.py::test_hidden_folders_are_skipped_by_the_dot_rule_not_the_list covers the plan."""
    vault = tmp_path / "v"
    _write(vault, ".hidden/h.md", "# Hidden" + NL + NL + "hidden body" + NL)
    _write(vault, "notes/.h2.md", "# Hidden file" + NL + NL + "hidden body two" + NL)
    _write(vault, "notes/v.md", "# Visible" + NL + NL + "body" + NL)
    opened = _spy_load_note(monkeypatch)
    for include_sensitive in (False, True):
        _, plan = plan_vault(vault, include_sensitive=include_sensitive)
        status = {e.rel: e.status for e in plan}
        assert status[".hidden/h.md"] == status["notes/.h2.md"] == "skip_hidden" and status["notes/v.md"] == "scan"
        sent = _sent(vault, include_sensitive=include_sensitive)
        assert set(sent) == {"notes/v.md"} and "Hidden" not in json.dumps(sent)
    assert not any(p.endswith(("/h.md", "/.h2.md")) for p in opened)  # stat only, never read
    # a hidden folder named as the target is scanned as named, and its notes list each other
    _write(vault, ".hidden/h2.md", "# Second hidden" + NL + NL + "another body" + NL)
    named = _sent(vault / ".hidden")
    assert set(named) == {"h.md", "h2.md"} and named["h.md"]["other_note_titles"] == ["Second hidden"]
    # a single note named directly: with an .obsidian/ marker, hidden folders count from the marker's folder down
    _write(tmp_path, "X/.secret/Vault/.obsidian/app.json", "{}")
    _write(tmp_path, "X/.secret/Vault/note.md", "# Above the marker" + NL + NL + "body m" + NL)  # hidden folder above the vault root
    _write(tmp_path, "X/.secret/Vault/.inner/deep.md", "# Below the marker" + NL + NL + "body d" + NL)  # hidden folder inside it
    _write(tmp_path, ".Vault3/.obsidian/app.json", "{}")
    _write(tmp_path, ".Vault3/n.md", "# Hidden vault" + NL + NL + "body h" + NL)  # the marker's own folder is hidden, and counts
    # with no marker, any hidden ancestor counts
    _write(tmp_path, "Y/.hid/V2/note.md", "# No marker" + NL + NL + "body n" + NL)
    for rel, expected in (("X/.secret/Vault/note.md", "scan"), ("X/.secret/Vault/.inner/deep.md", "skip_hidden"),
                          (".Vault3/n.md", "skip_hidden"), ("Y/.hid/V2/note.md", "skip_hidden")):
        assert [e.status for e in plan_vault(tmp_path / rel)[1]] == [expected], rel
    assert set(_sent(tmp_path / "X/.secret/Vault/note.md")) == {"note.md"} and _sent(tmp_path / "Y/.hid/V2/note.md") == {}
    # 0.6.2 (outside audit of 0.6.1, item 11): what is sent, not only the plan status
    assert _sent(tmp_path / "X/.secret/Vault/.inner/deep.md") == {} and _sent(tmp_path / ".Vault3/n.md") == {}
    # a folder named as the target under a hidden ancestor is scanned as named; a hidden folder inside it is not
    sent = _sent(tmp_path / "X/.secret/Vault")
    assert set(sent) == {"note.md"} and "Below the marker" not in json.dumps(sent)
    assert set(_sent(tmp_path / "Y/.hid/V2")) == {"note.md"}
    assert not any(p.endswith(("/deep.md", "/n.md")) for p in opened)  # the skipped ones were never read
    assert set(_sent(tmp_path / ".Vault3")) == {"n.md"}  # the hidden vault named as a folder is scanned as named
    text = _bullet("Notes under a hidden folder, and hidden files")
    for phrase in ("never opened", "`--include-sensitive` does not change that",
                   "A folder you name as the target is scanned as named, even when it or a folder above it is hidden.",
                   "a hidden folder between the folder that holds `.obsidian/` (that folder included) and the note skips it, and one above that folder does not",
                   "with no `.obsidian/` above the note, any hidden folder above it skips it."):
        assert phrase in text, phrase


def test_janitor_working_folder_notes_are_never_opened_even_when_named(tmp_path: Path, monkeypatch):
    _write(tmp_path, "_janitor/quarantine/q.md", "# Quarantined" + NL + NL + "body" + NL)
    _write(tmp_path, "v.md", "# Visible" + NL + NL + "body" + NL)
    opened = _spy_load_note(monkeypatch)
    for include_sensitive in (False, True):
        _, plan = plan_vault(tmp_path, include_sensitive=include_sensitive)
        assert {e.rel: e.status for e in plan}["_janitor/quarantine/q.md"] == "skip_janitor"
        sent = _sent(tmp_path, include_sensitive=include_sensitive)
        assert set(sent) == {"v.md"} and "Quarantined" not in json.dumps(sent)
    before = (tmp_path / "_janitor/quarantine/q.md").read_bytes()
    sent = _sent(tmp_path, apply=True)  # 0.6.2 (audit item 14): an applying run does not open it either
    assert set(sent) == {"v.md"} and (tmp_path / "_janitor/quarantine/q.md").read_bytes() == before
    for named in (tmp_path / "_janitor", tmp_path / "_janitor" / "quarantine", tmp_path / "_janitor" / "quarantine" / "q.md"):
        _, plan = plan_vault(named)
        assert [e.status for e in plan] == ["skip_janitor"]
        assert _sent(named) == {}
    assert opened and not any(p.endswith("/q.md") for p in opened)  # the spy saw v.md opened, and never q.md
    assert "never opened, whatever the flags" in _bullet("Notes under `_janitor/`")


def test_a_sensitive_notes_title_is_never_a_sibling_and_it_gets_none(tmp_path: Path):
    """tests/test_titles_privacy.py is the gate; this pins the bullet, both halves of the --include-sensitive case."""
    _write(tmp_path, "family/Secret plan.md", "# Secret plan" + NL + NL + "body one" + NL)
    _write(tmp_path, "family/Other plan.md", "# Other plan" + NL + NL + "body two" + NL)
    _write(tmp_path, "public/plan.md", "# Public plan" + NL + NL + "body three" + NL)
    _write(tmp_path, "public/sib.md", "# Sibling" + NL + NL + "body four" + NL)
    sent = _sent(tmp_path)
    assert set(sent) == {"public/plan.md", "public/sib.md"} and "Secret plan" not in json.dumps(sent)
    sent = _sent(tmp_path, include_sensitive=True)
    assert {"family/Secret plan.md", "family/Other plan.md"} <= set(sent)
    assert sent["family/Secret plan.md"]["other_note_titles"] == [] and sent["family/Other plan.md"]["other_note_titles"] == []
    assert all("Secret plan" not in t and "Other plan" not in t for s in sent.values() for t in s["other_note_titles"])
    text = _bullet("Notes under sensitive folders")
    assert "titles are never listed as another note's sibling" in text and "sent with no sibling titles of their own" in text


# Where each own field puts the sample. A path segment cannot hold `/`, so the two URL-shaped
# credentials have no path case (a folder name with a slash is two folders).
FIELDS = {
    "title": lambda s: ("n.md", [f"title: 'Note {s}'"], "# Plain" + NL + NL + "clean body words"),
    "aliases": lambda s: ("n.md", [f"aliases: ['{s}']"], "# Plain" + NL + NL + "clean body words"),
    "path": lambda s: (f"{s}/n.md", [], "# Plain" + NL + NL + "clean body words"),
    "frontmatter key name": lambda s: ("n.md", [f"'{s}': 1"], "# Plain" + NL + NL + "clean body words"),
    "body": lambda s: ("n.md", [], "# Plain" + NL + NL + f"clean body words {s}"),
}
CREDENTIAL_CASES = [(label, field) for label in CREDENTIALS for field in FIELDS
                    if not (field == "path" and "/" in CREDENTIALS[label])]


def test_the_credential_samples_are_exactly_the_seven_labels():
    assert set(CREDENTIALS) == set(HIGH_PRECISION_SECRETS) and len(CREDENTIALS) == 7
    for label, sample in CREDENTIALS.items():
        assert redact(sample).hits == [label], label
    assert len(CREDENTIAL_CASES) == 7 * 5 - 2


@pytest.mark.parametrize(("label", "field"), CREDENTIAL_CASES)
def test_a_credential_hit_in_any_own_field_is_not_sent_and_says_sent_null(tmp_path: Path, capsys, label: str, field: str):
    rel, front, body = FIELDS[field](CREDENTIALS[label])
    _note(tmp_path, rel, front, body)
    _write(tmp_path, "other.md", "# Other" + NL + NL + "another clean body" + NL)
    # The PEM sample's folder name holds the word `PRIVATE`, a sensitive name, so that case is
    # skipped before triage by default; --include-sensitive lets the credential rule decide it.
    sensitive = path_is_sensitive(rel)
    assert sensitive == (field == "path" and label == "PEM")
    flags = {"include_sensitive": True} if sensitive else {}
    assert set(_sent(tmp_path, **flags)) == {"other.md"}
    rows = _rows(tmp_path, capsys, "--show-payload", *(["--include-sensitive"] if sensitive else []))
    leak = next(r for path, r in rows.items() if path != "other.md")
    assert leak["judge"] == "local" and leak["action"] == "quarantine" and leak["sent"] is None
    assert label in leak["redacted_own"] and leak["quarantine_triggers"]
    # without local triage the note is sent, the credential replaced by its label
    sent = _sent(tmp_path, local_triage=False, **flags)
    assert len(sent) == 2 and CREDENTIALS[label] not in json.dumps(sent) and f"[{label}]" in json.dumps(sent)
    text = _bullet("A note with a credential hit")
    assert "in its own title, aliases, path, frontmatter key names or body" in text and "`--no-local-triage` turns it off" in text
    assert re.findall(r"`([A-Z_]+)`", text.split("**")[2].split(")")[0]) == list(HIGH_PRECISION_SECRETS)


def test_local_triage_decides_three_rules_and_sent_is_only_a_show_payload_key(tmp_path: Path, capsys):
    """tests/test_cold_review_055.py::test_show_payload_puts_sent_only_on_rows_that_leave covers the null."""
    _write(tmp_path, "a.md", "# A" + NL + NL + "the same body" + NL)
    _write(tmp_path, "b.md", "# B" + NL + NL + "the same body" + NL)  # an exact duplicate of a.md, later in plan order
    _write(tmp_path, "empty.md", "")
    _write(tmp_path, "heads.md", "# Only" + NL + NL + "## headings" + NL)
    _write(tmp_path, "leak.md", "# Leak" + NL + NL + KEY + NL)
    assert set(_sent(tmp_path)) == {"a.md"}
    rows = _rows(tmp_path, capsys, "--show-payload")
    for rel in ("b.md", "empty.md", "heads.md", "leak.md"):
        assert rows[rel]["judge"] == "local" and rows[rel]["sent"] is None, rel
    assert isinstance(rows["a.md"]["sent"], dict)
    plain = _rows(tmp_path, capsys)
    assert all("sent" not in r for r in plain.values())  # without the flag no row has the key
    assert set(_sent(tmp_path, local_triage=False)) == {"a.md", "b.md", "empty.md", "heads.md", "leak.md"}
    text = _bullet("A note local triage decides.")
    assert "Under `--show-payload` such a row says `sent: null`; without that flag no row has a `sent` key." in text


def test_the_triage_rules_apply_in_the_pages_order_by_outcome(tmp_path: Path, capsys):
    """0.6.2 (outside audit of 0.6.1, item 12): the order is proved by what a note that fits two rules becomes."""
    _write(tmp_path, "k1.md", "# K1" + NL + NL + KEY + NL)
    _write(tmp_path, "k2.md", "# K1" + NL + NL + KEY + NL)  # a credential and an exact duplicate of k1.md
    _write(tmp_path, "kempty.md", f"# Note {KEY}" + NL)  # a credential (in the title) and headings only
    _write(tmp_path, "e1.md", "")
    _write(tmp_path, "e2.md", "")  # empty, and the same bytes as e1.md
    rows = _rows(tmp_path, capsys)
    for rel in ("k1.md", "k2.md", "kempty.md"):  # secret wins over duplicate and over empty
        assert rows[rel]["action"] == "quarantine" and rows[rel]["bucket"] == "needs_review", rel
        assert rows[rel]["contains_secret"] == 1.0 and rows[rel]["looks_like_duplicate"] == 0.0, rel
    for rel in ("e1.md", "e2.md"):  # empty wins over duplicate
        assert rows[rel]["action"] == "frontmatter" and rows[rel]["reason"].startswith("empty body or headings only"), rel
        assert rows[rel]["looks_like_duplicate"] == 0.0, rel
    # the duplicate rule itself still fires when nothing earlier does
    _write(tmp_path, "d1.md", "# D" + NL + NL + "a body twice" + NL)
    _write(tmp_path, "d2.md", "# D" + NL + NL + "a body twice" + NL)
    assert _rows(tmp_path, capsys)["d2.md"]["reason"] == "exact duplicate of d1.md: decided locally"


def test_a_locked_note_is_skipped_with_no_request_whatever_the_flags(tmp_path: Path, capsys, monkeypatch):
    """tests/test_triage.py::test_locked_note_is_a_skip_row_with_no_request_and_no_rewrite covers the default."""
    _write(tmp_path, "locked.md", NL.join(["---", "janitor:", "  locked: true", "---", "# Locked", "", "locked body", ""]))
    _write(tmp_path, "ok.md", "# Ok" + NL + NL + "open body" + NL)  # a different body, so neither is a duplicate
    before = (tmp_path / "locked.md").read_bytes()
    for kwargs in ({}, {"local_triage": False}, {"include_sensitive": True}, {"apply": True}):
        rec = Recording()
        rows = {r["path"]: r for r in scan_vault(tmp_path, client=rec, offline=True, **kwargs)}
        assert [s["path"] for s in rec.states] == ["ok.md"] and rows["locked.md"]["action"] == "skip_locked", kwargs
        assert (tmp_path / "locked.md").read_bytes() == before, kwargs  # 0.6.2 (audit item 13): apply leaves it as it was
    # and through the CLI's --apply: every request the client receives is recorded, and none is the locked note's
    seen: list[str] = []
    real_vote = FixtureClient.vote

    def vote(self, state, questions):
        seen.append(state["path"])
        return real_vote(self, state, questions)

    monkeypatch.setattr(FixtureClient, "vote", vote)
    rows = _rows(tmp_path, capsys, "--apply")
    assert rows["locked.md"]["action"] == "skip_locked" and seen == ["ok.md"]  # the spy saw the one request
    assert (tmp_path / "locked.md").read_bytes() == before
    assert "skipped with no request, whatever the flags" in _bullet("A locked note")


def test_an_undecodable_or_unreadable_note_is_never_sent_nor_a_sibling(tmp_path: Path, monkeypatch):
    (tmp_path / "bad.md").write_bytes(b"# Bad title" + NL.encode() + b"\xff\xfe not utf-8" + NL.encode())
    _write(tmp_path, "gone.md", "# Gone title" + NL + NL + "body" + NL)
    _write(tmp_path, "ok.md", "# Ok" + NL + NL + "body" + NL)
    real = index_module.load_note

    def load(path: Path):
        if path.name == "gone.md":
            raise PermissionError("cannot read")  # an unreadable note
        return real(path)

    monkeypatch.setattr(index_module, "load_note", load)
    rec = Recording()
    rows = {r["path"]: r for r in scan_vault(tmp_path, client=rec, offline=True)}
    assert [s["path"] for s in rec.states] == ["ok.md"]
    assert rows["bad.md"]["action"] == "skip_undecodable" and rows["gone.md"]["kind"] == "error"
    wire = json.dumps(rec.states)
    assert "Bad title" not in wire and "Gone title" not in wire and rec.states[0]["other_note_titles"] == []
    text = _bullet("A note that is not valid UTF-8, or that cannot be read")
    assert "nothing of it is sent, and it is never listed as another note's sibling" in text


def test_the_body_past_the_excerpt_cap_never_leaves_and_a_hit_across_the_cap_is_redacted_first(tmp_path: Path):
    """tests/test_excerpt_chars.py covers the caps. Here a hit straddles the cut: cut-then-redact would
    send `ada.exampl` (no longer an email, so no hit); redact-then-cut sends `[EMAIL]`."""
    email = "ada.example@example.org"
    head = "# Long" + NL + NL
    filler = "a" * (190 - len(head) - 1) + " "
    body = head + filler + email + " " + "porcupine-tail " * 20
    assert body.index(email) == 190 and body.index(email) + len(email) > 200  # it straddles character 200
    _write(tmp_path, "long.md", body + NL)
    state = _sent(tmp_path, excerpt_chars=200)["long.md"]
    assert len(state["excerpt"]) == 200 and "porcupine" not in json.dumps(state)
    assert "ada.exampl" not in state["excerpt"] and state["excerpt"][190:197] == "[EMAIL]"
    assert "The body is redacted whole and then cut" in _bullet("The body past the excerpt cap.")
    # 0.6.2 (audit item 15): the defaults themselves, on a note longer than both
    _write(tmp_path, "long.md", "# Long" + NL + NL + "plain words " * 6000 + NL)  # 72,009 characters
    assert _sent(tmp_path)["long.md"]["excerpt"] == load_note(tmp_path / "long.md").body[:16000]
    assert len(_sent(tmp_path)["long.md"]["excerpt"]) == 16000
    assert len(_sent(tmp_path, excerpt_chars=cli.parse_excerpt_chars("full"))["long.md"]["excerpt"]) == 60000
    assert "(16,000 by default; `full` is still cut at the 60,000-character guard)" in _bullet("The body past the excerpt cap.")


def test_the_original_text_of_a_redaction_hit_never_leaves_while_the_note_does(tmp_path: Path):
    email, name, phone = "ada.example@example.org", "Jane Placeholder", "555-201-4477"
    card, ssn = "4111 1111 1111 1111", "123-45-6789"  # a documented test card number and an invented SSN
    _note(tmp_path, f"Notes/{name}.md", [f"aliases: [{email}]", f"'{email}': 1"],
          NL.join([f"# Call {name}", "", f"write to {email} or call {phone}", f"card {card}", f"ssn {ssn} {card}"]))
    _note(tmp_path, "Notes/Sibling.md", [f"title: Sibling {email}"], "sibling body")
    sent = _sent(tmp_path, denylist=[name])
    wire = json.dumps(sent)
    for original in (email, name, phone, card, ssn, "123-45", "1111"):
        assert original not in wire, original
    state = sent["Notes/[NAME].md"]  # the note itself leaves, with labels in place, path included
    assert state["title"] == "Call [NAME]" and state["aliases"] == ["[EMAIL]"] and "[EMAIL]" in state["frontmatter_keys"]
    assert state["excerpt"].endswith("write to [EMAIL] or call [PHONE]" + NL + "card [CARD]" + NL + "ssn [SSN] [CARD]")
    assert state["other_note_titles"] == ["Sibling [EMAIL]"]  # a non-credential hit is listed, redacted
    text = _bullet("The original text of a redaction hit")
    assert "such as an `EMAIL`, `PHONE`, `CARD` or `SSN` match or a denylist match" in text and "while the note itself still leaves" in text
    # 0.6.2 (audit items 1 and 16, and round 2): what is not recognised leaves as written; digits touching a match can go with it
    _note(tmp_path, "Notes/Formats.md", [], NL.join(["# Formats", "", "order 123456789 placed", "met on 2026-11-15 here",
                                                      "call 555-201-4477-2026 now", "qty 2 4111 1111 1111 1111 paid",
                                                      "qty 2 4111 1111 1111 1111-2026 paid", "dial 555-201-4477 2026 times"]))
    excerpt = _sent(tmp_path, denylist=[name])["Notes/Formats.md"]["excerpt"]
    assert "order 123456789 placed" in excerpt and "met on 2026-11-15 here" in excerpt  # recognised by no rule
    assert "call [PHONE] now" in excerpt and "qty 2 [CARD] paid" in excerpt and "2026 now" not in excerpt
    assert "qty [CARD] paid" in excerpt and "dial [PHONE] 2026 times" in excerpt  # widening runs both ways; spaces alone take nothing
    # the sentence is the same in the three docs, and every example it quotes is checked against redact()
    # in tests/test_redact_numbers_together.py::test_every_example_the_widen_sentence_quotes_is_what_redact_does
    assert WIDEN_SENTENCE in text
    for phrase in ("redaction can also take nearby digits", "when a digit touches the match, directly or across a hyphen",
                   "joined to it by a single hyphen or space, on either side, can be redacted with it",
                   "Two joiners in a row, such as two spaces or a space and a hyphen, end it",
                   "A neighbouring phone, card or SSN usually keeps its own label",
                   "when the two overlap, they can share one label, and every digit of both is still redacted",
                   "A match with only spaces around it takes nothing",
                   "a number in a format no rule recognises, such as a nine-digit order number or a date standing alone, leaves as written"):
        assert phrase in WIDEN_SENTENCE, phrase


NEVER_LEAVES_TESTS = {
    "Frontmatter values": test_frontmatter_values_other_than_title_aliases_and_creation_dates_never_leave,
    "The absolute path.": test_the_absolute_path_never_leaves,
    "Notes under a hidden folder, and hidden files": test_hidden_notes_inside_the_scan_are_never_opened_and_the_named_cases_are_exact,
    "Notes under `_janitor/`": test_janitor_working_folder_notes_are_never_opened_even_when_named,
    "Notes under sensitive folders": test_a_sensitive_notes_title_is_never_a_sibling_and_it_gets_none,
    "A note with a credential hit": test_a_credential_hit_in_any_own_field_is_not_sent_and_says_sent_null,
    "A note local triage decides.": test_local_triage_decides_three_rules_and_sent_is_only_a_show_payload_key,
    "A locked note": test_a_locked_note_is_skipped_with_no_request_whatever_the_flags,
    "A note that is not valid UTF-8, or that cannot be read": test_an_undecodable_or_unreadable_note_is_never_sent_nor_a_sibling,
    "The body past the excerpt cap.": test_the_body_past_the_excerpt_cap_never_leaves_and_a_hit_across_the_cap_is_redacted_first,
    "The original text of a redaction hit": test_the_original_text_of_a_redaction_hit_never_leaves_while_the_note_does,
}


def test_every_never_leaves_bullet_has_a_test():
    """Adding a bullet without a test, or rewording one's lead, fails here. Bodies are pinned by
    phrase in each bullet's own test (`_bullet`), at the claims that test proves."""
    assert _never_leaves_bullets() == list(NEVER_LEAVES_TESTS)
    section = _section("What never leaves")
    assert "What never leaves the machine includes the following; the list is not exhaustive." in section
    triage = (ROOT / "janitor" / "triage.py").read_text(encoding="utf-8")
    assert re.findall(r'LocalDecision\(vote, .*?, "(\w+)"\)', triage) == ["secret", "empty", "duplicate"]
    assert "a credential hit (above), an empty body or one with only headings, and an exact duplicate" in section


def test_the_sibling_cell_names_who_is_never_listed_and_a_named_hidden_folder(tmp_path: Path):
    """0.6.1, outside audit, line 16: "under a hidden folder" was false for a hidden folder you name."""
    cell = next(line for line in _section("The state: exactly seven fields").splitlines() if line.startswith("| `other_note_titles` |"))
    assert "a note under a hidden folder, or a hidden file, inside the folder you scan" in cell
    assert "A hidden folder you name as the target is scanned as named, so its notes are listed as each other's siblings." in cell
    _write(tmp_path, "notes/a.md", "# Alpha" + NL + NL + "body a" + NL)
    _write(tmp_path, "notes/.b.md", "# Hidden beta" + NL + NL + "body b" + NL)
    _write(tmp_path, "notes/.h/c.md", "# Hidden gamma" + NL + NL + "body c" + NL)
    _write(tmp_path, "notes/d.md", "# Delta" + NL + NL + "body d" + NL)
    assert _sent(tmp_path)["notes/a.md"]["other_note_titles"] == ["Delta"]
