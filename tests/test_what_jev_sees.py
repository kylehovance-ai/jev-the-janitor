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
# recording FixtureClient) or the --show-payload `sent` objects. Older gates that prove part of a
# bullet are named beside it; these tests pin the page's own wording to the same behaviour.

from janitor import cli  # noqa: E402
from janitor import index as index_module  # noqa: E402
from janitor.client import FixtureClient  # noqa: E402
from janitor.plan import plan_vault  # noqa: E402
from janitor.scan import scan_vault  # noqa: E402

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"  # invented; the same shape tests/test_survey.py uses


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


def _sent(vault: Path, **kwargs) -> dict[str, dict]:
    """The states the client received, by path."""
    rec = Recording()
    scan_vault(vault, client=rec, offline=True, **kwargs)
    return {s["path"]: s for s in rec.states}


def _rows(vault: Path, capsys, *extra: str) -> dict[str, dict]:
    assert cli.main([str(vault), "--offline", "--json", "--journal", "off", "--quiet", *extra]) == 0
    return {r["path"]: r for r in json.loads(capsys.readouterr().out)}


def _never_leaves_bullets() -> list[str]:
    return re.findall(r"^- \*\*(.+?)\*\*", _section("What never leaves"), re.M)


def test_frontmatter_values_other_than_title_aliases_and_creation_dates_never_leave(tmp_path: Path):
    _write(tmp_path, "n.md", NL.join(["---", "title: Garden plan", "aliases: [Beds]", "created: 2024-03-03",
                                      "modified: 2019-07-07", "owner: quokka-marmalade", "tags: [zebra-quartz]",
                                      "rating: 4711", "---", "# Heading", "", "body text", ""]))
    state = _sent(tmp_path)["n.md"]
    wire = json.dumps(state)
    for value in ("quokka-marmalade", "zebra-quartz", "4711", "2019-07-07", "2024-03-03", "2024"):
        assert value not in wire, value  # values stay local; `created` arrives only as a band
    assert state["title"] == "Garden plan" and state["aliases"] == ["Beds"]  # the frontmatter title wins over the H1
    assert state["frontmatter_keys"] == ["aliases", "created", "modified", "owner", "rating", "tags", "title"]
    assert state["graph"]["age_days"] in index_module.AGE_BANDS  # a band of days, not the date
    assert "a non-empty `title` string becomes the state's `title`" in _section("What never leaves")


def test_the_absolute_path_never_leaves(tmp_path: Path):
    """tests/test_state_path.py is the gate for the relative posix path; this pins the page's bullet."""
    _write(tmp_path, "Areas/n.md", "# N" + NL + NL + "body" + NL)
    state = _sent(tmp_path)["Areas/n.md"]
    wire = json.dumps(state)
    assert state["path"] == "Areas/n.md"
    assert str(tmp_path) not in wire and tmp_path.as_posix() not in wire and tmp_path.name not in wire


def test_hidden_notes_inside_the_scan_are_never_opened_and_a_named_hidden_folder_is_scanned(tmp_path: Path, monkeypatch):
    """tests/test_preflight.py::test_hidden_folders_are_skipped_by_the_dot_rule_not_the_list covers the plan."""
    _write(tmp_path, ".hidden/h.md", "# Hidden" + NL + NL + "hidden body" + NL)
    _write(tmp_path, "notes/.h2.md", "# Hidden file" + NL + NL + "hidden body" + NL)
    _write(tmp_path, "notes/v.md", "# Visible" + NL + NL + "body" + NL)
    opened: list[str] = []
    real = index_module.load_note

    def load(path: Path):
        opened.append(path.name)
        return real(path)

    monkeypatch.setattr(index_module, "load_note", load)
    for include_sensitive in (False, True):
        _, plan = plan_vault(tmp_path, include_sensitive=include_sensitive)
        status = {e.rel: e.status for e in plan}
        assert status[".hidden/h.md"] == status["notes/.h2.md"] == "skip_hidden" and status["notes/v.md"] == "scan"
        sent = _sent(tmp_path, include_sensitive=include_sensitive)
        assert set(sent) == {"notes/v.md"} and "Hidden" not in json.dumps(sent)
    assert "h.md" not in opened and ".h2.md" not in opened  # stat only, never read
    assert set(_sent(tmp_path / ".hidden")) == {"h.md"}  # named as the target, it is scanned as named
    _, plan = plan_vault(tmp_path / ".hidden" / "h.md")
    assert [e.status for e in plan] == ["skip_hidden"]  # a single note named under a hidden folder is skipped


def test_janitor_working_folder_notes_are_never_opened_even_when_named(tmp_path: Path):
    _write(tmp_path, "_janitor/quarantine/q.md", "# Quarantined" + NL + NL + "body" + NL)
    _write(tmp_path, "v.md", "# Visible" + NL + NL + "body" + NL)
    for include_sensitive in (False, True):
        _, plan = plan_vault(tmp_path, include_sensitive=include_sensitive)
        assert {e.rel: e.status for e in plan}["_janitor/quarantine/q.md"] == "skip_janitor"
        sent = _sent(tmp_path, include_sensitive=include_sensitive)
        assert set(sent) == {"v.md"} and "Quarantined" not in json.dumps(sent)
    for named in (tmp_path / "_janitor", tmp_path / "_janitor" / "quarantine"):
        _, plan = plan_vault(named)
        assert [e.status for e in plan] == ["skip_janitor"]
        assert _sent(named) == {}


def test_a_sensitive_notes_title_is_never_a_sibling_and_it_gets_none(tmp_path: Path):
    """tests/test_titles_privacy.py is the gate; this pins the bullet, both halves of the --include-sensitive case."""
    _write(tmp_path, "family/Secret plan.md", "# Secret plan" + NL + NL + "body one" + NL)
    _write(tmp_path, "family/Other plan.md", "# Other plan" + NL + NL + "body two" + NL)
    _write(tmp_path, "public/plan.md", "# Public plan" + NL + NL + "body three" + NL)
    _write(tmp_path, "public/sib.md", "# Sibling" + NL + NL + "body four" + NL)
    sent = _sent(tmp_path)
    assert set(sent) == {"public/plan.md", "public/sib.md"} and "Secret plan" not in json.dumps(sent["public/sib.md"])
    sent = _sent(tmp_path, include_sensitive=True)
    assert {"family/Secret plan.md", "family/Other plan.md"} <= set(sent)
    assert sent["family/Secret plan.md"]["other_note_titles"] == [] and sent["family/Other plan.md"]["other_note_titles"] == []
    assert all("Secret plan" not in t and "Other plan" not in t for s in sent.values() for t in s["other_note_titles"])


def test_a_credential_hit_is_not_sent_and_says_sent_null_and_no_local_triage_sends_it_redacted(tmp_path: Path, capsys):
    _write(tmp_path, "leak.md", "# Leak" + NL + NL + KEY + NL)
    _write(tmp_path, "ok.md", "# Ok" + NL + NL + "body" + NL)
    assert set(_sent(tmp_path)) == {"ok.md"}
    rows = _rows(tmp_path, capsys, "--show-payload")
    assert rows["leak.md"]["judge"] == "local" and rows["leak.md"]["sent"] is None
    sent = _sent(tmp_path, local_triage=False)
    assert KEY not in json.dumps(sent) and "[KEY]" in sent["leak.md"]["excerpt"]


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


def test_a_locked_note_is_skipped_with_no_request_whatever_the_flags(tmp_path: Path):
    """tests/test_triage.py::test_locked_note_is_a_skip_row_with_no_request_and_no_rewrite covers the default."""
    _write(tmp_path, "locked.md", NL.join(["---", "janitor:", "  locked: true", "---", "# Locked", "", "locked body", ""]))
    _write(tmp_path, "ok.md", "# Ok" + NL + NL + "open body" + NL)  # a different body, so neither is a duplicate
    for kwargs in ({}, {"local_triage": False}, {"include_sensitive": True}):
        rec = Recording()
        rows = {r["path"]: r for r in scan_vault(tmp_path, client=rec, offline=True, **kwargs)}
        assert [s["path"] for s in rec.states] == ["ok.md"] and rows["locked.md"]["action"] == "skip_locked", kwargs


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


def test_the_body_past_the_excerpt_cap_never_leaves(tmp_path: Path):
    """tests/test_excerpt_chars.py covers the caps; this pins that the text past the cut is absent."""
    head, tail = "kept " * 50, "porcupine-tail " * 20
    _write(tmp_path, "long.md", "# Long" + NL + NL + head + tail + NL)
    state = _sent(tmp_path, excerpt_chars=200)["long.md"]
    assert len(state["excerpt"]) == 200 and "porcupine" not in json.dumps(state)
    assert state["excerpt"].startswith("# Long" + NL + NL + "kept kept")


def test_the_original_text_of_a_redaction_hit_never_leaves_while_the_note_does(tmp_path: Path):
    email, name, phone = "ada.example@example.org", "Jane Placeholder", "555-201-4477"
    _write(tmp_path, f"Notes/{name}.md", NL.join(["---", f"aliases: [{email}]", "---", f"# Call {name}", "",
                                                   f"write to {email} or call {phone}", ""]))
    _write(tmp_path, "Notes/Sibling.md", NL.join(["---", f"title: Sibling {email}", "---", "body", ""]))
    sent = _sent(tmp_path, denylist=[name])
    wire = json.dumps(sent)
    assert email not in wire and name not in wire and phone not in wire
    state = sent["Notes/[NAME].md"]  # the note itself leaves, with labels in place, path included
    assert state["title"] == "Call [NAME]" and state["aliases"] == ["[EMAIL]"] and "[EMAIL]" in state["excerpt"]
    assert "[PHONE]" in state["excerpt"]
    assert state["other_note_titles"] == ["Sibling [EMAIL]"]  # a non-credential hit is listed, redacted


NEVER_LEAVES_TESTS = {
    "Frontmatter values": test_frontmatter_values_other_than_title_aliases_and_creation_dates_never_leave,
    "The absolute path.": test_the_absolute_path_never_leaves,
    "Notes under a hidden folder, and hidden files": test_hidden_notes_inside_the_scan_are_never_opened_and_a_named_hidden_folder_is_scanned,
    "Notes under `_janitor/`": test_janitor_working_folder_notes_are_never_opened_even_when_named,
    "Notes under sensitive folders": test_a_sensitive_notes_title_is_never_a_sibling_and_it_gets_none,
    "A note with a credential hit": test_a_credential_hit_is_not_sent_and_says_sent_null_and_no_local_triage_sends_it_redacted,
    "A note local triage decides.": test_local_triage_decides_three_rules_and_sent_is_only_a_show_payload_key,
    "A locked note": test_a_locked_note_is_skipped_with_no_request_whatever_the_flags,
    "A note that is not valid UTF-8, or that cannot be read": test_an_undecodable_or_unreadable_note_is_never_sent_nor_a_sibling,
    "The body past the excerpt cap.": test_the_body_past_the_excerpt_cap_never_leaves,
    "The original text of a redaction hit": test_the_original_text_of_a_redaction_hit_never_leaves_while_the_note_does,
}


def test_every_never_leaves_bullet_has_a_test():
    """Adding a bullet without a test, or rewording one's lead, fails here."""
    assert _never_leaves_bullets() == list(NEVER_LEAVES_TESTS)
    section = _section("What never leaves")
    assert "What never leaves the machine includes the following; the list is not exhaustive." in section
    triage = (ROOT / "janitor" / "triage.py").read_text(encoding="utf-8")
    assert re.findall(r'LocalDecision\(vote, .*?, "(\w+)"\)', triage) == ["secret", "empty", "duplicate"]
    assert "a credential hit (above), an empty body or one with only headings, and an exact duplicate" in section
