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
