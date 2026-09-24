"""Outside review finding 10d: sibling titles are the closest by token overlap, each cut to 80 characters, not the alphabetical first 80."""

from pathlib import Path

from janitor.client import FixtureClient
from janitor.frontmatter import MAX_TITLES
from janitor.index import MAX_TITLE_CHARS, build_index
from janitor.scan import scan_vault


class Recording(FixtureClient):
    def __init__(self):
        self.states = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


def test_closest_titles_come_first_and_ties_keep_plan_order(tmp_path: Path):
    (tmp_path / "zoning-appeal.md").write_text("# Zoning appeal draft\n\nbody z\n", encoding="utf-8")
    for i in range(100):
        (tmp_path / f"a{i:03d}.md").write_text(f"# Alpha note {i}\n\nbody {i}\n", encoding="utf-8")
    (tmp_path / "zoning-appeal-final.md").write_text("# Zoning appeal final\n\nbody final\n", encoding="utf-8")
    (tmp_path / "m-zoning.md").write_text("# Notes on zoning\n\nbody m\n", encoding="utf-8")
    index = build_index(tmp_path)
    titles = index.sibling_titles("zoning-appeal.md", MAX_TITLES, own_title="Zoning appeal draft")
    assert len(titles) == MAX_TITLES
    assert titles[0] == "Zoning appeal final" and titles[1] == "Notes on zoning"  # 0.3.0 sent "Alpha note 0".."Alpha note 79"
    assert titles[2:] == [f"Alpha note {i}" for i in range(MAX_TITLES - 2)]  # ties: plan order
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True)
    sent = next(s for s in rec.states if s["path"] == "zoning-appeal.md")["other_note_titles"]
    assert sent[0] == "Zoning appeal final"


def test_each_title_is_cut_to_eighty_characters_after_redaction(tmp_path: Path):
    """The index returns the whole title; build_state redacts it and only then cuts it to 80.
    Through 0.4.6 the index cut first, so a denylisted name straddling character 80 left as
    `... Jonathan ` with no token, the class the body fix in 0.1.2 closed."""
    long_title = "A " + "very " * 60 + "long title"
    (tmp_path / "a.md").write_text(f"# {long_title}\n\nbody a\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("# B\n\nbody b\n", encoding="utf-8")
    index = build_index(tmp_path)
    [t] = index.sibling_titles("b.md", MAX_TITLES, own_title="B")
    assert t == long_title  # whole: the cut is build_state's, after redaction
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True)
    [sent] = next(s for s in rec.states if s["path"] == "b.md")["other_note_titles"]
    assert len(sent) == MAX_TITLE_CHARS == 80 and sent == long_title[:80]
    # The straddling case: 70 characters, then a denylisted name across the cut.
    (tmp_path / "a.md").write_text("# " + "A" * 70 + " Jonathan Smith\n\nbody a\n", encoding="utf-8")
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True, denylist=["Jonathan Smith"])
    [sent] = next(s for s in rec.states if s["path"] == "b.md")["other_note_titles"]
    assert sent == "A" * 70 + " [NAME]" and "Jonathan" not in sent


def test_no_own_title_falls_back_to_plan_order(tmp_path: Path):
    for name in ("c.md", "a.md", "b.md"):
        (tmp_path / name).write_text(f"# {name}\n\nbody {name}\n", encoding="utf-8")
    index = build_index(tmp_path)
    assert index.sibling_titles("b.md", 10) == ["a.md", "c.md"]
