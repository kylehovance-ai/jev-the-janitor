"""Graph facts and aliases on the outgoing state: numbers and redacted second titles, never a target's name.

This widened what leaves the machine (STATE_VERSION 6), so the claims here mirror the
README's contract lines for it.
"""

import json
from pathlib import Path

import pytest

from janitor.client import FixtureClient
from janitor.journal import STATE_VERSION
from janitor.scan import scan_vault

SECRET_TARGET = "Zebra Quilt Diagnosis"


class Recording(FixtureClient):
    def __init__(self):
        self.states = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    files = {
        "notes/hub.md": "---\naliases: [Hub of Hubs, 'Ada Lovelace hub', 'ops@example.com']\n---\n# Hub\n\n"
                        + " ".join(f"[[spoke{i}]]" for i in range(9)) + f" [[family/{SECRET_TARGET}]] [[.obsidian/workspace]]\n",
        **{f"notes/spoke{i}.md": f"# Spoke {i}\n\nback to [[hub]] number {i}\n" for i in range(9)},
        f"family/{SECRET_TARGET}.md": "# Zebra\n\nprivate\n",
        ".obsidian/workspace.md": "# ws\n",
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


def test_state_carries_graph_numbers_and_redacted_aliases(vault: Path):
    rec = Recording()
    scan_vault(vault, client=rec, offline=True, denylist=["Ada Lovelace"])
    hub = next(s for s in rec.states if s["path"] == "notes/hub.md")
    g = hub["graph"]
    assert g["out_links"] == 11 and g["in_links"] == 9 and g["embeds"] == 0
    assert g["unresolved_links"] == 0  # the sensitive and hidden targets exist; they are counted, not named
    assert g["is_moc"] is True and g["is_orphan"] is False
    assert isinstance(g["words"], int) and isinstance(g["headings"], int) and isinstance(g["age_days"], int)
    assert hub["aliases"] == ["Hub of Hubs", "[NAME] hub", "[EMAIL]"]
    spoke = next(s for s in rec.states if s["path"] == "notes/spoke0.md")
    assert spoke["graph"]["out_links"] == 1 and spoke["graph"]["in_links"] == 1 and spoke["aliases"] == []


def test_graph_facts_add_no_names(vault: Path):
    """A [[wikilink]] in a body is body text and leaves inside the excerpt like any other text;
    that was always so. The graph facts add nothing to it: outside the excerpt, no target name."""
    rec = Recording()
    scan_vault(vault, client=rec, offline=True)
    outside_excerpt = json.dumps([{k: v for k, v in s.items() if k != "excerpt"} for s in rec.states])
    assert SECRET_TARGET not in outside_excerpt and "workspace" not in outside_excerpt  # ("spoke" is in paths and sibling titles, legitimately)
    assert all(not isinstance(v, str) for s in rec.states for v in s["graph"].values())
    hub = next(s for s in rec.states if s["path"] == "notes/hub.md")
    assert SECRET_TARGET in hub["excerpt"]  # stated, not hidden: the operator wrote that link in the body


def test_words_and_age_are_banded_so_keys_survive_small_edits_and_midnight():
    from janitor.index import banded_age, banded_words

    assert [banded_words(n) for n in (0, 7, 99, 100, 1506, 1594, 23456)] == [0, 7, 99, 100, 1500, 1500, 23000]
    assert [banded_age(d) for d in (None, 0, 1, 6, 7, 29, 30, 364, 365, 5000)] == [None, 0, 1, 1, 7, 7, 30, 90, 365, 1000]


def test_alias_hits_count_as_the_notes_own(vault: Path):
    rows = {r["path"]: r for r in scan_vault(vault, offline=True, denylist=["Ada Lovelace"])}
    assert {"EMAIL", "NAME"} <= set(rows["notes/hub.md"]["redacted_own"])


def test_single_file_target_reports_unknown_in_degree(vault: Path):
    rec = Recording()
    scan_vault(vault / "notes" / "spoke0.md", client=rec, offline=True)
    g = rec.states[0]["graph"]
    assert g["in_links"] is None and g["is_orphan"] is None and g["out_links"] == 1


def test_facts_are_in_the_cache_key(vault: Path):
    """A new inbound link changes the state, so the vote is re-asked; the index is what noticed."""
    k1 = {r["path"]: r["key"] for r in scan_vault(vault, offline=True) if r["kind"] == "vote"}
    (vault / "notes" / "spoke0.md").write_text("# Spoke 0\n\nback to [[hub]] number 0 and [[spoke1]]\n", encoding="utf-8")
    k2 = {r["path"]: r["key"] for r in scan_vault(vault, offline=True) if r["kind"] == "vote"}
    assert k1["notes/spoke1.md"] != k2["notes/spoke1.md"]  # in_links 1 -> 2
    assert k1["notes/spoke2.md"] == k2["notes/spoke2.md"]  # untouched


def test_every_vote_row_carries_the_graph_numbers_without_show_payload(vault: Path):
    """A grader needing is_orphan or is_moc must not depend on --show-payload."""
    rows = [r for r in scan_vault(vault, offline=True) if r["kind"] == "vote"]
    hub = next(r for r in rows if r["path"] == "notes/hub.md")
    assert hub["graph"]["is_moc"] is True and hub["graph"]["in_links"] == 9
    assert all("sent" not in r for r in rows)
    assert all(not isinstance(v, str) for r in rows for v in r["graph"].values())  # numbers and booleans only


def test_a_vault_that_barely_links_reports_orphans_as_unknown(tmp_path: Path, capsys):
    """The first live run: 31 real notes that reference each other by path, 30 with no link out,
    17 came back is_orphan: true. Correct arithmetic that said nothing. Now: unknown, and said."""
    from janitor import cli
    from janitor.index import build_index

    for i in range(30):
        (tmp_path / f"ledger-{i:02d}.md").write_text(f"---\ncreated: 2024-01-01\n---\n# Ledger {i}\n\nsee ledger-{(i + 1) % 30:02d}.md for the rest {i}\n", encoding="utf-8")
    (tmp_path / "linker.md").write_text("---\ncreated: 2024-01-01\n---\n# Linker\n\n[[ledger-00]]\n", encoding="utf-8")
    index = build_index(tmp_path)
    assert index.graph_sparse and 0 < index.linking_share < 0.05
    facts = index.facts("ledger-05.md")
    assert facts["in_links"] == 0 and facts["is_orphan"] is None  # not False, not True: unknown
    assert index.facts("ledger-00.md")["is_orphan"] is None
    assert cli.main([str(tmp_path), "--offline"]) == 0
    err = capsys.readouterr().err
    assert "graph: 97% of 31 scanned notes have no outgoing" in err and "is_orphan is reported as unknown" in err

    # a vault that links normally keeps the finding
    for i in range(30):
        (tmp_path / f"ledger-{i:02d}.md").write_text(f"---\ncreated: 2024-01-01\n---\n# Ledger {i}\n\nsee [[ledger-{(i + 1) % 30:02d}]] {i}\n", encoding="utf-8")
    index = build_index(tmp_path)
    assert not index.graph_sparse and index.facts("linker.md")["is_orphan"] is True
    assert cli.main([str(tmp_path), "--offline"]) == 0
    assert "graph:" not in capsys.readouterr().err


def test_state_version_is_at_least_six():
    assert STATE_VERSION >= 6  # 6 added the facts; 7 corrected age to creation age
