"""The brain map's data layer: per-folder rollups, graph facts, duplicates, one record per note.

Paths, labels, counts and bands only. No titles, no excerpts, no text of any kind, so the
file can be handed to a renderer or a person without a second privacy review.
"""

import json
from pathlib import Path

from janitor import cli
from janitor.index import build_index
from janitor.map import MAP_SCHEMA, build_map
from janitor.scan import scan_vault

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"
SECRET_TITLE = "Zebra Quilt Diagnosis"


def _vault(tmp_path: Path) -> Path:
    vault = tmp_path / "vault"
    files = {
        "hub.md": "---\ncreated: 2023-01-01\n---\n# Hub of Everything\n\n" + " ".join(f"[[spoke{i}]]" for i in range(9)) + "\n",
        **{f"projects/alpha/spoke{i}.md": f"---\ncreated: 2023-06-01\n---\n# Spoke {i}\n\nback to [[hub]] spoke {i}\n" for i in range(9)},
        "projects/beta/lonely.md": "---\ncreated: 2022-01-01\n---\n# Lonely\n\nnobody links here\n",
        "projects/beta/copy.md": "# Copy\n\nnobody links here\n",
        "projects/beta/leak.md": f"# Leak\n\n{KEY}\n",
        "projects/beta/broken.md": "---\nstatus: a: b\n---\n# Broken\n\nbody of broken\n",
        "notes/locked.md": "---\njanitor:\n  locked: true\n---\n# Locked\n\nlocked body\n",
        f"family/{SECRET_TITLE}.md": "# Zebra\n\nprivate\n",
        ".obsidian/workspace.md": "# ws\n",
    }
    for rel, text in files.items():
        p = vault / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return vault


def test_map_rolls_up_folders_graph_duplicates_and_findings(tmp_path: Path):
    vault = _vault(tmp_path)
    index = build_index(vault)
    rows = scan_vault(vault, offline=True)
    m = build_map(index, rows, taxonomy="abc", vault_name="vault")
    assert m["schema"] == MAP_SCHEMA and m["vault"] == "vault" and m["taxonomy"] == "abc"
    t = m["totals"]
    assert t["notes"] == 17 and t["judged"] == 14 and t["locked"] == 1
    assert t["skipped"] == {"sensitive path part 'family'": 1, "hidden folder or file '.obsidian' (starts with '.')": 1}
    assert t["local"] == 2 and t["jev"] == 12  # copy (duplicate) and leak (secret) decided locally
    assert t["quarantined"] == 1 and t["findings"] == {"unreadable_frontmatter": 1}
    assert t["age_from_mtime"] == 3 and t["dated"] == 11  # copy, leak, broken have no created:
    by_folder = {f["folder"]: f for f in m["folders"]}
    assert set(by_folder) == {"./", "projects/", "projects/alpha/", "projects/beta/", "notes/", "family/", ".obsidian/"}
    assert by_folder["projects/"]["notes"] == 13 and by_folder["projects/alpha/"]["notes"] == 9
    assert by_folder["projects/alpha/"]["in_links"] == 9 and by_folder["projects/alpha/"]["out_links"] == 9
    assert by_folder["projects/beta/"]["quarantined"] == 1 and by_folder["projects/beta/"]["findings"] == {"unreadable_frontmatter": 1}
    assert by_folder["projects/beta/"]["orphans"] >= 1 and by_folder["./"]["mocs"] == 1
    assert by_folder["./"]["notes"] == 17  # the root rolls everything up
    g = m["graph"]
    assert g["nodes"] == 15 and g["edges"] == 18 and g["mocs"] == 1 and g["unresolved_links"] == 0  # the locked note is indexed too
    assert g["hubs"][0] == {"path": "hub.md", "in_links": 9}
    assert m["duplicates"] == [{"canonical": "projects/beta/copy.md", "copies": ["projects/beta/lonely.md"]}]  # first in plan order is canonical
    notes = {n["path"]: n for n in m["notes"]}
    assert notes["hub.md"]["is_moc"] is True and notes["hub.md"]["bucket"] and notes["hub.md"]["judge"] == "jev"
    assert notes["projects/beta/leak.md"]["action"] == "quarantine" and notes["projects/beta/leak.md"]["judge"] == "local"
    assert notes["notes/locked.md"]["locked"] is True and notes["notes/locked.md"]["kind"] == "skip"
    assert notes[f"family/{SECRET_TITLE}.md"]["status"] == "skip_sensitive" and notes[f"family/{SECRET_TITLE}.md"]["words"] is None


def test_map_holds_no_titles_or_text(tmp_path: Path):
    vault = _vault(tmp_path)
    m = build_map(build_index(vault), scan_vault(vault, offline=True))
    blob = json.dumps(m)
    assert "Hub of Everything" not in blob and "nobody links here" not in blob and KEY not in blob
    assert f"family/{SECRET_TITLE}.md" in blob  # a path is structure, and the map is local; the title itself is not carried


def test_cli_writes_the_map_only_where_asked(tmp_path: Path, capsys):
    vault = _vault(tmp_path)
    before = sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*"))
    assert cli.main([str(vault), "--offline"]) == 0
    assert sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*")) == before
    out = tmp_path / "out" / "map.json"
    assert cli.main([str(vault), "--offline", "--map", str(out)]) == 0
    assert f"map: {out}" in capsys.readouterr().err
    m = json.loads(out.read_text(encoding="utf-8"))
    assert m["totals"]["judged"] == 14 and m["graph"]["hubs"][0]["path"] == "hub.md"
    assert m["taxonomy"] and m["state_version"] >= 8
