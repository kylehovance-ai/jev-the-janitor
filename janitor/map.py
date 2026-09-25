"""The brain map's data layer: everything a map of the vault needs to know, and no drawing.

"The brain map is the product; the terminal table is the debug view." Two reviewers who
never saw each other's work said so. This module is the half that can be built before a
real corpus exists: the numbers, per folder and for the whole graph, from one run's rows
and the index that run was built on. The presentation waits for a corpus to be shaped
around, because a report designed against twelve fixture notes is a report for twelve
fixture notes.

The map holds paths, labels, counts and bands. No titles, no excerpts, no link-target
text beyond the path: it can be handed to a renderer, or to another person, without a
second privacy review. It is written only where the operator says (--map FILE).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from janitor.index import VaultIndex
from janitor.journal import STATE_VERSION
from janitor.plan import rel_folder

MAP_SCHEMA = 1
HUBS = 20


def _folder_chain(folder: str) -> list[str]:
    """'a/b/c/' -> ['./', 'a/', 'a/b/', 'a/b/c/'] so every ancestor rolls up."""
    if folder == "./":
        return ["./"]
    parts = folder.rstrip("/").split("/")
    return ["./"] + ["/".join(parts[: i + 1]) + "/" for i in range(len(parts))]


def build_map(index: VaultIndex, rows: list[dict[str, Any]], *, taxonomy: str = "", vault_name: str = "") -> dict[str, Any]:
    by_path = {r["path"]: r for r in rows if r.get("path")}
    notes: list[dict[str, Any]] = []
    folders: dict[str, dict[str, Any]] = {}

    def folder_entry(folder: str) -> dict[str, Any]:
        if folder not in folders:
            folders[folder] = {
                "folder": folder, "notes": 0, "judged": 0, "buckets": Counter(), "judge": Counter(), "review": 0,
                "quarantined": 0, "locked": 0, "skipped": Counter(), "findings": Counter(), "orphans": 0, "mocs": 0,
                "words": 0, "age_bands": Counter(), "age_from_mtime": 0, "in_links": 0, "out_links": 0, "unresolved_links": 0,
            }
        return folders[folder]

    totals: dict[str, Any] = {
        "notes": 0, "judged": 0, "local": 0, "jev": 0, "cached": 0, "review": 0, "quarantined": 0, "locked": 0,
        "skipped": Counter(), "findings": Counter(), "errors": 0, "age_from_mtime": 0, "dated": 0, "stamp_dated": 0,
    }
    buckets: Counter = Counter()
    duplicates: dict[str, list[str]] = defaultdict(list)

    for entry in index.plan:
        rel = entry.rel
        ix = index.notes[rel]
        row = by_path.get(rel, {})
        facts = index.facts(rel) if ix.note is not None else {}
        kind = row.get("kind")
        note: dict[str, Any] = {
            "path": rel,
            "folder": rel_folder(rel),
            "status": entry.status,
            "kind": kind,
            "bucket": row.get("bucket"),
            "suggested_bucket": row.get("suggested_bucket"),
            "confidence": row.get("confidence"),
            "judge": row.get("judge"),
            "action": row.get("action"),
            "review": bool(row.get("suggested_bucket")),
            "locked": row.get("skipped") == "locked",
            "cached": bool(row.get("cached")),
            "findings": list(row.get("findings") or []),
            "exact_duplicate_of": row.get("exact_duplicate_of"),
            "age_source": row.get("age_source"),
            "words": facts.get("words"),
            "headings": facts.get("headings"),
            "age_band": facts.get("age_days"),
            "in_links": facts.get("in_links"),
            "out_links": facts.get("out_links"),
            "embeds": facts.get("embeds"),
            "unresolved_links": facts.get("unresolved_links"),
            "is_moc": facts.get("is_moc"),
            "is_orphan": facts.get("is_orphan"),
            "size": ix.size,
        }
        notes.append(note)
        totals["notes"] += 1
        for folder in _folder_chain(note["folder"]):
            f = folder_entry(folder)
            f["notes"] += 1
            if entry.status != "scan":
                f["skipped"][entry.rule] += 1
            if kind == "vote":
                f["judged"] += 1
                f["buckets"][note["bucket"]] += 1
                f["judge"][note["judge"] or "jev"] += 1
                f["review"] += int(note["review"])
                f["quarantined"] += int(note["action"] == "quarantine")
                if note["age_source"] == "mtime":
                    f["age_from_mtime"] += 1
            if note["locked"]:
                f["locked"] += 1
            for finding in note["findings"]:
                f["findings"][finding] += 1
            if facts:
                f["orphans"] += int(bool(facts.get("is_orphan")))
                f["mocs"] += int(bool(facts.get("is_moc")))
                f["words"] += ix.words
                f["age_bands"][str(facts.get("age_days"))] += 1
                f["in_links"] += facts.get("in_links") or 0
                f["out_links"] += facts.get("out_links") or 0
                f["unresolved_links"] += facts.get("unresolved_links") or 0
        if entry.status != "scan":
            totals["skipped"][entry.rule] += 1
        if kind == "vote":
            totals["judged"] += 1
            totals[note["judge"] or "jev"] += 1
            totals["cached"] += int(note["cached"])
            totals["review"] += int(note["review"])
            totals["quarantined"] += int(note["action"] == "quarantine")
            buckets[note["bucket"]] += 1
            if note["age_source"] == "mtime":
                totals["age_from_mtime"] += 1
            elif note["age_source"] == "frontmatter":
                totals["dated"] += 1
            elif note["age_source"] == "stamp":
                totals["stamp_dated"] += 1  # the date the janitor's stamp recorded (0.5.2): dated, and it does not reset
        if kind == "error":
            totals["errors"] += 1
        if note["locked"]:
            totals["locked"] += 1
        for finding in note["findings"]:
            totals["findings"][finding] += 1
        if note["exact_duplicate_of"]:
            duplicates[note["exact_duplicate_of"]].append(rel)

    scanned = [index.notes[e.rel] for e in index.plan if index.notes[e.rel].note is not None]
    edges = sum(len(ix.links_out) for ix in scanned)
    in_degree = Counter({ix.rel: ix.in_links for ix in scanned})
    out_hist: Counter = Counter(min(len(ix.links_out) + ix.unresolved, 20) for ix in scanned)
    in_hist: Counter = Counter(min(ix.in_links, 20) for ix in scanned)
    graph = {
        "nodes": len(scanned),
        "edges": edges,
        "unresolved_links": sum(ix.unresolved for ix in scanned),
        "orphans": sum(1 for n in notes if n["is_orphan"]),
        "mocs": sum(1 for n in notes if n["is_moc"]),
        "hubs": [{"path": p, "in_links": n} for p, n in in_degree.most_common(HUBS) if n],
        "in_degree_histogram": {str(k): v for k, v in sorted(in_hist.items())},
        "out_degree_histogram": {str(k): v for k, v in sorted(out_hist.items())},
    }

    def plain(f: dict[str, Any]) -> dict[str, Any]:
        return {k: (dict(v) if isinstance(v, Counter) else v) for k, v in f.items()}

    return {
        "schema": MAP_SCHEMA,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "vault": vault_name,
        "taxonomy": taxonomy,
        "state_version": STATE_VERSION,
        "totals": plain(totals),
        "buckets": dict(buckets),
        "folders": [plain(folders[k]) for k in sorted(folders)],
        "graph": graph,
        "duplicates": [{"canonical": c, "copies": sorted(v)} for c, v in sorted(duplicates.items())],
        "notes": notes,
    }
