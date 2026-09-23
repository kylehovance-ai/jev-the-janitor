"""Survey first, full scan second: a stratified sample so a new brain can check the taxonomy.

Nobody lets an unknown tool make 20,000 calls over their private notes on first contact.
A survey draws 50 to 100 notes spread across the vault's folders, lengths and ages, runs
them through the same pre-flight and the same judge, and stops. The votes go to the
journal like any other run, so the full scan that follows serves them from cache and
sends only the rest.

The sample is deterministic for a vault (seeded by its id), so two people looking at the
same survey see the same notes, and a re-run after a taxonomy edit re-judges the same
sample, which is what makes the two comparable.
"""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from janitor.scan import Prepared

DEFAULT_SURVEY = 75
LENGTH_BANDS = ((100, "stub"), (500, "short"), (2000, "medium"))  # by banded word count; else "long"


def length_band(words: int | None) -> str:
    w = words or 0
    for limit, name in LENGTH_BANDS:
        if w < limit:
            return name
    return "long"


def top_folder(rel: str) -> str:
    return rel.split("/", 1)[0] + "/" if "/" in rel else "./"


def stratum_of(item: Prepared) -> tuple[str, str, str]:
    graph = (item.state or {}).get("graph") or {}
    age = graph.get("age_days")
    return top_folder(item.rel), length_band(graph.get("words")), f"age{age}" if age is not None else "age?"


@dataclass
class Survey:
    requested: int
    eligible: int  # notes the judge would see: not local, not locked, not cached, readable
    items: list = field(default_factory=list)  # the sampled Prepared items, plan order
    strata: Counter = field(default_factory=Counter)  # stratum -> sampled count
    population: Counter = field(default_factory=Counter)  # stratum -> eligible count

    def describe(self) -> str:
        return (f"SURVEY: {len(self.items):,} of {self.eligible:,} judge-eligible notes, drawn across {len(self.strata):,} strata "
                f"(top folder x length band x age band; {len(self.population):,} strata exist). The rest are not sent; "
                f"a full scan later serves these votes from the journal.")


def survey_sample(items: list[Prepared], n: int = DEFAULT_SURVEY, *, seed: str = "") -> Survey:
    """Round-robin over strata: every stratum gets one note before any gets a second.

    Within a stratum the order is a seeded shuffle. Notes code already decided (local
    triage, locked), notes already in the journal cache, and unreadable notes are not
    candidates: the survey is spent on what the judge would actually see.
    """
    eligible = [it for it in items if it.error is None and it.undecodable is None and not it.locked
                and it.local is None and it.cached_row is None and it.state is not None]
    survey = Survey(requested=n, eligible=len(eligible))
    buckets: dict[tuple[str, str, str], list[Prepared]] = {}
    for it in eligible:
        buckets.setdefault(stratum_of(it), []).append(it)
    for key, group in buckets.items():
        survey.population[key] = len(group)
        random.Random(f"{seed}|{'|'.join(key)}").shuffle(group)
    chosen: set[str] = set()
    keys = sorted(buckets)
    while len(chosen) < min(n, len(eligible)):
        progressed = False
        for key in keys:
            if len(chosen) >= n:
                break
            group = buckets[key]
            if group:
                it = group.pop()
                chosen.add(it.rel)
                survey.strata[key] += 1
                progressed = True
        if not progressed:
            break
    survey.items = [it for it in items if it.rel in chosen]  # plan order
    return survey


def survey_summary(survey: Survey, rows: list[dict[str, Any]]) -> str:
    """After the run: how the sample voted, per stratum, so a taxonomy edit has something to compare against."""
    by_path = {r.get("path"): r for r in rows if r.get("kind") == "vote"}
    lines = [f"survey: {len(survey.items):,} notes judged across {len(survey.strata):,} strata"]
    buckets = Counter(r.get("bucket") for r in by_path.values())
    lines.append("  buckets: " + ", ".join(f"{b} {n:,}" for b, n in buckets.most_common()))
    review = sum(1 for r in by_path.values() if r.get("suggested_bucket"))
    quarantine = sum(1 for r in by_path.values() if r.get("action") == "quarantine")
    lines.append(f"  routed to a person: {review:,} for review, {quarantine:,} quarantined")
    lines.append("  per stratum (folder, length, age): sampled / eligible, buckets")
    for key in sorted(survey.strata):
        sampled = [by_path[it.rel] for it in survey.items if stratum_of(it) == key and it.rel in by_path]
        dist = Counter(r.get("bucket") for r in sampled)
        lines.append(f"    {key[0]:<28} {key[1]:<7} {key[2]:<8} {survey.strata[key]:>3} / {survey.population[key]:<5} "
                     + ", ".join(f"{b} {n}" for b, n in dist.most_common()))
    lines.append("  edit the taxonomy, re-run the survey, and compare; then scan in full.")
    return "\n".join(lines)
