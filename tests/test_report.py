"""Every diagnostic the report states, pinned on a synthetic run.json with no real data.

The fixture is built in code: a tie pair, a needs_review pull, one hot folder, a truncation
skew, a dominant bucket spread over a few folders, an error class, two withheld notes, one
quarantine of each kind, a linkless graph and mtime ages. Every threshold is read from the
module, so a change to a constant changes the expectation, not the test.
"""

from __future__ import annotations

import json
import random
import re

import pytest

from janitor import report as R

BUCKETS = R.ALL_BUCKETS


def vote(path, bucket, probs, *, conf=None, truncated=False, words=400, tokens=1000, chars=3000,
         out_links=0, age_source="mtime", age_days=0, judge="jev", redacted=(), action="frontmatter", triggers=(), cached=False):
    full = {b: 0.0 for b in BUCKETS}
    full.update(probs)
    ordered = sorted(full.values(), reverse=True)
    return {
        "kind": "vote", "judge": judge, "path": path, "bucket": bucket, "bucket_probabilities": full,
        "confidence": ordered[0] if conf is None else conf, "bucket_margin": round(ordered[0] - ordered[1], 3),
        "persist": 1.0, "action": action, "quarantine_triggers": list(triggers), "redacted": list(redacted),
        "redacted_own": list(redacted), "truncated": truncated, "excerpt_chars": 16000 if truncated else chars,
        "payload_chars": chars, "input_tokens": tokens, "cached": cached, "model": "jev-1.13.0", "taxonomy": R.default_fingerprint(),
        "graph": {"words": words, "headings": 1, "out_links": out_links, "in_links": 0, "embeds": 0,
                  "unresolved_links": 0, "is_moc": False, "is_orphan": False, "age_days": age_days},
        "age_source": age_source, "exact_duplicate_of": None, "reason": "normal vote",
    }


def fixture():
    rng = random.Random(7)
    rows = []
    # 62 confident log_entry notes across three folders: the dominant bucket (over half of judged)
    for i in range(62):
        folder = ["logs/a", "logs/b", "logs/c"][i % 3]
        rows.append(vote(f"{folder}/run-{i}.md", "log_entry", {"log_entry": 0.9, "junk": 0.05}, tokens=2000, chars=6000))
    # 12 confident notes elsewhere, with dated frontmatter
    for i in range(12):
        rows.append(vote(f"notes/n{i}.md", "durable_memory", {"durable_memory": 0.8, "reference": 0.1}, out_links=1 if i < 2 else 0, age_source="frontmatter", age_days=40))
    # the pile: 10 code_note-reference ties (merging clears them: 0.4 + 0.35 = 0.75). Their folder
    # holds fewer than HOT_FOLDER_MIN_NOTES judged notes, so it cannot read as hot.
    for i in range(10):
        rows.append(vote(f"ties/tie-{i}.md", "code_note", {"code_note": 0.40, "reference": 0.35, "log_entry": 0.15}))
    # 12 needs_review pulls: 6 explicit, 6 as runner-up. Jev abstaining, not a category pair.
    for i in range(6):
        rows.append(vote(f"review/nr-{i}.md", "needs_review", {"needs_review": 0.45, "durable_memory": 0.40}))
    for i in range(6):
        rows.append(vote(f"review/nr2-{i}.md", "durable_memory", {"durable_memory": 0.45, "needs_review": 0.40}))
    # a hot folder: 22 judged, 14 in the pile (64% against a vault share around 30%), all truncated
    for i in range(22):
        if i < 14:
            rows.append(vote(f"hot/h{i}.md", "ephemeral", {"ephemeral": 0.38, "junk": 0.34, "log_entry": 0.2}, truncated=True))
        else:
            rows.append(vote(f"hot/h{i}.md", "ephemeral", {"ephemeral": 0.85, "junk": 0.1}))
    # a third real pair, so the spread below is not one of the top TIE_TOP_PAIRS pairs
    for i in range(2):
        rows.append(vote(f"misc2/dr-{i}.md", "durable_memory", {"durable_memory": 0.40, "reference": 0.35, "junk": 0.15}))
    # a pile note no rule explains: a three-way spread whose pair is fourth, not hot, not truncated
    rows.append(vote("misc/spread.md", "project_decision", {"project_decision": 0.34, "ephemeral": 0.33, "code_note": 0.33}))
    # local decisions, withheld notes, errors, one quarantine of each kind
    rows.append(vote("notes/dup.md", "junk", {"junk": 1.0}, judge="local"))
    rows[-1]["reason"] = "exact duplicate of notes/n0.md: decided locally"
    rows.append(vote("notes/empty.md", "junk", {"junk": 1.0}, judge="local"))
    rows[-1]["reason"] = "empty body or headings only: decided locally"
    rows.append(vote("notes/leak.md", "needs_review", {"needs_review": 1.0}, judge="local", redacted=["KEY"], action="quarantine", triggers=["local:KEY"]))
    rows[-1]["reason"] = "local redaction hit: KEY"
    rows.append(vote("notes/secretish.md", "durable_memory", {"durable_memory": 0.9}, action="quarantine", triggers=["contains_secret"]))
    rows.append({"kind": "skip", "path": "private/a.md", "skipped": "sensitive_path"})
    rows.append({"kind": "skip", "path": "private/b.md", "skipped": "sensitive_path"})
    rows.append({"kind": "error", "path": "notes/boom.md", "error": "TypeSafePermissionDeniedError", "attempt": 1, "action": "error"})
    rng.shuffle(rows)
    return rows


N_JUDGED = 62 + 12 + 10 + 12 + 22 + 2 + 1 + 1  # the contains_secret note is judged too
N_PILE = 10 + 12 + 14 + 2 + 1


@pytest.fixture(scope="module")
def D():
    return R.diagnose(fixture())


@pytest.fixture(scope="module")
def page(tmp_path_factory):
    out = tmp_path_factory.mktemp("r") / "r.html"
    R.build(fixture(), "Synthetic vault", out)
    return out.read_text(encoding="utf-8")


def test_counts_and_pile(D):
    assert D["n_judged"] == N_JUDGED and D["n_local"] == 3 and D["n_withheld"] == 2 and D["n_errors"] == 1
    assert D["n_pile"] == N_PILE
    assert D["pile_pct"] == pytest.approx(N_PILE / N_JUDGED * 100)
    assert D["median_margin_pile"] < D["median_margin_rest"]


# --- item 1: a tie with needs_review is Jev abstaining, never a merge candidate -----------------

def test_tie_pairs_are_real_category_pairs_only(D):
    pairs = dict(D["tie_pairs"])
    assert pairs[("code_note", "reference")] == 10
    assert pairs[("ephemeral", "junk")] == 14
    assert all("needs_review" not in p for p in pairs)
    assert all("needs_review" not in w["pair"] for w in D["merge_whatif"])
    assert D["needs_review_explicit"] == 6 and D["needs_review_runner_up"] == 6 and D["needs_review_pull"] == 12


def test_merge_and_differ_advice_never_sits_next_to_needs_review(page):
    for li in re.findall(r"<li>(.*?)</li>", page, re.S):
        if "needs_review" in li and ("`needs_review`" in li or "needs_review pull" in li):
            assert "merg" not in li.lower() or "not two overlapping sentences" in li, li[:200]
            assert "say how they differ" not in li, li[:200]
    summary = re.search(r"<section id='summary'>(.*?)</section>", page, re.S).group(1)
    # the label counts explicit votes plus runner-ups and says so; through 0.5.5 it read "Jev abstaining
    # into needs_review", which called a runner-up a vote
    assert "on top or as runner-up" in summary or "needs_review" not in summary
    assert "abstaining" not in page and "abstained" not in page


# --- item 2: the what-if is an estimate under a stated assumption, not a bound ----------------

def test_merge_whatif_is_an_estimate_from_the_probabilities(D):
    by_pair = {w["pair"]: w for w in D["merge_whatif"]}
    assert by_pair[("code_note", "reference")]["clears"] == 10  # 0.40 + 0.35 = 0.75
    assert by_pair[("ephemeral", "junk")]["clears"] == 14  # 0.38 + 0.34 = 0.72
    assert len(by_pair[("ephemeral", "junk")]["covers"]) == 14
    assert D["best_merge"]["pair"] == ("ephemeral", "junk")


def test_no_upper_bound_wording_anywhere(page):
    assert "upper bound" not in page
    assert "if Jev splits its vote the same way" in page.lower() or "If Jev splits its vote the same way" in page


# --- item 3: a taxonomy edit means a full-price scan; the pile-only cost is hypothetical --------

def test_taxonomy_edit_cost_is_the_full_scan(D, page):
    assert D["full_rescan_usd"] == pytest.approx(D["cost_usd"])
    assert "full price" in page and "every cache key misses" in page
    assert "logged as <code>--only-pile</code>, not built" in page
    assert "re-sends everything at full price" in page  # section F's exception
    assert "then rerun the pile" not in page


# --- item 4: two kinds of quarantine ----------------------------------------------------------

def test_quarantines_are_split_by_kind(D, page):
    assert len(D["quarantine_local"]) == 1 and len(D["quarantine_vote"]) == 1
    assert D["quarantine_by_trigger"] == {"local:KEY": 1, "contains_secret": 1}
    assert "If it is real, rotate it" in page and "EXAMPLEKEY" in page
    assert "Jev judged the note to hold a secret" in page
    assert page.count("rotate it") == 1  # only on the local-hit bullet


# --- item 5: the unused-bucket advice is computed from the run --------------------------------

def test_unused_bucket_advice_comes_from_the_rows(D, page):
    assert "wiki of digests" not in page
    assert D["unused_buckets"] == ["reference", "junk"]
    assert D["unused_runner_up"] == {"reference": 12, "junk": 14}
    assert "`reference` was the runner-up in 12 pile notes" in page
    rows = [r for r in fixture() if not r["path"].startswith(("ties/", "misc2/"))]
    D2 = R.diagnose(rows)
    assert "reference" in D2["unused_buckets"] and D2["unused_runner_up"]["reference"] == 0
    out = R.build.__globals__["section_c"](D2)
    assert "`reference` was never a runner-up in the pile either" in out


# --- item 6: the noise floor is the measured one --------------------------------------------

def test_footer_states_the_measured_noise_floor(page):
    assert "0.03–0.04" not in page
    assert "1,974 of 1,974" in page and "median 0.01, p90 0.03, at most 0.10" in page


# --- item 7: overlapping actions are stated and never exceed the pile -------------------------

def test_next_scan_states_overlaps_and_the_distinct_total(D, page):
    acts = D["next_scan"]
    hot = next(a for a in acts if a["unit"] == "pile notes in hot folders")
    trunc = next(a for a in acts if a["unit"] == "truncated pile notes")
    later = hot if acts.index(hot) > acts.index(trunc) else trunc
    assert later["shared"] == 14 and later["overlaps"] is True  # the hot folder's 14 pile notes are the 14 truncated ones
    assert D["next_scan_distinct"] <= D["n_pile"]
    assert "14 of these notes are already counted by an action above; mostly the same fix seen twice" in page
    assert f"touch {D['next_scan_distinct']:,} distinct pile notes of {D['n_pile']:,}" in page


# --- item 8: a just-cloned copy -------------------------------------------------------------

def test_just_cloned_diagnosis(D):
    assert D["just_cloned"] is False  # 12 notes carry frontmatter dates
    rows = fixture()
    for r in rows:
        if r.get("kind") == "vote":
            r["age_source"] = "mtime"
            r["graph"]["age_days"] = 0
    D2 = R.diagnose(rows)
    assert D2["age_mtime_share"] == 1.0 and D2["age_zero_share"] == 1.0 and D2["just_cloned"] is True
    out = R.build.__globals__["section_g"](D2)
    assert "This copy was just cloned or copied" in out and "created:" in out


# --- item 9: the unexplained remainder is explicit ---------------------------------------------

def test_unexplained_remainder_is_counted_marked_and_actioned(D, page):
    assert D["pile_no_cause"] == 1
    spread = next(r for r in D["pile"] if r["path"] == "misc/spread.md")
    assert D["causes"][id(spread)] == ["unexplained"]
    assert "<strong>Unexplained:</strong> 1 pile notes match none of these rules" in page
    assert "Spot-check the 1 pile notes no rule explains" in page


# --- the rest of the diagnostics, unchanged from the first round --------------------------------

def test_hot_folder_rule(D):
    assert [h["folder"] for h in D["hot_folders"]] == ["hot"]
    h = D["hot_folders"][0]
    assert h["judged"] == 22 and h["pile"] == 14
    assert h["share"] >= R.HOT_FOLDER_RATIO * D["vault_pile_share"]
    assert h["usd"] == pytest.approx(22 * 1000 / 1e6 * R.PRICE_PER_MILLION_USD)


def test_hot_folder_needs_the_minimum_note_count():
    rows = fixture()
    for i in range(10):
        rows.append(vote(f"tiny/t{i}.md", "ephemeral", {"ephemeral": 0.38, "junk": 0.34} if i < 9 else {"ephemeral": 0.9}))
    assert "tiny" not in [h["folder"] for h in R.diagnose(rows)["hot_folders"]]


def test_truncation_skew_is_a_cause_only_when_over_represented(D):
    assert D["trunc_pile"] == 14 and D["trunc_all"] == 14
    assert D["truncation_cause"] is True and D["excerpt_cap"] == 16000
    rows = fixture()
    for r in rows:
        if r.get("kind") == "vote":
            r["truncated"] = True
    assert R.diagnose(rows)["truncation_cause"] is False


def test_short_notes_not_a_cause_here_and_a_cause_when_skewed(D):
    assert D["short_cause"] is False
    rows = fixture()
    for r in rows:
        if r.get("kind") == "vote" and r["path"].startswith("hot/") and (r.get("confidence") or 0) < R.REVIEW_FLOOR:
            r["graph"]["words"] = 10
    assert R.diagnose(rows)["short_cause"] is True


def test_every_pile_row_gets_its_causes(D):
    causes = {r["path"]: D["causes"][id(r)] for r in D["pile"]}
    assert causes["ties/tie-0.md"] == ["tie code_note–reference"]
    assert causes["review/nr-0.md"] == ["needs_review pull"]
    assert causes["review/nr2-0.md"] == ["needs_review pull"]
    assert causes["hot/h0.md"] == ["tie ephemeral–junk", "hot folder", "truncated"]


def test_pile_rerun_cost_is_the_bills_range(D):
    chars = N_PILE * 3000 + R.DEFAULT_QUESTION_CHARS * N_PILE
    assert D["pile_rerun_usd"] == R.cost_for_chars(chars)
    assert D["pile_rerun_measured_usd"] == pytest.approx(N_PILE * 1000 / 1e6 * R.PRICE_PER_MILLION_USD)


def test_dominant_bucket_and_its_folders(D):
    d = D["dominant"]
    assert d["bucket"] == "log_entry" and d["n"] == 62 and d["share"] == pytest.approx(62 / N_JUDGED)
    assert {f for f, _ in d["folders"]} == {"logs/a", "logs/b", "logs/c"}
    assert d["cover_notes"] == 62 and d["cover_tokens"] == 124000


def test_no_dominant_bucket_below_the_share():
    rows = [r for r in fixture() if not r["path"].startswith("logs/")]
    assert R.diagnose(rows)["dominant"] is None


def test_membrane_counts_never_carry_a_path(D):
    assert D["withheld_by_reason"] == {"sensitive_path": 2}
    assert D["local_by_reason"] == {"exact duplicate": 1, "empty body or headings only": 1, "local redaction hit": 1}
    assert D["hits_by_label"] == {"KEY": 1}
    assert len(D["quarantined"]) == 2


def test_errors_by_class(D):
    assert D["errors_by_class"] == {"TypeSafePermissionDeniedError": 1}


def test_cost_and_measured_ratio(D):
    tokens = 62 * 2000 + (N_JUDGED - 62) * 1000
    assert D["input_tokens"] == tokens and D["n_sent"] == N_JUDGED
    assert D["cost_usd"] == pytest.approx(tokens / 1e6 * R.PRICE_PER_MILLION_USD)
    payload = 62 * 6000 + (N_JUDGED - 62) * 3000
    assert D["measured_ratio"] == pytest.approx((payload + R.DEFAULT_QUESTION_CHARS * N_JUDGED) / tokens)
    assert D["suggested_max_usd"] == R.MAX_USD_STEP


def test_cached_rows_do_not_count_as_spend():
    rows = fixture()
    for r in rows:
        if r.get("kind") == "vote":
            r["cached"] = True
    D = R.diagnose(rows)
    assert D["input_tokens"] == 0 and D["cost_usd"] == 0 and D["measured_ratio"] is None


def test_graph_and_age(D):
    assert D["linking_share"] == pytest.approx(2 / N_JUDGED)
    assert D["orphan_unknown"] is True
    assert D["age_sources"] == {"mtime": N_JUDGED - 12, "frontmatter": 12}
    assert D["age_mtime_share"] > 0.5


def test_next_scan_is_ordered_by_impact_and_names_each_fix(D):
    units = [a["unit"] for a in D["next_scan"]]
    assert units[0] in ("notes that would clear if the split holds (estimate)", "pile notes in hot folders") and D["next_scan"][0]["impact"] == 14
    assert "dollars per scan (measured)" in units and "truncated pile notes" in units and "errored notes" in units
    impacts = [a["impact"] * (100 if a.get("dollars") else 1) for a in D["next_scan"]]
    assert impacts == sorted(impacts, reverse=True)
    texts = " ".join(a["what"] for a in D["next_scan"])
    assert "--excerpt-chars" in texts and "--sensitive-paths" in texts and "--resume" in texts and "created:" in texts and "Spot-check" in texts


def test_taxonomy_sentences_are_quoted_only_for_the_default_fingerprint(D):
    if R.TAXONOMY_FILE.exists():
        assert D["sentences"]["needs_review"].startswith("Not enough signal")
    rows = fixture()
    for r in rows:
        if r.get("kind") == "vote":
            r["taxonomy"] = "0000deadbeef"
    assert R.diagnose(rows)["sentences"] == {}


def test_build_writes_every_section_and_labels_estimates(page):
    for anchor in ("id='summary'", "id='pile'", "id='landed'", "id='membrane'", "id='errors'", "id='cost'", "id='graph'", "id='next'"):
        assert anchor in page, anchor
    assert "estimate" in page and "measured" in page
    assert "everything else can be left alone" not in page
    assert "Spot-check" in page


def test_empty_run_does_not_crash(tmp_path):
    out = tmp_path / "e.html"
    _, D = R.build([], "Empty", out)
    assert D["n_votes"] == 0 and out.exists()


# --- r3 item 1: exclusion advice is safe: defaults kept, name-anywhere stated, collateral counted ---

def test_every_exclusion_flag_keeps_the_five_defaults(D, page):
    flags = re.findall(r"--sensitive-paths [^<\s]+", page)
    assert flags, "no exclusion flag rendered"
    for flag in flags:
        names = flag.split(" ", 1)[1].split(",")
        assert names[:5] == list(R.DEFAULT_SENSITIVE), flag
    assert "replaces the list rather than extending it" in page
    assert "matches as whole words anywhere in the vault" in page
    assert "no journal for this run was found" in page  # the fixture passes no journal header


def test_exclusion_names_the_other_folders_the_same_name_would_withhold():
    rows = fixture()
    # the hot folder's name appears elsewhere in the vault: `hot` under archive/, plus a distractor
    for i in range(3):
        rows.append(vote(f"archive/hot/old-{i}.md", "log_entry", {"log_entry": 0.9}))
    rows.append(vote("archive/hotel/h.md", "log_entry", {"log_entry": 0.9}))  # `hotel` is not the word `hot`
    rows.append({"kind": "skip", "path": "private/hot/x.md", "skipped": "sensitive_path"})  # withheld folders count too
    D2 = R.diagnose(rows)
    ex = D2["hot_folders"][0]["exclude"]
    assert ex["name"] == "hot"
    assert ex["flag"] == "--sensitive-paths family,private,personal,secrets,inbox,hot"
    assert ex["others"] == ["archive/hot"]  # private/hot is already withheld by the list, so it is not collateral
    out = R.build.__globals__["section_b"](D2)
    assert "also matches 1 other folder(s) in this run" in out and "archive/hot" in out


def test_exclusion_helper_matches_whole_words_and_skips_subfolders():
    folders = {"a/planting-seeds", "a/planting-seeds/2026", "b/Planting Seeds", "c/seeds", "d/unplanting-seeds"}
    ex = R.exclusion(folders, "a/planting-seeds")
    assert ex["name"] == "planting-seeds"
    assert ex["others"] == ["b/Planting Seeds"]  # words match case-insensitively; the subfolder is the same exclusion, not collateral
    ex2 = R.exclusion(folders, "c/seeds", base=["family", "private", "personal", "secrets", "inbox", "notes"])
    assert ex2["flag"] == "--sensitive-paths family,private,personal,secrets,inbox,notes,seeds"
    # `seeds` is a whole word of four other folder names: exactly the collateral the report must state
    assert ex2["others"] == ["a/planting-seeds", "a/planting-seeds/2026", "b/Planting Seeds", "d/unplanting-seeds"]


# --- r3 item 2: "path rule" only under "What would make it better" -------------------------------

def test_path_rule_appears_only_in_enhancement_blocks(page):
    for m in re.finditer(r'<div class="ex"><span class="exk">(.*?)</span><div class="exv">(.*?)</div></div>', page, re.S):
        key, body = m.group(1), m.group(2)
        if key != "What would make it better":
            assert "path rule" not in body, (key, body[:160])
    for sid in ("summary", "next"):
        sec = re.search(rf"<section id='{sid}'>(.*?)</section>", page, re.S).group(1)
        assert "path rule" not in sec, sid


# --- r3 item 3: hot folders are conditional and name what competes there ---------------------------

def test_hot_folder_advice_is_conditional_and_names_the_competing_pair(D, page):
    h = D["hot_folders"][0]
    assert h["competes"] == {"kind": "tie", "pair": ("ephemeral", "junk"), "n": 14}
    assert "If this folder is machine-generated, exclude it" in page
    assert "If it is your own writing, the taxonomy has no bucket that fits it" in page
    assert "`ephemeral` against `junk` in 14 of its 14 pile notes" in page
    assert "jev-janitor &lt;vault&gt;/hot --taxonomy FILE" in page


def test_hot_folder_competes_can_be_needs_review():
    rows = fixture()
    for i in range(22):
        rows.append(vote(f"abstain/a{i}.md", "needs_review" if i < 14 else "durable_memory",
                         {"needs_review": 0.45, "durable_memory": 0.40} if i < 14 else {"durable_memory": 0.9}))
    D2 = R.diagnose(rows)
    h = next(h for h in D2["hot_folders"] if h["folder"] == "abstain")
    assert h["competes"] == {"kind": "needs_review", "n": 14}


# --- r3 item 4: the summary's first action is safe and doable today --------------------------------

def test_summary_first_action_is_safe(page):
    summary = re.search(r"<section id='summary'>(.*?)</section>", page, re.S).group(1)
    assert "path rule" not in summary and "then rerun the pile" not in summary
    if "--sensitive-paths" in summary:
        assert "--sensitive-paths family,private,personal,secrets,inbox," in summary
        assert "machine-generated" in summary


# --- r3 item 5: the truncation what-if covers every truncated note and states its assumption --------

def test_truncation_whatif_covers_every_truncated_note(D, page):
    rows = fixture()
    # two confident, truncated notes outside the pile
    for i in range(2):
        rows.append(vote(f"notes/long-{i}.md", "durable_memory", {"durable_memory": 0.9}, truncated=True))
    D2 = R.diagnose(rows)
    assert D2["trunc_pile"] == 14 and D2["trunc_all_notes"] == 16
    assert D2["trunc_new_cap"] == 16000 * R.EXCERPT_DOUBLE
    assert D2["trunc_double_cap_usd"] == R.cost_for_chars(16 * 16000 * (R.EXCERPT_DOUBLE - 1))
    out = R.build.__globals__["section_b"](D2)
    assert "If the cap doubles to 32,000" in out and "across all 16 truncated notes in the vault, not only the pile's 14" in out
    assert "if every truncated note doubles" not in page and "Bill delta if" not in page


# --- r3 item 1, gated: a name with collateral is never offered as a flag -------------------------

def test_exclusion_set_splits_safe_from_unsafe_names():
    folders = {"logs/a", "logs/b", "logs/c", "archive/a", "x/output", "y/output", "z/reports"}
    ex = R.exclusion_set(folders, ["logs/a", "logs/b", "x/output"])
    assert [s["name"] for s in ex["safe"]] == ["b"]  # `a` also matches archive/a; `output` also matches y/output
    assert {u["name"]: u["others"] for u in ex["unsafe"]} == {"a": ["archive/a"], "output": ["y/output"]}
    assert ex["flag"] == "--sensitive-paths family,private,personal,secrets,inbox,b"
    assert R.exclusion_set(folders, ["x/output"])["flag"] is None


def test_an_unsafe_hot_folder_gets_no_flag_only_the_reason():
    rows = fixture()
    for i in range(3):
        rows.append(vote(f"archive/hot/old-{i}.md", "log_entry", {"log_entry": 0.9}))
    D2 = R.diagnose(rows)
    assert D2["hot_folders"][0]["exclude"]["safe"] is False
    assert D2["hot_exclusion"]["flag"] is None
    out = R.build.__globals__["section_b"](D2)
    assert "it still cannot be withheld by name" in out and "archive/hot" in out
    assert "--sensitive-paths family,private,personal,secrets,inbox,hot" not in out
    h = R.build.__globals__["section_h"](D2)
    assert "none of them can be withheld by name" in h


def test_a_safe_hot_folder_gets_the_flag_and_the_no_collateral_statement(D, page):
    assert D["hot_folders"][0]["exclude"]["safe"] is True
    assert D["hot_exclusion"]["flag"] == "--sensitive-paths family,private,personal,secrets,inbox,hot"
    assert "<code>hot</code> matches no other folder in this run" in page
    assert "1 of them can be withheld by name with no other folder affected" in page


def test_an_unsafe_hot_folder_advice_has_no_path_rule_either():
    rows = fixture()
    for i in range(3):
        rows.append(vote(f"archive/hot/old-{i}.md", "log_entry", {"log_entry": 0.9}))
    out = R.build.__globals__["section_b"](R.diagnose(rows))
    for m in re.finditer(r'<div class="ex"><span class="exk">(.*?)</span><div class="exv">(.*?)</div></div>', out, re.S):
        if m.group(1) != "What would make it better":
            assert "path rule" not in m.group(2)


# --- r4 item 1: flags are built on the run's recorded list, read from the journal header ---------

RECORDED = ["family", "private", "personal", "secrets", "inbox", "Clients", "board-minutes", "payroll"]


def test_flags_are_built_on_the_journal_headers_list(tmp_path):
    header = {"kind": "header", "run": "abcd1234", "sensitive_parts": RECORDED}
    rows = fixture()
    rows.append({"kind": "skip", "path": "Clients/acme/x.md", "skipped": "sensitive_path"})
    D2 = R.diagnose(rows, journal_header=header)
    assert D2["sensitive_list"] == RECORDED and D2["sensitive_list_known"] is True
    assert "8 names" in D2["sensitive_list_source"] and "abcd1234" in D2["sensitive_list_source"]
    out = tmp_path / "r.html"
    R.build(rows, "Synthetic", out, journal_header=header)
    page = out.read_text(encoding="utf-8")
    flags = re.findall(r"--sensitive-paths [^<\s]+", page)
    assert flags
    for flag in flags:
        names = flag.split(" ", 1)[1].split(",")
        assert names[:8] == RECORDED, flag
    import html as _html
    assert "the list this run actually used, read from the run's journal header (8 names, run abcd1234)" in _html.unescape(page)
    assert "no journal for this run was found" not in page


def test_without_a_journal_the_defaults_carry_a_prominent_warning(page):
    assert "<strong>the five names before it are the defaults, not necessarily your list:</strong>" in page
    assert "they will be sent on the next scan" in page


def test_collateral_ignores_folders_the_recorded_list_already_withholds():
    folders = {"a/hot", "Clients/hot", "b/hot"}
    ex = R.exclusion(folders, "a/hot", base=RECORDED)
    assert ex["others"] == ["b/hot"]  # Clients/hot is withheld by `Clients` already
    ex2 = R.exclusion_set(folders, ["a/hot", "b/hot"], base=RECORDED)
    assert ex2["flag"] == "--sensitive-paths " + ",".join(RECORDED) + ",hot"


def test_journal_discovery_next_to_run_json(tmp_path):
    (tmp_path / "run.json").write_text("[]", encoding="utf-8")
    assert R.find_journal(tmp_path / "run.json") is None
    j = tmp_path / "journal" / "run-20260101T000000-aaaa.jsonl"
    j.parent.mkdir()
    j.write_text('{"kind": "header", "run": "aaaa", "sensitive_parts": ["family", "x"]}' + chr(10) + '{"kind": "vote"}' + chr(10), encoding="utf-8")
    newer = tmp_path / "journal" / "run-20260102T000000-bbbb.jsonl"
    newer.write_text('{"kind": "header", "run": "bbbb", "sensitive_parts": ["family", "y"]}' + chr(10), encoding="utf-8")
    assert R.find_journal(tmp_path / "run.json") == newer
    assert R.load_journal_header(newer)["sensitive_parts"] == ["family", "y"]


# --- r4 item 2: the matcher is the janitor's own, and the fallback agrees with it ------------------

def test_matcher_is_the_janitors_own():
    from janitor.redact import segment_matches as real

    assert R.MATCHER_SOURCE == "janitor.redact.segment_matches" and R.segment_matches is real


# --- r4 item 3: the summary names the action in one sentence and points to the section ----------

def test_summary_first_action_is_one_sentence_without_the_flag(page):
    summary = re.search(r"<section id='summary'>(.*?)</section>", page, re.S).group(1)
    first = re.split(r"The one thing to do first, because [^:]*: ", summary)[1]
    assert "--sensitive-paths" not in first
    assert "pile section" in first or "landed section" in first or first.count(". ") <= 1


# --- r4c item 1: the summary's lead is the largest cause BY COUNT; the first action is H #1 and says why

def test_summary_lead_is_the_largest_cause_and_the_first_action_is_ranked_by_effect():
    """A 6-note tie that no merge would clear (both probabilities low) leads the pile by count; a 4-note
    tie whose merge clears every note is the first action by effect. The summary must say both, as
    two different things, and never call the smaller tie the lead."""
    rows = []
    for i in range(40):
        rows.append(vote(f"notes/n{i}.md", "durable_memory", {"durable_memory": 0.9, "reference": 0.05}))
    for i in range(6):
        rows.append(vote(f"a/tie-{i}.md", "log_entry", {"log_entry": 0.26, "ephemeral": 0.25, "junk": 0.2, "reference": 0.2}))
    for i in range(4):
        rows.append(vote(f"b/tie-{i}.md", "code_note", {"code_note": 0.40, "reference": 0.35, "junk": 0.15}))
    D = R.diagnose(rows)
    assert D["tie_pairs"][0] == (("ephemeral", "log_entry"), 6)
    assert D["best_merge"]["pair"] == ("code_note", "reference") and D["best_merge"]["clears"] == 4
    assert D["next_scan"][0]["why"] == "4 notes would clear if the split holds, an estimate"
    page = R.section_a(D)
    assert "led by a tie between the categories `ephemeral` and `log_entry` (6 notes)" in page
    assert "led by a tie between the categories `code_note`" not in page
    assert ("The one thing to do first, because it has the largest effect on the list (4 notes would clear if the split holds, an estimate): "
            "Edit the taxonomy so `code_note` and `reference` say how they differ, or merge them.") in page


def test_summary_first_action_is_the_first_next_scan_row(D, page):
    summary = re.search(r"<section id='summary'>(.*?)</section>", page, re.S).group(1)
    first = D["next_scan"][0]
    assert first.get("short", first["what"]) in summary
    assert f"largest effect on the list ({first['why']})" in summary
    assert first["why"].split(" ")[0] == str(first["impact"])


def test_every_ranked_action_says_why_in_its_own_units(D):
    for a in D["next_scan"]:
        if a["impact"]:
            assert a["why"], a["what"]
            assert (R.usd(a["impact"]) if a.get("dollars") else str(a["impact"])) in a["why"]
        else:
            assert "why" not in a


# --- the --html flag: written at the end of a run, offline says so, inside-the-vault warns ------

def test_cli_html_writes_the_report_offline_and_names_the_fixture(tmp_path, capsys):
    from janitor import cli

    vault = tmp_path / "v"
    vault.mkdir()
    for i in range(4):
        (vault / f"n{i}.md").write_text(f"# Note {i}\n\nbody of note {i}, a standing fact.\n", encoding="utf-8")
    out = tmp_path / "report.html"
    rc = cli.main([str(vault), "--offline", "--no-config", "--html", str(out)])
    assert rc == 0 and out.exists()
    page = out.read_text(encoding="utf-8")
    assert "every vote below is from the keyword fixture, not from Jev" in page
    assert "this run&#x27;s sensitive list (5 names)" in page
    err = capsys.readouterr().err
    assert "report: " in err and "local only: it lists each note's vault-relative path as written, unredacted" in err and "WARNING" not in err


def test_cli_html_inside_the_vault_warns(tmp_path, capsys):
    from janitor import cli

    vault = tmp_path / "v"
    vault.mkdir()
    (vault / "n.md").write_text("# N\n\nbody\n", encoding="utf-8")
    rc = cli.main([str(vault), "--offline", "--no-config", "--html", str(vault / "report.html")])
    assert rc == 0
    assert "WARNING: it is inside the vault" in capsys.readouterr().err


def test_module_main_renders_a_saved_run(tmp_path, capsys):
    import json as _json

    run = tmp_path / "run.json"
    run.write_text(_json.dumps(fixture()), encoding="utf-8")
    out = tmp_path / "r.html"
    assert R.main([str(run), str(out), "Saved run"]) == 0
    assert out.exists() and "no journal for this run was found" in out.read_text(encoding="utf-8")
    assert "wrote" in capsys.readouterr().out


# --- the page carries no sent text: a sentinel body, frontmatter value and alias under --show-payload --

def test_the_page_carries_paths_but_never_the_excerpt_a_frontmatter_value_or_an_alias(tmp_path, capsys):
    from janitor import cli

    vault = tmp_path / "v"
    vault.mkdir()
    NL = chr(10)
    (vault / "alpha-note.md").write_text(NL.join(["---", "aliases: [ALIAS-SENTINEL-77]", "client: VALUE-SENTINEL-88", "---", "# Alpha title", "", "BODY-SENTINEL-99 is in the body.", ""]), encoding="utf-8")
    (vault / "beta-note.md").write_text(NL.join(["# Beta title", "", "plain body", ""]), encoding="utf-8")
    out = tmp_path / "report.html"
    rc = cli.main([str(vault), "--offline", "--no-config", "--json", "--show-payload", "--html", str(out)])
    assert rc == 0
    stdout = capsys.readouterr().out
    assert "BODY-SENTINEL-99" in stdout  # --json --show-payload does carry the excerpt, as documented
    page = out.read_text(encoding="utf-8")
    assert "alpha-note.md" in page and "beta-note.md" in page  # the path, as written
    for sentinel in ("BODY-SENTINEL-99", "VALUE-SENTINEL-88", "ALIAS-SENTINEL-77"):
        assert sentinel not in page, sentinel
    assert "lists each note's vault-relative path as written, unredacted" in page


# --- the demo vault: an offline scan of it is a smoke test, and it holds no vendor token shapes ------

DEMO = R.DEFAULT_TAXONOMY.resolve().parent.parent.parent / "examples" / "demo-vault"


def test_demo_vault_scans_offline_and_the_report_renders(tmp_path, capsys):
    from janitor import cli

    assert DEMO.is_dir()
    out = tmp_path / "demo.html"
    rc = cli.main([str(DEMO), "--offline", "--no-config", "--json", "--html", str(out)])
    assert rc == 0
    rows = json.loads(capsys.readouterr().out)
    votes = [r for r in rows if r.get("kind") == "vote"]
    skips = [r for r in rows if r.get("kind") == "skip"]
    assert 200 <= len(votes) <= 300 and len(votes) + len(skips) == len(rows)
    assert {r["path"].split("/")[0] for r in skips} == {"Inbox", "personal"}  # withheld by the default list
    assert sum(1 for r in votes if r["action"] == "quarantine") == 1
    labels = {k for r in votes for k in r.get("redacted", [])}
    assert labels == {"EMAIL", "PHONE", "URL_CREDENTIAL"}
    assert sum(1 for r in votes if r.get("truncated")) == 2
    assert 3 <= sum(1 for r in votes if r.get("exact_duplicate_of")) <= 12
    assert sum(1 for r in votes if r.get("age_source") == "frontmatter") > 0.8 * len(votes)
    D = R.diagnose(rows)
    assert D["n_votes"] == len(votes) and D["n_withheld"] == len(skips)
    page = out.read_text(encoding="utf-8")
    assert "keyword fixture, not from Jev" in page and "id='next'" in page


def test_demo_vault_holds_no_vendor_token_shape_and_nothing_real():
    """The tree-scan test skips the demo vault for its one fake URL password; this is the
    sweep it gets instead: no vendor key or webhook shape, no JWT or PEM, only reserved
    contact details, and none of the private names the repo's own sweep forbids."""
    from janitor.redact import PATTERNS

    scanners = [pat for label, pat in PATTERNS if label in ("KEY", "WEBHOOK", "JWT", "PEM", "AWS_SECRET", "BEARER")]
    texts = {p: p.read_text(encoding="utf-8") for p in DEMO.rglob("*.md")}
    assert len(texts) >= 200
    for p, text in texts.items():
        for pat in scanners:
            assert pat.search(text) is None, (p.name, pat.pattern[:30])
        for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
            assert email.endswith(("@example.com", "@example.org")), (p.name, email)
        for phone in re.findall(r"\b\d{3}-\d{3}-\d{4}\b", text):
            assert phone.startswith("555-555-01"), (p.name, phone)
    creds = [p.name for p, text in texts.items() if re.search(r"://[^\s/]+:[^\s@]+@", text)]
    assert creds == ["Sensor database.md"]


def test_demo_vault_body_lines_do_not_repeat_across_notes():
    """The vault must read as written, not generated: outside the three deliberate archive copies,
    no substantive body line (over 25 characters, frontmatter excluded) appears in more than
    three notes, and at least 90% of such lines are distinct across the vault."""
    from collections import Counter

    deliberate = {"Archive/Greenhouse budget (old).md", "Archive/Backup job (copy).md", "Archive/Starter care (copy).md", "README.md"}
    lines, per_note, total = Counter(), Counter(), 0
    for p in DEMO.rglob("*.md"):
        rel = p.relative_to(DEMO).as_posix()
        if rel in deliberate:
            continue
        text = p.read_text(encoding="utf-8")
        if text.startswith("---"):
            text = text.split("---", 2)[2]
        seen = set()
        for line in text.splitlines():
            s = line.strip()
            if len(s) > 25:
                total += 1
                lines[s] += 1
                if s not in seen:
                    seen.add(s)
                    per_note[s] += 1
    repeated = [(s, n) for s, n in per_note.items() if n > 3]
    assert not repeated, repeated[:5]
    assert len(lines) / total >= 0.9, (len(lines), total)


# --- the committed live run: rows, card and README agree, and nothing sent is in the repo -----------

RUN_DIR = DEMO.parent / "demo-vault-run"


def test_committed_demo_run_is_consistent_with_its_card_and_the_readme():
    rows = json.loads((RUN_DIR / "run.json").read_text(encoding="utf-8"))
    votes = [r for r in rows if r.get("kind") == "vote"]
    jev = [r for r in votes if r.get("judge") == "jev"]
    assert len(rows) == 251 and len(votes) == 235 and len(jev) == 229
    assert not any("sent" in r for r in rows), "the committed rows must not carry the payload"
    assert all(r.get("model") == "jev-1.13.0" for r in jev)
    tokens = sum(r.get("input_tokens") or 0 for r in jev)
    cost = tokens / 1e6 * R.PRICE_PER_MILLION_USD
    assert tokens == 350181 and f"{cost:.4f}" == "0.0147"
    D = R.diagnose(rows, sensitive_list=list(R.DEFAULT_SENSITIVE))
    assert D["n_pile"] == 27 and len(D["quarantined"]) == 1 and D["n_withheld"] == 16
    page = (RUN_DIR / "report.html").read_text(encoding="utf-8")
    assert "LIVE" in page and "keyword fixture" not in page and "$0.0147" in page
    assert (RUN_DIR / "card.png").stat().st_size > 50_000
    readme = (DEMO.parent.parent / "README.md").read_text(encoding="utf-8")
    assert "229 of 251 notes sent" in readme and "350,181 input tokens" in readme and "**$0.0147**" in readme
    assert "27 notes (12%) went to the review pile" in readme
    # every path the rows and the card name is a demo-vault path: nothing from anywhere else
    demo_paths = {p.relative_to(DEMO).as_posix() for p in DEMO.rglob("*.md")}
    assert {r["path"] for r in rows} <= demo_paths
    assert not re.search(r"[A-Za-z]:\\\\|/Users/|/home/", (RUN_DIR / "report.html").read_text(encoding="utf-8"))
    # the header carries the run's own time, labelled as the run, not the time the page was rendered
    assert R.run_time(rows) == max(r["at"] for r in rows if "at" in r)
    assert "run 2026-09-24 18:08 UTC" in page and "rendered " not in page


# --- 0.5.1: the header time is the run's, from the rows' stamps; a stampless run says so ------------

def test_header_time_is_the_runs_latest_stamp_or_says_it_is_the_render_time():
    rows = [vote("a.md", "junk", {"junk": 0.9}), vote("b.md", "junk", {"junk": 0.9}), {"kind": "skip", "path": "c.md", "skipped": "sensitive_path"}]
    assert R.run_time(rows) is None
    assert R.when_label(rows).startswith("rendered ") and "no time stamps" in R.when_label(rows)
    rows[0]["at"] = "2026-01-02T03:04:05Z"
    rows[1]["at"] = "2026-01-02T03:59:59Z"
    rows[2]["at"] = "2026-01-02T03:30:00Z"
    assert R.run_time(rows) == "2026-01-02T03:59:59Z"
    assert R.when_label(rows) == "run 2026-01-02 03:59 UTC"
    rows[1]["at"] = "not a time"
    assert R.when_label(rows).startswith("rendered ")


# --- 0.5.2: the 0.5.1 audit's findings on the page ------------------------------------------------

def test_measured_ratio_uses_the_runs_recorded_question_size_not_a_constant():
    """A3. Through 0.5.1 a constant 2,086 (the default taxonomy's questions) fed the measured ratio of
    every run, --taxonomy runs included. The rows now record the size; an old run on another
    taxonomy gets "unavailable", not a wrong number; an old run on the default gets the default's."""
    rows = [vote(f"n{i}.md", "durable_memory", {"durable_memory": 0.9}, tokens=1000, chars=3000) for i in range(10)]
    for r in rows:
        r["taxonomy"] = "0000deadbeef"
        r["question_chars"] = 500
    D = R.diagnose(rows)
    assert D["question_chars_per_call"] == 500 and D["question_chars_source"] == "recorded on each row"
    assert D["measured_ratio"] == pytest.approx((10 * 3000 + 10 * 500) / 10_000)
    assert "500 question characters per call, recorded on each row" in R.section_f(D)
    for r in rows:
        del r["question_chars"]
    D = R.diagnose(rows)
    assert D["question_chars_known"] is False and D["measured_ratio"] is None and D["estimate_usd"] == (0.0, 0.0)
    page = R.section_f(D)
    assert "unavailable" in page and "0000deadbeef" in page and "characters per token</strong>" not in page
    for r in rows:
        r["taxonomy"] = R.DEFAULT_FINGERPRINT
    D = R.diagnose(rows)
    assert D["question_chars_per_call"] == R.DEFAULT_QUESTION_CHARS == 2086
    assert "matched by this run's fingerprint" in R.section_f(D)
    assert D["measured_ratio"] == pytest.approx((10 * 3000 + 10 * 2086) / 10_000)


def test_the_page_makes_no_network_request(page):
    """B1. The page lists unredacted vault paths; opening it must fetch nothing. Through 0.5.1 it
    loaded three font families from Google Fonts."""
    head = page.split("</head>")[0]
    assert "<link" not in head and "<script" not in page and "@import" not in page
    assert not re.search(r"""(src|href)=["']https?://""", page) and not re.search(r"""url\(\s*["']?https?://""", page)
    assert "fonts.googleapis" not in page and "fonts.gstatic" not in page
    assert "system-ui" in page and "ui-monospace" in page


def test_the_next_scan_price_sentence_is_computed_from_the_run(D, page):
    """B2. Through 0.5.1 the cost section hard-coded "the first action is a taxonomy edit, and the
    0.4.7 release already moved STATE_VERSION"."""
    first = D["next_scan"][0]
    sentence = R.next_scan_price(D)
    assert ("is a taxonomy edit" in sentence) == ("taxonomy" in first["what"].lower())
    assert "0.4.7 release already moved" not in page and "STATE_VERSION" not in sentence  # same version: no warning
    older = dict(D, state_version=R.STATE_VERSION - 1)
    assert f"made under STATE_VERSION {R.STATE_VERSION - 1} and this build uses {R.STATE_VERSION}" in R.next_scan_price(older)
    assert "regardless" not in R.next_scan_price(dict(D, state_version=R.STATE_VERSION))
    assert "checklist below is empty" in R.next_scan_price(dict(D, next_scan=[]))
    not_taxonomy = dict(D, next_scan=[{"what": "Run again with --resume", "impact": 1}])
    assert "is not a taxonomy edit" in R.next_scan_price(not_taxonomy)


def test_the_dominant_bucket_sentence_attributes_the_reading_to_jev(D, page):
    """The summary said "this vault is mostly <the bucket's definition>", stating the taxonomy's
    sentence as a fact about the vault. It is Jev's reading, and the summary says so."""
    assert D["dominant"]["bucket"] == "log_entry"
    summary = re.search(r"<section id='summary'>(.*?)</section>", page, re.S).group(1)
    assert "most of this vault reads to Jev as `log_entry` (a dated run report or snapshot)" in summary
    assert "this vault is mostly" not in summary


def test_the_footer_names_every_figure_not_from_the_rows():
    """0.5.3. The footer said the noise floor was the one quoted figure, on a page whose 2,086
    question characters were the default taxonomy's size (the fallback for rows that predate the
    field). The fallback is named as a second figure exactly when it is used."""
    rows = [vote(f"n{i}.md", "durable_memory", {"durable_memory": 0.9}, tokens=1000, chars=3000) for i in range(5)]
    for r in rows:
        r["question_chars"] = 700
    D = R.diagnose(rows)
    assert D["question_chars_source"] == "recorded on each row"
    assert R.quoted_figures(D).startswith("the one quoted figure is the noise floor") and "question characters" not in R.quoted_figures(D)
    for r in rows:
        del r["question_chars"]
    D = R.diagnose(rows)
    assert D["question_chars_source"] == R.FALLBACK_SOURCE
    text = R.quoted_figures(D)
    assert text.startswith("two quoted figures are not from these rows: the noise floor") and "2,086 question characters per call" in text
    assert "predate the recorded field" in text
    demo = (RUN_DIR / "report.html").read_text(encoding="utf-8")
    assert "two quoted figures are not from these rows" in demo and "2,086 question characters per call" in demo
    assert "the one quoted figure" not in demo


def test_the_committed_demo_page_carries_the_052_fixes():
    page = (RUN_DIR / "report.html").read_text(encoding="utf-8")
    assert "most of this vault reads to Jev as `log_entry`" in page and "this vault is mostly" not in page
    assert "fonts.googleapis" not in page and "<link" not in page.split("</head>")[0]
    assert "0.4.7 release" not in page
    assert "question characters per call, the default taxonomy's size, matched by this run's fingerprint" in page  # run.json predates the field
    assert "The first action in the checklist below is a taxonomy edit, so the scan after it is full price." in page
    assert "noise floor, a measurement from the calibration corpus" in page
