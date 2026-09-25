"""The brain-scan report: one self-contained HTML page that explains itself.

``jev-janitor VAULT --html FILE`` writes it at the end of a run from the run's own rows and
the sensitive list the run used. A saved run renders again without a request:

    python -m janitor.report run.json out.html "Vault name" [journal.jsonl]

No network, no libraries, no external assets beyond web fonts. Nothing is computed anywhere
but here, from the rows. The report lists each note's vault-relative path as written,
unredacted (the redacted form is what was sent), so the report itself is a local file:
keep it outside the vault, it is never written to the journal, and it is never sent.

Every section follows the same shape: what this shows, what we found (computed), why (a
named rule with a named threshold), what you can do (the flag, file or taxonomy sentence,
with its estimated effect and cost), and what would make it better. Every threshold below
is a named constant; every estimate is labelled as one.
"""
from __future__ import annotations

import html
import json
import math
import random
import re
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from janitor.bill import CHARS_PER_TOKEN_HIGH, CHARS_PER_TOKEN_LOW, PRICE_PER_MILLION_USD, taxonomy_chars, usd
from janitor.journal import STATE_VERSION
from janitor.redact import DEFAULT_SENSITIVE_PATH_PARTS as DEFAULT_SENSITIVE
from janitor.redact import segment_matches
from janitor.schema import DEFAULT_TAXONOMY, load_taxonomy, taxonomy_fingerprint

# ---- thresholds and constants: every rule in the report names one of these ----------------
REVIEW_FLOOR = 0.55            # policy.decide: a bucket vote under this is routed to a human
TIE_TOP_PAIRS = 3              # how many tied pairs the pile is broken down into
TAXONOMY_FIT_SHARE = 0.5       # if this share of the pile sits in TIE_TOP_PAIRS pairs, the buckets overlap
HOT_FOLDER_RATIO = 1.5         # a folder's pile share at or above this multiple of the vault's is hot
HOT_FOLDER_MIN_NOTES = 20      # ... provided the folder has at least this many judged notes
SKEW_RATIO = 1.5               # truncated / short notes are a cause when their pile share is this multiple of their overall share
SKEW_MIN_NOTES = 10            # ... and at least this many pile notes carry the trait
SHORT_NOTE_WORDS = 50          # a note under this many words is "short"
DOMINANT_SHARE = 0.5           # a bucket holding more than this share of judged notes is dominant
DOMINANT_COVER = 0.8           # the folders that together hold this share of the dominant bucket
LINKLESS_SHARE = 0.05          # index.py: under this share of notes linking out, is_orphan is unknown
SPOT_CHECK_N = 20              # confident notes to spot-check instead of trusting the floor
CLONED_SHARE = 0.95            # at or above this share of 0-day mtime ages, the copy was just cloned or copied
OVERLAP_SHARE = 0.5            # two next-scan actions sharing this share of their notes are said to overlap
NOISE_FLOOR = "two identical live runs on a 1,974-note measured test corpus: buckets agreed on 1,974 of 1,974; bucket confidence moved by a median 0.01, p90 0.03, at most 0.10"
DEFAULT_FINGERPRINT = taxonomy_fingerprint(DEFAULT_TAXONOMY)
DEFAULT_QUESTION_CHARS = taxonomy_chars(load_taxonomy(None))  # the default taxonomy's serialized questions, sent with every call ON THAT FILE
# The question characters of a run come from its rows (`question_chars`, recorded since 0.5.2); a
# saved run without the field gets the default file's size only when its fingerprint is the
# default's, and otherwise the measured ratio is reported as unavailable, not computed on the
# wrong taxonomy (through 0.5.1 a constant 2,086 was used for every run, --taxonomy runs included).
MAX_USD_STEP = 0.50            # the --max-usd suggestion is rounded up to this
EXCERPT_DOUBLE = 2             # the truncation what-if doubles the cap
TAXONOMY_FILE = DEFAULT_TAXONOMY  # sentences are quoted only when the run's fingerprint is this file's


def default_fingerprint() -> str:
    return taxonomy_fingerprint(DEFAULT_TAXONOMY)

BUCKET_BLURB = {
    "durable_memory": "standing fact, still true next month",
    "project_decision": "a dated choice future work must honor",
    "code_note": "implementation, command, schema, benchmark",
    "reference": "third-party docs, quotes, links",
    "log_entry": "a dated run report or snapshot",
    "ephemeral": "scratch, chat debris, a mood",
    "junk": "empty, boilerplate, noise",
    "needs_review": "not enough signal — a human should look",
}
ALL_BUCKETS = list(BUCKET_BLURB)

PERSIST_WORD = {0: "drop", 1: "park", 2: "promote"}


# ---- small helpers ---------------------------------------------------------------------------

def persist_label(v):
    if v is None:
        return "—"
    lo = int(v)
    hi = min(lo + 1, 2)
    frac = v - lo
    if frac < 0.15:
        return PERSIST_WORD[lo]
    if frac > 0.85:
        return PERSIST_WORD[hi]
    lean = PERSIST_WORD[lo] if frac < 0.5 else PERSIST_WORD[hi]
    return f"{PERSIST_WORD[lo]}–{PERSIST_WORD[hi]}, leaning {lean}"


def esc(s):
    return html.escape(str(s if s is not None else ""))


def flag_amount(x):
    """A dollar amount as a flag VALUE (`--max-usd 3.00`): a bare number, not a money print, which
    is why it does not go through usd(). It is already rounded up to MAX_USD_STEP, so two
    decimals are exact."""
    return f"{x:.2f}"


def n_notes(n):
    """"1 note", "27 notes": the committed demo page once read "(1 notes)"."""
    return f"{n:,} note" + ("" if n == 1 else "s")


def pct(n, d):
    return (n / d * 100) if d else 0.0


def folder_of(path):
    path = (path or "").replace("\\", "/")
    return path.rsplit("/", 1)[0] if "/" in path else "."


def top_folder_of(path):
    path = (path or "").replace("\\", "/")
    return path.split("/", 1)[0] if "/" in path else "."


def ordered_probs(r):
    probs = r.get("bucket_probabilities") or {}
    return sorted(probs.items(), key=lambda kv: -kv[1])


def runner_up(r):
    ordered = ordered_probs(r)
    if len(ordered) < 2:
        return "no contender"
    return f"{ordered[1][0]} at {ordered[1][1]:.2f}"


def tokens_for(chars, ratio):
    return int(math.ceil(chars / ratio))


def cost_for_chars(chars):
    """(pessimistic, optimistic) USD for a payload, the bill's own range."""
    return (tokens_for(chars, CHARS_PER_TOKEN_LOW) / 1e6 * PRICE_PER_MILLION_USD,
            tokens_for(chars, CHARS_PER_TOKEN_HIGH) / 1e6 * PRICE_PER_MILLION_USD)


MATCHER_SOURCE = "janitor.redact.segment_matches"  # the matcher the scan uses, never a copy


def withheld_by(folder, names):
    """Would the recorded sensitive list already withhold this folder? (Any segment of its path matches any name.)"""
    return any(segment_matches(seg, part) for seg in folder.split("/") for part in names)


def load_journal_header(journal_path):
    """The first line of a run's journal: it records the --sensitive-paths the run used, which run.json does not."""
    with open(journal_path, encoding="utf-8-sig") as fh:
        head = json.loads(fh.readline())
    return head if isinstance(head, dict) else {}


def find_journal(run_json_path):
    """The newest journal next to run.json (``journal*/run-*.jsonl``), or None."""
    base = Path(run_json_path).resolve().parent
    candidates = sorted(base.glob("journal*/run-*.jsonl"), key=lambda q: q.name)
    return candidates[-1] if candidates else None


def exclusion(folders_in_run, folder, base=DEFAULT_SENSITIVE):
    """The exact, SAFE --sensitive-paths flag that withholds ``folder``, and its collateral.

    --sensitive-paths REPLACES the list the run used, so the flag is always <the run's recorded
    list> + <the new name>: a bare `--sensitive-paths <name>` would drop every name the owner
    already passes and send the folders they protect. ``base`` is the recorded list from the
    journal header when one is available, else the five defaults. The new name is the folder's
    own last segment; it matches as whole words anywhere in the vault, not one path, so the
    OTHER folders it would withhold are counted over this run's paths, leaving out the folders
    ``base`` already withholds (they are not new).
    """
    name = folder.rsplit("/", 1)[-1] if folder != "." else folder
    names = list(dict.fromkeys(list(base) + [name]))
    flag = "--sensitive-paths " + ",".join(names)
    others = sorted({f for f in folders_in_run
                     if f != folder and not f.startswith(folder + "/")
                     and not withheld_by(f, base)
                     and any(segment_matches(seg, name) for seg in f.split("/"))})
    return {"name": name, "flag": flag, "others": others}


def exclusion_set(folders_in_run, targets, base=DEFAULT_SENSITIVE):
    """For several target folders at once: the names that withhold ONLY targets (safe), the names
    that would also withhold other folders (unsafe, with their collateral), and the one flag
    that excludes every safe target on top of the run's recorded list. Excluding a target's
    subfolders is intended, not collateral; so is another target, or a folder ``base`` already
    withholds."""
    targets = list(dict.fromkeys(targets))
    inside = lambda f: any(f == tg or f.startswith(tg + "/") for tg in targets)
    safe, unsafe = [], []
    for tg in targets:
        name = tg.rsplit("/", 1)[-1] if tg != "." else tg
        others = sorted({f for f in folders_in_run if not inside(f) and not withheld_by(f, base)
                         and any(segment_matches(seg, name) for seg in f.split("/"))})
        (safe if not others else unsafe).append({"folder": tg, "name": name, "others": others})
    names = [n for n in dict.fromkeys(s["name"] for s in safe) if n not in base]
    flag = ("--sensitive-paths " + ",".join(list(base) + names)) if names else None
    return {"safe": safe, "unsafe": unsafe, "flag": flag}


def list_note(D):
    """Where the names before the new ones came from, next to every printed flag."""
    if D["sensitive_list_known"]:
        return f"the {len(D['sensitive_list'])} names before it are the list this run actually used, read from {esc(D['sensitive_list_source'])}, because the flag replaces the list rather than extending it"
    return ("<strong>the five names before it are the defaults, not necessarily your list:</strong> no journal for this run was found, and the flag replaces the list rather than extending it, "
            "so if you pass any other names today, add them or they will be sent on the next scan")


def load_taxonomy_sentences(fingerprint):
    """The bucket sentences of the default taxonomy file, quoted only when the run's
    fingerprint says these are the words that produced the votes."""
    if fingerprint != default_fingerprint() or not TAXONOMY_FILE.exists():
        return {}
    text = TAXONOMY_FILE.read_text(encoding="utf-8")
    m = re.search(r"\n    options:\n((?:      \w+: .*\n)+)", text)
    if not m:
        return {}
    out = {}
    for line in m.group(1).splitlines():
        name, _, sentence = line.strip().partition(": ")
        out[name] = sentence.strip()
    return out


# ---- the diagnosis: everything the report says, computed once from the rows -----------------

def diagnose(rows, *, floor=REVIEW_FLOOR, journal_header=None, sensitive_list=None, sensitive_source=None):
    """Compute every number the report states. Returns a plain dict so tests can pin it.

    ``sensitive_list`` is the list the run actually used, passed straight from the CLI; a
    saved run passes its journal header instead (``journal_header``, whose ``sensitive_parts``
    is that list). Every exclusion flag is built on it."""
    votes = [r for r in rows if r.get("kind", "vote" if "bucket" in r else "") == "vote" and "bucket" in r]
    skips = [r for r in rows if r.get("kind") == "skip" or ("kind" not in r and "bucket" not in r and "skipped" in r)]
    errors = [r for r in rows if r.get("kind") == "error" or r.get("action") == "error"]
    judged = [r for r in votes if r.get("judge", "jev") != "local"]
    local = [r for r in votes if r.get("judge") == "local"]
    n_judged = len(judged)

    pile = sorted([r for r in judged if (r.get("confidence") or 0) < floor], key=lambda r: r.get("confidence") or 0)
    rest = [r for r in judged if (r.get("confidence") or 0) >= floor]
    pile_ids = {id(r) for r in pile}
    D = {
        "n_rows": len(rows), "n_votes": len(votes), "n_judged": n_judged, "n_local": len(local),
        "n_withheld": len(skips), "n_errors": len(errors), "floor": floor,
        "n_pile": len(pile), "pile_pct": pct(len(pile), n_judged),
        "model": next((r.get("model") for r in judged if r.get("model")), "—"),
        "taxonomy": next((r.get("taxonomy") for r in votes if r.get("taxonomy")), "—"),
        "offline": next((r.get("model") for r in judged if r.get("model")), "") == "fixture",
        "applied": any(r.get("applied") for r in votes),
    }
    D["sentences"] = load_taxonomy_sentences(D["taxonomy"])

    # -- margins: the pile is where the top two buckets sat close together
    margins = lambda rs: [r.get("bucket_margin") if r.get("bucket_margin") is not None else 0.0 for r in rs]
    D["median_margin_pile"] = statistics.median(margins(pile)) if pile else None
    D["median_margin_rest"] = statistics.median(margins(rest)) if rest else None
    confs = [r.get("confidence") for r in judged if r.get("confidence") is not None and r.get("bucket_probabilities")]
    diffs = [abs(r["confidence"] - max(r["bucket_probabilities"].values())) for r in judged
             if r.get("confidence") is not None and r.get("bucket_probabilities")]
    D["median_conf_top_diff"] = statistics.median(diffs) if diffs else None

    # -- cause 1: two-bucket ties
    # `needs_review` is Jev abstaining, not a category: a split with it on either side is not two
    # overlapping sentences and gets the needs_review fix below, never merge advice.
    pairs = Counter()
    pair_of = {}
    for r in pile:
        ordered = ordered_probs(r)
        if len(ordered) >= 2 and "needs_review" not in (ordered[0][0], ordered[1][0]):
            pair = tuple(sorted((ordered[0][0], ordered[1][0])))
            pairs[pair] += 1
            pair_of[id(r)] = pair
    D["tie_pairs"] = pairs.most_common(TIE_TOP_PAIRS)
    D["tie_top_share"] = pct(sum(n for _, n in D["tie_pairs"]), len(pile))
    D["taxonomy_overlap"] = bool(pile) and D["tie_top_share"] >= TAXONOMY_FIT_SHARE * 100

    # -- merge what-if for each real pair: an ESTIMATE that assumes Jev splits its vote the same
    # way under the edited taxonomy. Merging A and B adds their probabilities; a note clears when
    # the merged top probability reaches the floor. It is not a bound in either direction: a
    # taxonomy edit changes every vote, and only a rerun says what it does.
    whatif = []
    for (a, b), n_pair in D["tie_pairs"]:
        cleared = 0
        clears_ids = set()
        for r in pile:
            probs = dict(r.get("bucket_probabilities") or {})
            if a in probs and b in probs:
                merged = probs[a] + probs[b]
                probs[a] = merged
                del probs[b]
            if probs and max(probs.values()) >= floor:
                cleared += 1
                clears_ids.add(id(r))
        whatif.append({"pair": (a, b), "tied": n_pair, "clears": cleared, "covers": clears_ids})
    D["merge_whatif"] = sorted(whatif, key=lambda w: -w["clears"])
    D["best_merge"] = D["merge_whatif"][0] if D["merge_whatif"] else None

    # -- cause 2: needs_review pull
    nr_explicit = [r for r in pile if r.get("bucket") == "needs_review"]
    nr_runner = [r for r in pile if len(ordered_probs(r)) >= 2 and ordered_probs(r)[1][0] == "needs_review" and r.get("bucket") != "needs_review"]
    D["needs_review_explicit"] = len(nr_explicit)
    D["needs_review_runner_up"] = len(nr_runner)
    D["needs_review_pull"] = len(nr_explicit) + len(nr_runner)
    D["needs_review_pull_pct"] = pct(D["needs_review_pull"], len(pile))

    # -- cause 3: hot folders (pile share >= HOT_FOLDER_RATIO x the vault's, n >= HOT_FOLDER_MIN_NOTES)
    per_folder_judged = Counter(folder_of(r["path"]) for r in judged)
    per_folder_pile = Counter(folder_of(r["path"]) for r in pile)
    per_folder_tokens = Counter()
    for r in judged:
        per_folder_tokens[folder_of(r["path"])] += r.get("input_tokens") or 0
    vault_share = len(pile) / n_judged if n_judged else 0.0
    hot = []
    for folder, n in per_folder_judged.items():
        if n < HOT_FOLDER_MIN_NOTES:
            continue
        share = per_folder_pile[folder] / n
        if vault_share and share >= HOT_FOLDER_RATIO * vault_share:
            hot.append({"folder": folder, "judged": n, "pile": per_folder_pile[folder], "share": share,
                        "tokens": per_folder_tokens[folder], "usd": per_folder_tokens[folder] / 1e6 * PRICE_PER_MILLION_USD})
    hot.sort(key=lambda h: (-h["share"], -h["pile"]))
    # every folder this run saw, judged, local or withheld: the collateral of a name exclusion is counted over these
    all_folders = {folder_of(r["path"]) for r in votes + skips if r.get("path")}
    D["all_folders"] = all_folders
    # run.json does not record the --sensitive-paths the run used; the journal header does. With
    # the header, every flag is built on that list; without it, on the five defaults, and the
    # report says so prominently.
    recorded = list(sensitive_list) if sensitive_list else (journal_header or {}).get("sensitive_parts")
    if isinstance(recorded, list) and all(isinstance(x, str) for x in recorded) and recorded:
        D["sensitive_list"] = [x.strip() for x in recorded if x.strip()]
        if sensitive_list:
            D["sensitive_list_source"] = sensitive_source or f"this run's --sensitive-paths ({len(D['sensitive_list'])} names)"
        else:
            D["sensitive_list_source"] = f"the run's journal header ({len(D['sensitive_list'])} names, run {(journal_header or {}).get('run', '?')})"
        D["sensitive_list_known"] = True
    else:
        D["sensitive_list"] = list(DEFAULT_SENSITIVE)
        D["sensitive_list_source"] = "the five defaults, because no journal for this run was found"
        D["sensitive_list_known"] = False
    D["matcher_source"] = MATCHER_SOURCE
    base = D["sensitive_list"]
    D["hot_exclusion"] = exclusion_set(all_folders, [h["folder"] for h in hot], base)
    for h in hot:
        h["exclude"] = exclusion(all_folders, h["folder"], base)
        h["exclude"]["safe"] = not h["exclude"]["others"]
        # which sentences compete THERE: the most common real tie pair among its pile rows, or Jev abstaining
        in_folder = [r for r in pile if folder_of(r["path"]) == h["folder"]]
        pairs_here = Counter(pair_of[id(r)] for r in in_folder if id(r) in pair_of)
        nr_here = sum(1 for r in in_folder if r.get("bucket") == "needs_review" or (len(ordered_probs(r)) >= 2 and ordered_probs(r)[1][0] == "needs_review"))
        top_pair = pairs_here.most_common(1)[0] if pairs_here else None
        if top_pair and top_pair[1] >= nr_here:
            h["competes"] = {"kind": "tie", "pair": top_pair[0], "n": top_pair[1]}
        elif nr_here:
            h["competes"] = {"kind": "needs_review", "n": nr_here}
        else:
            h["competes"] = None
    D["hot_folders"] = hot
    D["hot_folder_pile_notes"] = sum(h["pile"] for h in hot)
    D["vault_pile_share"] = vault_share
    hot_set = {h["folder"] for h in hot}
    biggest = per_folder_judged.most_common(1)
    D["biggest_folder"] = None
    if biggest:
        f, n = biggest[0]
        D["biggest_folder"] = {"folder": f, "judged": n, "pile": per_folder_pile[f], "share": per_folder_pile[f] / n if n else 0.0,
                               "rest_share": (len(pile) - per_folder_pile[f]) / (n_judged - n) if n_judged - n else 0.0}

    # -- cause 4: truncation over-represented in the pile
    trunc_pile = sum(1 for r in pile if r.get("truncated"))
    trunc_all = sum(1 for r in judged if r.get("truncated"))
    D["trunc_pile"], D["trunc_all"] = trunc_pile, trunc_all
    D["trunc_pile_pct"], D["trunc_all_pct"] = pct(trunc_pile, len(pile)), pct(trunc_all, n_judged)
    D["truncation_cause"] = trunc_pile >= SKEW_MIN_NOTES and D["trunc_all_pct"] > 0 and D["trunc_pile_pct"] >= SKEW_RATIO * D["trunc_all_pct"]
    trunc_rows = [r for r in judged if r.get("truncated")]
    cap = max((r.get("excerpt_chars") or 0 for r in trunc_rows), default=0)
    D["excerpt_cap"] = cap
    # the bill delta if the cap doubles, an estimate over EVERY truncated note in the vault (not only
    # the pile's): each could send up to another cap of characters
    D["trunc_all_notes"] = len(trunc_rows)
    D["trunc_new_cap"] = cap * EXCERPT_DOUBLE
    extra_chars = len(trunc_rows) * cap * (EXCERPT_DOUBLE - 1)
    D["trunc_double_cap_usd"] = cost_for_chars(extra_chars)

    # -- cause 5: short notes over-represented in the pile
    words = lambda r: ((r.get("graph") or {}).get("words"))
    short_pile = sum(1 for r in pile if words(r) is not None and words(r) < SHORT_NOTE_WORDS)
    short_all = sum(1 for r in judged if words(r) is not None and words(r) < SHORT_NOTE_WORDS)
    D["short_pile"], D["short_all"] = short_pile, short_all
    D["short_pile_pct"], D["short_all_pct"] = pct(short_pile, len(pile)), pct(short_all, n_judged)
    D["short_cause"] = short_pile >= SKEW_MIN_NOTES and D["short_all_pct"] > 0 and D["short_pile_pct"] >= SKEW_RATIO * D["short_all_pct"]

    # -- per-row causes, for the pile table
    top_pairs = {p for p, _ in D["tie_pairs"]}
    causes = {}
    for r in pile:
        c = []
        p = pair_of.get(id(r))
        if p in top_pairs:
            c.append(f"tie {p[0]}–{p[1]}")
        if r.get("bucket") == "needs_review" or (len(ordered_probs(r)) >= 2 and ordered_probs(r)[1][0] == "needs_review"):
            c.append("needs_review pull")
        if folder_of(r["path"]) in hot_set:
            c.append("hot folder")
        if r.get("truncated") and D["truncation_cause"]:
            c.append("truncated")
        if words(r) is not None and words(r) < SHORT_NOTE_WORDS and D["short_cause"]:
            c.append("short")
        causes[id(r)] = c or ["unexplained"]
    D["pile"] = pile
    D["causes"] = causes
    D["pile_no_cause"] = sum(1 for r in pile if causes[id(r)] == ["unexplained"])

    # -- the question characters each call carried (see DEFAULT_QUESTION_CHARS)
    def question_size(r):
        q = r.get("question_chars")
        if isinstance(q, int) and q > 0:
            return q
        return DEFAULT_QUESTION_CHARS if r.get("taxonomy") == DEFAULT_FINGERPRINT else None
    sent_rows = [r for r in judged if not r.get("cached")]
    sizes = [question_size(r) for r in sent_rows]
    D["question_chars_known"] = bool(sent_rows) and all(s is not None for s in sizes)
    D["question_chars_total"] = sum(s for s in sizes if s) if D["question_chars_known"] else None
    D["question_chars_per_call"] = round(D["question_chars_total"] / len(sent_rows)) if D["question_chars_known"] else None
    if not sent_rows:
        D["question_chars_source"] = None
    elif all(isinstance(r.get("question_chars"), int) and r["question_chars"] > 0 for r in sent_rows):
        D["question_chars_source"] = "recorded on each row"
    elif D["question_chars_known"]:
        D["question_chars_source"] = FALLBACK_SOURCE
    else:
        D["question_chars_source"] = None
    qc = D["question_chars_per_call"] or 0
    D["state_version"] = (journal_header or {}).get("state_version")

    # -- the cost of a confirming rerun of the pile alone
    pile_chars = sum(r.get("payload_chars") or 0 for r in pile) + qc * len(pile)
    D["pile_rerun_usd"] = cost_for_chars(pile_chars)
    pile_tokens = sum(r.get("input_tokens") or 0 for r in pile)
    D["pile_rerun_measured_usd"] = pile_tokens / 1e6 * PRICE_PER_MILLION_USD if pile_tokens else None
    # A taxonomy edit changes the fingerprint, so every cache key misses and the next scan is the
    # whole vault at full price; the pile-only figure is what a pile-only rescan WOULD cost, and
    # no such flag exists (logged, not built).
    all_tokens = sum(r.get("input_tokens") or 0 for r in judged)
    D["full_rescan_usd"] = all_tokens / 1e6 * PRICE_PER_MILLION_USD

    # -- C: where the notes landed
    counts = Counter(r.get("bucket") for r in judged)
    D["bucket_counts"] = counts
    D["unused_buckets"] = [b for b in ALL_BUCKETS if counts.get(b, 0) == 0]
    # how often an unused bucket was the runner-up in the pile: close but losing, or absent
    D["unused_runner_up"] = {b: sum(1 for r in pile if len(ordered_probs(r)) >= 2 and ordered_probs(r)[1][0] == b) for b in D["unused_buckets"]}
    D["dominant"] = None
    if counts:
        b, n = counts.most_common(1)[0]
        if n_judged and n / n_judged > DOMINANT_SHARE:
            by_folder = Counter(folder_of(r["path"]) for r in judged if r.get("bucket") == b)
            cover, acc = [], 0
            for f, k in by_folder.most_common():
                cover.append((f, k))
                acc += k
                if acc >= DOMINANT_COVER * n:
                    break
            cover_set = {f for f, _ in cover}
            cover_rows = [r for r in judged if folder_of(r["path"]) in cover_set]
            cover_tokens = sum(r.get("input_tokens") or 0 for r in cover_rows)
            D["dominant"] = {"bucket": b, "n": n, "share": n / n_judged, "folders": cover, "cover_notes": len(cover_rows),
                             "cover_tokens": cover_tokens, "cover_usd": cover_tokens / 1e6 * PRICE_PER_MILLION_USD,
                             "cover_chars": sum(r.get("payload_chars") or 0 for r in cover_rows)}
            all_f = {folder_of(r["path"]) for r in votes + skips if r.get("path")}
            D["dominant"]["exclusion"] = exclusion_set(all_f, [f for f, _ in cover], D["sensitive_list"])

    # -- D: the membrane
    D["withheld_by_reason"] = Counter(r.get("skipped") or r.get("reason") or r.get("action") for r in skips)
    D["hits_by_label"] = Counter(k for r in votes for k in (r.get("redacted") or []))
    D["own_hits_by_label"] = Counter(k for r in votes for k in (r.get("redacted_own") or []))
    quarantined = [r for r in votes if r.get("action") == "quarantine"]
    D["quarantined"] = quarantined
    D["quarantine_by_trigger"] = Counter(t for r in quarantined for t in (r.get("quarantine_triggers") or ["(unstated)"]))
    D["quarantine_local"] = [r for r in quarantined if any(str(t).startswith("local:") for t in (r.get("quarantine_triggers") or []))]
    D["quarantine_vote"] = [r for r in quarantined if r not in D["quarantine_local"]]
    D["n_redacted_notes"] = sum(1 for r in votes if r.get("redacted"))
    D["n_dupes"] = sum(1 for r in votes if r.get("exact_duplicate_of"))
    # "exact duplicate of <path>: decided locally" collapses to its kind; the path stays out of the count.
    D["local_by_reason"] = Counter(re.sub(r"^(exact duplicate) of .*$", r"\1", (r.get("reason") or "").split(":")[0]) for r in local)

    # -- E: errors
    D["errors_by_class"] = Counter(r.get("error") or "unknown" for r in errors)
    D["error_rows"] = errors

    # -- F: cost and measurement
    tokens = sum(r.get("input_tokens") or 0 for r in judged if not r.get("cached"))
    sent_n = sum(1 for r in judged if not r.get("cached"))
    payload = sum(r.get("payload_chars") or 0 for r in judged if not r.get("cached"))
    D["input_tokens"], D["n_sent"], D["payload_chars"] = tokens, sent_n, payload
    D["cost_usd"] = tokens / 1e6 * PRICE_PER_MILLION_USD
    known = D["question_chars_known"]
    D["measured_ratio"] = ((payload + D["question_chars_total"]) / tokens) if tokens and known else None
    D["estimate_usd"] = cost_for_chars(payload + D["question_chars_total"]) if sent_n and known else (0.0, 0.0)
    D["ratio_verdict"] = None
    if D["measured_ratio"] is not None:
        if D["measured_ratio"] < CHARS_PER_TOKEN_LOW:
            D["ratio_verdict"] = "below"
        elif D["measured_ratio"] > CHARS_PER_TOKEN_HIGH:
            D["ratio_verdict"] = "above"
        else:
            D["ratio_verdict"] = "inside"
    worst = max(D["estimate_usd"][0], D["cost_usd"])
    D["suggested_max_usd"] = math.ceil(worst / MAX_USD_STEP) * MAX_USD_STEP if worst else 0.0

    # -- G: graph and age
    graph_rows = [r for r in judged if isinstance(r.get("graph"), dict)]
    linking = sum(1 for r in graph_rows if (r["graph"].get("out_links") or 0) > 0)
    D["linking_share"] = linking / len(graph_rows) if graph_rows else None
    D["orphan_unknown"] = D["linking_share"] is not None and D["linking_share"] < LINKLESS_SHARE
    D["orphans"] = sum(1 for r in graph_rows if r["graph"].get("is_orphan") is True)
    D["age_sources"] = Counter(r.get("age_source") or "unknown" for r in judged)
    D["age_mtime_share"] = D["age_sources"].get("mtime", 0) / n_judged if n_judged else 0.0
    ages = [r["graph"].get("age_days") for r in graph_rows if r["graph"].get("age_days") is not None]
    D["age_zero_share"] = (sum(1 for a in ages if a == 0) / len(ages)) if ages else 0.0
    D["just_cloned"] = bool(ages) and D["age_mtime_share"] >= CLONED_SHARE and D["age_zero_share"] >= CLONED_SHARE

    # -- H: next scan, ordered by estimated impact
    actions = []
    full = f"the next scan is the whole vault at full price, {usd(D['full_rescan_usd'])} at this run's measured rate, because a taxonomy edit changes the fingerprint and every cache key misses"
    if D["best_merge"] and D["best_merge"]["clears"]:
        a, b = D["best_merge"]["pair"]
        actions.append({"impact": D["best_merge"]["clears"], "unit": "notes that would clear if the split holds (estimate)", "covers": D["best_merge"]["covers"],
                        "why": f"{D['best_merge']['clears']} notes would clear if the split holds, an estimate",
                        "what": f"Edit the taxonomy so `{a}` and `{b}` say how they differ, or merge them.",
                        "cost": full})
    if D["needs_review_pull"]:
        nr_ids = {id(r) for r in pile if r.get("bucket") == "needs_review" or (len(ordered_probs(r)) >= 2 and ordered_probs(r)[1][0] == "needs_review")}
        actions.append({"impact": D["needs_review_pull"], "unit": "pile notes with needs_review on top or runner-up", "covers": nr_ids,
                        "why": f"{D['needs_review_pull']} pile notes have needs_review on top or as runner-up",
                        "what": "Reword the `needs_review` sentence in the taxonomy so it is a last resort, not a peer of the other buckets.",
                        "cost": full})
    if D["dominant"]:
        d = D["dominant"]
        actions.append({"impact": d["cover_usd"], "unit": "dollars per scan (measured)", "dollars": True, "covers": set(),
                        "why": f"{usd(d['cover_usd'])} of every scan goes to those folders, measured",
                        "what": f"If the {len(d['folders'])} folder(s) holding {DOMINANT_COVER:.0%} of `{d['bucket']}` are machine-generated, exclude them"
                                + (f": <code>{esc(d['exclusion']['flag'])}</code> withholds {len(d['exclusion']['safe'])} of them with no other folder affected ({list_note(D)})" if d["exclusion"]["flag"] else "")
                                + (f"; the other {len(d['exclusion']['unsafe'])} share their name with other folders and cannot be singled out by <code>--sensitive-paths</code>" if d["exclusion"]["unsafe"] else "")
                                + ". If they are your own writing, leave them in.",
                        "short": f"If the {len(d['folders'])} folder(s) holding {DOMINANT_COVER:.0%} of `{d['bucket']}` are machine-generated, exclude them; the flag and its collateral are in the landed section.",
                        "cost": "free; the next report is then about the notes you wrote"})
    if hot:
        worst = ", ".join(f"`{h['folder']}` {h['pile']}/{h['judged']}" for h in hot[:3])
        hx = D["hot_exclusion"]
        if hx["flag"]:
            by_name = (f"{len(hx['safe'])} of them can be withheld by name with no other folder affected: <code>{esc(hx['flag'])}</code> "
                       f"({list_note(D)})")
        else:
            by_name = "none of them can be withheld by name without also withholding other folders"
        if hx["unsafe"]:
            by_name += (f"; the other {len(hx['unsafe'])} share their name with {sum(len(u['others']) for u in hx['unsafe'])} other folder(s) in this run, so <code>--sensitive-paths</code> cannot single them out, and the separate scan or the sentence edit is the route for those")
        actions.append({"impact": D["hot_folder_pile_notes"], "unit": "pile notes in hot folders", "covers": {id(r) for r in pile if folder_of(r["path"]) in hot_set},
                        "why": f"{D['hot_folder_pile_notes']} pile notes sit in the hot folders",
                        "what": f"For each of the {len(hot)} hot folder(s) (the worst: {worst}" + (f", and {len(hot) - 3} more in the pile section" if len(hot) > 3 else "") + "): "
                                f"if it is machine-generated, exclude it; if it is your own writing, the taxonomy has no bucket that fits it, so edit the competing sentences named in the pile section or scan it separately with <code>jev-janitor &lt;vault&gt;/&lt;folder&gt; --taxonomy FILE</code>. "
                                f"Exclusion by name: {by_name}.",
                        "short": f"Sort the {len(hot)} hot folder(s): machine-generated ones out by name ({len(hx['safe'])} can be, with no other folder affected), your own writing to the competing sentences; the flags and their collateral are in the pile section.",
                        "cost": f"{usd(sum(h['usd'] for h in hot))} of this scan was these folders (measured)"})
    if D["truncation_cause"]:
        actions.append({"impact": trunc_pile, "unit": "truncated pile notes", "covers": {id(r) for r in pile if r.get("truncated")},
                        "why": f"{trunc_pile} pile notes were cut at the excerpt cap",
                        "what": f"Raise --excerpt-chars above {cap:,} for the next scan; {trunc_pile} pile notes were cut there against {D['trunc_all_pct']:.0f}% overall.",
                        "cost": f"if the cap doubles to {D['trunc_new_cap']:,}: about {usd(D['trunc_double_cap_usd'][1])} to {usd(D['trunc_double_cap_usd'][0])} more per scan (estimate), across all {D['trunc_all_notes']:,} truncated notes in the vault, not only the pile's"})
    if D["short_cause"]:
        actions.append({"impact": short_pile, "unit": "short pile notes", "covers": {id(r) for r in pile if words(r) is not None and words(r) < SHORT_NOTE_WORDS},
                        "why": f"{short_pile} pile notes are under {SHORT_NOTE_WORDS} words",
                        "what": f"Notes under {SHORT_NOTE_WORDS} words carry little signal: accept them as the pile's floor, or give them a `created:`-style frontmatter tag you can filter on yourself.",
                        "cost": "free"})
    if D["errors_by_class"]:
        actions.append({"impact": len(errors), "unit": "errored notes", "why": f"{len(errors)} notes errored",
                        "what": "Run again with --resume: errored notes are retried; persistent ones stay held.",
                        "cost": (f"about {usd(cost_for_chars(qc * len(errors))[0])} for the questions alone, plus their payload (estimate)" if qc
                                 else "their payload plus the questions (this run's question size is not recorded, so no figure)")})
    if D["orphan_unknown"]:
        actions.append({"impact": 0, "unit": "", "what": "Orphan status is unknown on a vault that barely links; nothing to do unless you add links.", "cost": "free"})
    if D["age_mtime_share"] > 0.5:
        actions.append({"impact": 0, "unit": "", "what": f"Add `created:` frontmatter: {D['age_mtime_share']:.0%} of ages came from file mtimes, which reset when a vault is moved or re-synced.", "cost": "free"})
    if D["pile_no_cause"]:
        actions.append({"impact": 0, "unit": "", "covers": {id(r) for r in pile if causes[id(r)] == ["unexplained"]},
                        "what": f"Spot-check the {D['pile_no_cause']} pile notes no rule explains: if they share a folder or a shape, that is the next rule.", "cost": "free"})
    actions.sort(key=lambda a: -(a["impact"] * (100 if a.get("dollars") else 1)))
    # Two actions that share most of their notes are one fix seen twice; say so, and never let
    # the impacts read as clearing more notes than the pile holds.
    seen = set()
    for a in actions:
        cov = a.get("covers") or set()
        shared = len(cov & seen)
        a["shared"] = shared
        a["overlaps"] = bool(cov) and shared >= OVERLAP_SHARE * len(cov)
        seen |= cov
    D["next_scan"] = actions
    D["next_scan_distinct"] = len(seen)
    return D


# ---- rendering -------------------------------------------------------------------------------

def bar_rows(counts, total):
    out = []
    top = max(counts.values()) if counts else 1
    for bucket, n in counts.most_common():
        p = pct(n, total)
        out.append(f"""
      <div class="barrow" title="{esc(bucket)}: {n} of {total} notes ({p:.0f}%)">
        <div class="barlabel"><span class="bname">{esc(bucket)}</span><span class="bnote">{esc(BUCKET_BLURB.get(bucket, ''))}</span></div>
        <div class="bartrack"><div class="barfill" style="width:{n / top * 100:.2f}%"></div></div>
        <div class="barval">{n}</div>
      </div>""")
    return "".join(out)


def conf_cell(conf):
    if conf is None:
        return '<td class="num">—</td>'
    low = conf < REVIEW_FLOOR
    cls = "cbar low" if low else "cbar"
    return (
        f'<td class="num conf"><span class="cnum">{conf:.2f}</span>'
        f'<span class="ctrack"><span class="{cls}" style="width:{conf * 100:.1f}%"></span></span></td>'
    )


def flags(r):
    out = []
    if r.get("action") == "quarantine":
        out.append('<span class="chip small crit">quarantine</span>')
    if r.get("redacted"):
        out.append(f'<span class="chip small warn">{esc(", ".join("[" + k + "]" for k in r["redacted"]))}</span>')
    if r.get("exact_duplicate_of"):
        out.append(f'<span class="chip small">dup of {esc(r["exact_duplicate_of"])}</span>')
    if (r.get("contains_secret") or 0) >= 0.5 and r.get("action") != "quarantine":
        out.append('<span class="chip small warn">secret?</span>')
    return " ".join(out) or '<span class="muted">—</span>'


def explain(shows, found, why, can_do, better):
    """The five-part block every section carries."""
    parts = [("What this shows", shows), ("What we found in your vault", found), ("Why", why),
             ("What you can do", can_do), ("What would make it better", better)]
    return '<div class="explain">' + "".join(
        f'<div class="ex"><span class="exk">{k}</span><div class="exv">{v}</div></div>' for k, v in parts if v
    ) + "</div>"


def li(items):
    return "<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>" if items else ""


def quote(D, bucket):
    s = D["sentences"].get(bucket)
    return f' <q>{esc(s)}</q>' if s else " (its sentence is in your taxonomy file; this run's fingerprint is not the default file's, so it is not quoted here)"


def section_a(D):
    dom = D["dominant"]
    lead = None
    if D["n_pile"]:
        candidates = []
        # The lead is the cause with the most pile notes. The first ACTION below is ranked by
        # estimated effect, which can name a different pair: a 5-note tie whose merge would clear
        # 17 notes outranks a 7-note tie whose merge clears fewer.
        if D["tie_pairs"]:
            (a, b), n_top = D["tie_pairs"][0]
            candidates.append((n_top, f"a tie between the categories `{a}` and `{b}` ({n_notes(n_top)})"))
        if D["needs_review_pull"]:
            # explicit votes plus runner-ups: through 0.5.5 this read "Jev abstaining into needs_review",
            # which called a runner-up a vote (the demo's one such note voted durable_memory)
            candidates.append((D["needs_review_pull"], f"`needs_review` on top or as runner-up ({n_notes(D['needs_review_pull'])})"))
        if D["hot_folders"]:
            candidates.append((D["hot_folder_pile_notes"], f"{len(D['hot_folders'])} hot folder(s) ({D['hot_folder_pile_notes']} pile notes)"))
        if D["truncation_cause"]:
            candidates.append((D["trunc_pile"], f"truncation ({D['trunc_pile']} pile notes cut at the excerpt cap)"))
        if candidates:
            lead = max(candidates)[1]
    sentences = [
        f"<strong>{D['n_votes']:,} notes</strong> got a decision: {D['n_judged']:,} judged by {esc(D['model'])}, {D['n_local']:,} decided locally, "
        f"{D['n_withheld']:,} withheld, {D['n_errors']:,} errored.",
        f"The run cost <strong>{usd(D['cost_usd'])}</strong> for {D['input_tokens']:,} input tokens" + (
            f", at {D['measured_ratio']:.2f} characters per token ({D['ratio_verdict']} the {CHARS_PER_TOKEN_LOW}–{CHARS_PER_TOKEN_HIGH} range the estimate assumes)." if D["measured_ratio"] else "."),
    ]
    if dom:
        sentences.append(f"<strong>`{dom['bucket']}` holds {dom['share']:.0%}</strong> of judged notes, and {len(dom['folders'])} folder(s) hold {DOMINANT_COVER:.0%} of it: most of this vault reads to Jev as `{dom['bucket']}` ({esc(BUCKET_BLURB.get(dom['bucket'], dom['bucket']))}).")
    elif D["bucket_counts"]:
        b, n = D["bucket_counts"].most_common(1)[0]
        sentences.append(f"The largest bucket is `{b}` at {pct(n, D['n_judged']):.0f}%; no bucket holds more than {DOMINANT_SHARE:.0%}.")
    if D["n_pile"]:
        sentences.append(f"<strong>{D['n_pile']:,} notes ({D['pile_pct']:.0f}%) need a human</strong>" + (f", led by {lead}." if lead else ", with no single cause the rules below recognise."))
    if D["next_scan"]:
        first = D["next_scan"][0]
        because = f"largest effect on the list ({first['why']})" if first.get("why") else "nothing on the list has a measured or estimated effect, so start with the free check"
        sentences.append(f"The one thing to do first, because it has the {because}: {first.get('short', first['what'])}")
    return "<section id='summary'><h2>Summary</h2><p class='lede'>" + " ".join(sentences) + "</p></section>"


def section_b(D):
    n, total = D["n_pile"], D["n_judged"]
    if not total:
        return ""
    mp = f"{D['median_margin_pile']:.2f}" if D["median_margin_pile"] is not None else "—"
    mr = f"{D['median_margin_rest']:.2f}" if D["median_margin_rest"] is not None else "—"
    shows = (f"Under {D['floor']} Jev split its vote, most often between two buckets (median gap between the top two {mp} here, "
             f"against {mr} for the rest), so a person should pick. {n:,} of {total:,} judged notes ({D['pile_pct']:.0f}%) landed here. "
             f"A confident vote is Jev's best reading, not proof: spot-check {SPOT_CHECK_N} random confident notes (listed at the end of this section) before trusting the rest.")
    found = []
    if D["tie_pairs"]:
        found.append(f"<strong>Two-bucket ties:</strong> the top {len(D['tie_pairs'])} pairs hold {D['tie_top_share']:.0f}% of the pile: " +
                     ", ".join(f"`{a}`–`{b}` {k}" for (a, b), k in D["tie_pairs"]) + ".")
    found.append(f"<strong>`needs_review` pull:</strong> {D['needs_review_explicit']} explicit votes and {D['needs_review_runner_up']} with it as runner-up, {D['needs_review_pull_pct']:.0f}% of the pile.")
    if D["hot_folders"]:
        found.append(f"<strong>Hot folders</strong> (pile share ≥ {HOT_FOLDER_RATIO}× the vault's {D['vault_pile_share']:.0%}, at least {HOT_FOLDER_MIN_NOTES} judged notes): {len(D['hot_folders'])}, holding {D['hot_folder_pile_notes']} pile notes. Worst: " +
                     ", ".join(f"<code>{esc(h['folder'])}</code> {h['pile']}/{h['judged']} ({h['share']:.0%})" for h in D["hot_folders"][:5]) + ".")
    else:
        bf = D["biggest_folder"]
        found.append(f"<strong>Hot folders:</strong> none by the {HOT_FOLDER_RATIO}× rule (at least {HOT_FOLDER_MIN_NOTES} judged notes)." +
                     (f" The biggest folder, <code>{esc(bf['folder'])}</code>, sits at {bf['share']:.0%} against {bf['rest_share']:.0%} for the rest." if bf else ""))
    found.append(f"<strong>Truncation:</strong> {D['trunc_pile_pct']:.0f}% of the pile was cut at the excerpt cap against {D['trunc_all_pct']:.0f}% of all judged notes: " +
                 ("a cause" if D["truncation_cause"] else "not a cause") + f" (rule: pile share ≥ {SKEW_RATIO}× overall and at least {SKEW_MIN_NOTES} notes).")
    found.append(f"<strong>Short notes</strong> (under {SHORT_NOTE_WORDS} words): {D['short_pile_pct']:.0f}% of the pile against {D['short_all_pct']:.0f}% overall: " +
                 ("a cause" if D["short_cause"] else "not a cause") + ".")
    found.append(f"<strong>Unexplained:</strong> {D['pile_no_cause']} pile notes match none of these rules. They are marked <em>unexplained</em> in the table below; spot-check them, because an unexplained remainder is information: if they share a folder or a shape, that is the next rule.")
    why = (f"The taxonomy fit: {'<strong>the buckets overlap for this kind of material</strong>' if D['taxonomy_overlap'] else 'the pile is spread across pairs, so no single pair of buckets is the problem'}"
           f" (rule: at least {TAXONOMY_FIT_SHARE:.0%} of the pile in the top {TIE_TOP_PAIRS} pairs; here {D['tie_top_share']:.0f}%). "
           f"A missing or overlapping bucket shows up as exactly this: a low-confidence spread between two sentences that both fit. Confidence tracks the top bucket's probability "
           f"(median gap {D['median_conf_top_diff']:.2f} here), so a note clears the floor when one sentence wins outright." if D["median_conf_top_diff"] is not None else "")
    can = []
    rerun = (f"Any taxonomy edit changes the fingerprint, so every cache key misses and the next scan is the whole vault at full price: <strong>{usd(D['full_rescan_usd'])}</strong> at this run's measured rate. "
             f"If a pile-only rescan existed (logged as <code>--only-pile</code>, not built) it would be {usd(D['pile_rerun_usd'][1])} to {usd(D['pile_rerun_usd'][0])} by the bill's range"
             + (f", {usd(D['pile_rerun_measured_usd'])} at the measured rate" if D["pile_rerun_measured_usd"] else "") + ".")
    for w in D["merge_whatif"]:
        a, b = w["pair"]
        can.append(f"<strong>Tie `{a}`–`{b}` ({w['tied']} notes):</strong> edit the two sentences in <code>janitor/taxonomies/vault_memory.yaml</code> so they say how they differ, or merge them. "
                   f"`{a}`:{quote(D, a)} `{b}`:{quote(D, b)} If Jev splits its vote the same way under the edited taxonomy, about <strong>{w['clears']} of {n}</strong> would clear (an estimate from this run's own probabilities, not a bound); only a rerun confirms it.")
    if D["needs_review_pull"]:
        can.append(f"<strong>`needs_review` on top or as runner-up ({n_notes(D['needs_review_pull'])}, {D['needs_review_explicit']} voted it outright):</strong> `needs_review` is not a category, it is Jev declining to choose, so a split with it is not two overlapping sentences. Reword the sentence so it is a last resort, not a peer of the other buckets. Today it reads:{quote(D, 'needs_review')}")
    if D["merge_whatif"] or D["needs_review_pull"]:
        can.append(f"<strong>The cost of any taxonomy edit:</strong> {rerun}")
    for h in D["hot_folders"]:
        ex = h["exclude"]
        c = h.get("competes")
        if c and c["kind"] == "tie":
            competes = f"What competes there: `{c['pair'][0]}` against `{c['pair'][1]}` in {c['n']} of its {h['pile']} pile notes."
        elif c:
            competes = f"What competes there: `needs_review` on top or as runner-up in {c['n']} of its {h['pile']} pile notes."
        else:
            competes = "No single pair competes there."
        if ex["safe"]:
            how = (f"If this folder is machine-generated, exclude it: <code>{esc(ex['flag'])}</code>; {list_note(D)}. "
                   f"A name matches as whole words anywhere in the vault, not one path; <code>{esc(ex['name'])}</code> matches no other folder in this run that the list does not already withhold.")
        else:
            how = (f"If this folder is machine-generated, it still cannot be withheld by name: <code>--sensitive-paths</code> matches a folder name as whole words anywhere in the vault, and <code>{esc(ex['name'])}</code> also matches {len(ex['others'])} other folder(s) in this run ("
                   + ", ".join(f"<code>{esc(o)}</code>" for o in ex["others"][:6]) + (f", and {len(ex['others']) - 6} more" if len(ex["others"]) > 6 else "") + "), which the flag would withhold too. To leave it out of the main scan today, move it under a folder whose name is on the list, or scan the vault by its other top-level folders.")
        can.append(f"<strong>Hot folder <code>{esc(h['folder'])}</code> ({h['pile']} of {h['judged']}):</strong> {competes} {how} "
                   f"If it is your own writing, the taxonomy has no bucket that fits it: edit the two sentences named above, or scan it on its own with <code>jev-janitor &lt;vault&gt;/{esc(h['folder'])} --taxonomy FILE</code>. It cost {usd(h['usd'])} of this scan (measured).")
    if D["truncation_cause"]:
        can.append(f"<strong>Truncation ({D['trunc_pile']} pile notes):</strong> raise <code>--excerpt-chars</code> above {D['excerpt_cap']:,}. If the cap doubles to {D['trunc_new_cap']:,}: about "
                   f"{usd(D['trunc_double_cap_usd'][1])} to {usd(D['trunc_double_cap_usd'][0])} more per scan (estimate), across all {D['trunc_all_notes']:,} truncated notes in the vault, not only the pile's {D['trunc_pile']}.")
    if D["short_cause"]:
        can.append(f"<strong>Short notes ({D['short_pile']}):</strong> a note under {SHORT_NOTE_WORDS} words gives Jev little to read; accept them as the pile's floor.")
    better = ("Optional, logged and not built: a rescan of just the pile under an edited taxonomy would confirm a what-if at the pile-only price (<code>--only-pile</code>); "
              "path rules in <code>janitor.toml</code> would decide machine-generated folders locally without withholding them by name; "
              "and when several hot folders share a <code>&lt;parent&gt;/*/&lt;leaf&gt;</code> pattern, naming the pattern is where such a rule would apply.")
    rows_html = "".join(
        f"""
        <tr>
          <td class="path">{esc(r['path'])}</td>
          <td><span class="bucket">{esc(r.get('bucket'))}</span></td>
          {conf_cell(r.get('confidence'))}
          <td class="num">{(r.get('bucket_margin') or 0):.2f}</td>
          <td class="why">{esc(runner_up(r))}</td>
          <td class="why">{" ".join(f'<span class="chip small">{esc(c)}</span>' for c in D['causes'][id(r)]) or '<span class="muted">—</span>'}</td>
        </tr>"""
        for r in D["pile"]
    ) or '<tr><td colspan="6" class="empty">Nothing under the floor — every note cleared {floor}.</td></tr>'.replace("{floor}", str(D["floor"]))
    return ("<section id='pile'><h2>What needs a human</h2>" + explain(shows, li(found), why, li(can), better) +
            '<div class="tablewrap"><table><thead><tr><th>note</th><th>bucket</th><th>confidence</th><th>margin</th><th>runner-up</th><th>cause</th></tr></thead><tbody>'
            + rows_html + "</tbody></table></div></section>")


def spot_check(D, judged):
    rest = [r for r in judged if (r.get("confidence") or 0) >= D["floor"]]
    if not rest:
        return ""
    rng = random.Random(str(D["taxonomy"]) + str(len(rest)))
    sample = rng.sample(rest, min(SPOT_CHECK_N, len(rest)))
    rows_html = "".join(
        f'<tr><td class="path">{esc(r["path"])}</td><td><span class="bucket">{esc(r.get("bucket"))}</span></td>{conf_cell(r.get("confidence"))}<td class="num">{(r.get("bucket_margin") or 0):.2f}</td></tr>'
        for r in sample)
    return (f"<h3>Spot-check: {len(sample)} confident notes, drawn at random</h3><p class='dek'>Confidence at or above {D['floor']} is Jev's best reading, not proof. "
            f"If more than one or two of these {len(sample)} are wrong, the floor is too low for this vault; raise it in policy.py or read the pile's runner-up column with more suspicion.</p>"
            '<div class="tablewrap"><table><thead><tr><th>note</th><th>bucket</th><th>confidence</th><th>margin</th></tr></thead><tbody>' + rows_html + "</tbody></table></div>")


def section_c(D):
    counts = D["bucket_counts"]
    total = D["n_judged"]
    shows = f"{len(counts)} of the {len(ALL_BUCKETS)} buckets were used. A bucket nobody lands in, or one that swallows everything, is a signal about the taxonomy wording, not about the notes."
    found, can = [], []
    dom = D["dominant"]
    if dom:
        found.append(f"<strong>`{dom['bucket']}` is dominant:</strong> {dom['n']:,} of {total:,} judged notes ({dom['share']:.0%}; rule: more than {DOMINANT_SHARE:.0%}). "
                     f"{len(dom['folders'])} folder(s) hold {DOMINANT_COVER:.0%} of it: " + ", ".join(f"<code>{esc(f)}</code> {k:,}" for f, k in dom["folders"][:12]) +
                     (f", and {len(dom['folders']) - 12} more" if len(dom["folders"]) > 12 else "") + ".")
        found.append(f"Those folders are {dom['cover_notes']:,} notes, {dom['cover_tokens']:,} input tokens and <strong>{usd(dom['cover_usd'])}</strong> of this scan (measured).")
        ex = dom["exclusion"]
        parts = ["If those folders are machine-generated (run reports, digests, task records), exclude them."]
        if ex["flag"]:
            parts.append(f"<code>{esc(ex['flag'])}</code> withholds {len(ex['safe'])} of the {len(dom['folders'])} with no other folder affected; {list_note(D)}.")
        if ex["unsafe"]:
            parts.append(f"The other {len(ex['unsafe'])} cannot be singled out by name: a name matches as whole words anywhere in the vault, and " + "; ".join(f"<code>{esc(u['name'])}</code> also matches {len(u['others'])} other folder(s)" for u in ex["unsafe"][:6]) + (f"; and {len(ex['unsafe']) - 6} more" if len(ex["unsafe"]) > 6 else "") + ".")
        parts.append(f"With all of them out, the next scan is {usd(dom['cover_usd'])} cheaper and the report is about the notes you wrote. If they are yours, `{dom['bucket']}` is simply what this vault is.")
        can.append(" ".join(parts))
    else:
        found.append(f"No bucket holds more than {DOMINANT_SHARE:.0%} of judged notes.")
    if D["unused_buckets"]:
        found.append(f"<strong>Unused buckets:</strong> " + ", ".join(f"`{b}`" for b in D["unused_buckets"]) + ".")
        for b in D["unused_buckets"]:
            k = D["unused_runner_up"].get(b, 0)
            if b == "needs_review":
                can.append(f"`needs_review` unused means no note's top vote was `needs_review`; that is fine, not a wording problem ({n_notes(k)} in the pile had it as runner-up).")
            elif k:
                can.append(f"`{b}` was the runner-up in {k} pile notes: close but losing, so its sentence is a wording problem. Sharpen it against the buckets those notes landed in.")
            else:
                can.append(f"`{b}` was never a runner-up in the pile either: this vault holds none of that material, and the empty bucket is fine.")
    better = "Optional, logged and not built: a folder × bucket matrix would show at a glance which folders are homogeneous, and a path rule in <code>janitor.toml</code> would decide such a folder locally without withholding it by name."
    return ("<section id='landed'><h2>Where the notes landed</h2>" + explain(shows, li(found), "", li(can), better) +
            f'<div class="bars">{bar_rows(counts, total)}</div></section>')


def section_d(D, skips):
    shows = "What the run refused to send, which redaction patterns fired on what it did send, and which notes were quarantined. Values never appear here, only labels and counts."
    found = []
    if D["withheld_by_reason"]:
        found.append("<strong>Withheld:</strong> " + ", ".join(f"{esc(k)} {n:,}" for k, n in D["withheld_by_reason"].most_common()) + f" ({D['n_withheld']:,} notes never read for a live call).")
    else:
        found.append("<strong>Withheld:</strong> none.")
    if D["local_by_reason"]:
        found.append("<strong>Decided locally without a call:</strong> " + ", ".join(f"{esc(k)} {n:,}" for k, n in D["local_by_reason"].most_common()) + ".")
    found.append("<strong>Redaction hits by label:</strong> " + (", ".join(f"[{esc(k)}] {n:,}" for k, n in D["hits_by_label"].most_common()) or "none") + f" ({D['n_redacted_notes']:,} notes carried at least one).")
    found.append("<strong>Quarantines by trigger:</strong> " + (", ".join(f"{esc(k)} {n:,}" for k, n in D["quarantine_by_trigger"].most_common()) or "none") + f" ({len(D['quarantined']):,} notes).")
    found.append(f"<strong>Exact duplicates:</strong> {D['n_dupes']:,} notes are byte-identical to an earlier one.")
    why = (f"Withheld notes matched a sensitive folder name; local decisions cost nothing and are never served from cache. Two kinds of quarantine: <strong>{len(D['quarantine_local'])} on a local hit</strong> "
           f"(a machine-checkable credential format in the note's own title, aliases, path, key names or body, decided before any vote; trigger <code>local:…</code>) and <strong>{len(D['quarantine_vote'])} on Jev's vote</strong> "
           f"(<code>contains_secret</code> at or above 0.7, decided after the vote).")
    can = []
    if D["quarantine_local"]:
        can.append(f"<strong>Local hits ({len(D['quarantine_local'])}): a credential-shaped string sat in the note. If it is real, rotate it.</strong> The token names the format, so you know which system's key to rotate; documentation examples such as AWS's <code>…EXAMPLEKEY</code> are common and are not real. Under <code>--apply</code> the note moves to <code>_janitor/quarantine/</code>, git-ignored.")
    if D["quarantine_vote"]:
        can.append(f"<strong>Jev's votes ({len(D['quarantine_vote'])}): Jev judged the note to hold a secret.</strong> Open it and check; a private identifier or a password in prose is what it usually finds, and nothing to rotate until you have looked.")
    can.append(f"Tune <code>--sensitive-paths</code> if a withheld folder should be scanned, or a scanned one should not; the flag replaces the list, so always pass the whole list with it (<code>--sensitive-paths {esc(','.join(D['sensitive_list']))},&lt;name&gt;</code>; {list_note(D)}); the pre-flight names every folder it skips.")
    can.append("Add names and codenames to the denylist: they match whole words across line breaks and become `[NAME]`.")
    better = "Optional: read <code>--offline --json --show-payload</code> once and check the `sent.excerpt` field by eye; regexes miss things."
    def trigger_chips(r):  # built outside the f-string: a backslash inside a replacement field is a SyntaxError before 3.12
        return " ".join('<span class="chip small crit">' + esc(t) + "</span>" for t in (r.get("quarantine_triggers") or []))
    q_html = "".join(
        f'<tr><td class="path">{esc(r["path"])}</td><td>{trigger_chips(r)}</td><td class="why">{esc(", ".join(r.get("redacted_own") or []))}</td></tr>'
        for r in D["quarantined"]) or '<tr><td colspan="3" class="empty">No quarantines.</td></tr>'
    s_html = "".join(
        f'<tr><td class="path">{esc(r["path"])}</td><td><span class="chip small crit">{esc(r.get("skipped") or r.get("reason") or r.get("action"))}</span></td></tr>'
        for r in skips) or '<tr><td colspan="2" class="empty">No notes were withheld in this run.</td></tr>'
    return ("<section id='membrane'><h2>The membrane</h2>" + explain(shows, li(found), why, li(can), better) +
            '<h3>Quarantined</h3><div class="tablewrap"><table><thead><tr><th>note</th><th>trigger</th><th>own hits</th></tr></thead><tbody>' + q_html + "</tbody></table></div>"
            '<h3>Withheld</h3><div class="tablewrap"><table><thead><tr><th>withheld note</th><th>rule</th></tr></thead><tbody>' + s_html + "</tbody></table></div></section>")


def section_e(D):
    shows = "Notes whose call failed, by exception class. An error row has no vote; the note is held, not decided."
    if not D["errors_by_class"]:
        found = ["No errors."]
        can = []
        why = ""
    else:
        found = ["<strong>By class:</strong> " + ", ".join(f"{esc(k)} {n}" for k, n in D["errors_by_class"].most_common()) + f" ({D['n_errors']} notes)."]
        why = ("What is known: the API refused or failed these calls; the row keeps the class name and a redacted detail. What is not known: the cause. "
               "A TypeSafePermissionDeniedError on a handful of notes among thousands has not been explained by content, size or timing in any run so far; the rows carry the class name only.")
        can = ["Run again with <code>--resume</code>: errored notes are retried and everything else is served from the journal. A note that errors twice stays held; open it and look for what is unusual (size, encoding, a body that is all tokens)."]
    rows_html = "".join(
        f'<tr><td class="path">{esc(r["path"])}</td><td class="why">{esc(r.get("error"))}</td><td class="num">{esc(r.get("attempt"))}</td></tr>' for r in D["error_rows"])
    table = ('<div class="tablewrap"><table><thead><tr><th>note</th><th>class</th><th>attempt</th></tr></thead><tbody>' + rows_html + "</tbody></table></div>") if rows_html else ""
    return "<section id='errors'><h2>Errors</h2>" + explain(shows, li(found), why, li(can), "") + table + "</section>"


FALLBACK_SOURCE = "the default taxonomy's size, matched by this run's fingerprint"


def quoted_figures(D):
    """The footer's list of figures NOT computed from the rows: always the noise floor, and the
    default taxonomy's question size when that fallback stood in for rows that do not record it
    (through 0.5.2 the footer named the noise floor as the only one, on a demo page that used the fallback)."""
    noise = f"the noise floor, a measurement from the calibration corpus, not from these rows: {NOISE_FLOOR}"
    if D.get("question_chars_source") == FALLBACK_SOURCE:
        return (f"two quoted figures are not from these rows: {noise}; and the {D['question_chars_per_call']:,} question characters per call in the cost section, "
                f"the default taxonomy file's size, used because these rows predate the recorded field and this run's fingerprint is the default's.")
    return f"the one quoted figure is {noise}."


def next_scan_price(D):
    """Whether the scan after the checklist's first action is full price, computed from the run.

    Through 0.5.1 this sentence was hard-coded ("the first action is a taxonomy edit, and the
    0.4.7 release already moved STATE_VERSION"), true for one demo run and not in general.
    """
    first = D["next_scan"][0] if D["next_scan"] else None
    if first is None:
        out = "The checklist below is empty, so the next scan costs only the notes that changed."
    elif "taxonomy" in first["what"].lower():
        out = "The first action in the checklist below is a taxonomy edit, so the scan after it is full price."
    else:
        out = "The first action in the checklist below is not a taxonomy edit, so the scan after it costs only the notes that changed."
    if D.get("state_version") is not None and D["state_version"] != STATE_VERSION:
        out += f" This run's keys were made under STATE_VERSION {D['state_version']} and this build uses {STATE_VERSION}, so the next scan is full price regardless."
    return out


def section_f(D):
    shows = f"What this run cost, and how the API's own token count compares with the {CHARS_PER_TOKEN_HIGH} down to {CHARS_PER_TOKEN_LOW} characters-per-token range the pre-flight estimate assumes."
    if not D["n_sent"] or D["measured_ratio"] is None:
        if not D["n_sent"]:
            found = "Nothing was sent in this run, so there is no measured ratio."
        elif not D["input_tokens"]:
            found = f"{D['n_sent']:,} notes were judged but no input tokens were counted (an offline run: the keyword fixture bills nothing), so there is no measured ratio and the cost is $0."
        else:
            found = (f"<strong>{usd(D['cost_usd'])}</strong> for {D['input_tokens']:,} input tokens over {D['n_sent']:,} calls. The measured characters-per-token figure is <strong>unavailable</strong>: "
                     f"the ratio needs the question characters each call carried, this run's rows do not record them (runs before 0.5.2), and its taxonomy fingerprint "
                     f"<code>{esc(D['taxonomy'])}</code> is not the default file's, so the default's size would be the wrong number.")
        return "<section id='cost'><h2>Cost and measurement</h2>" + explain(shows, found, "", "", "") + "</section>"
    lo, hi = D["estimate_usd"]
    found = [f"<strong>{usd(D['cost_usd'])}</strong> for {D['input_tokens']:,} input tokens over {D['n_sent']:,} calls at ${PRICE_PER_MILLION_USD} per million (input only: one invoice check put any output-token charge under about $0.005 per million).",
             f"<strong>Measured: {D['measured_ratio']:.2f} characters per token</strong> ({D['payload_chars']:,} payload characters plus {D['question_chars_per_call']:,} question characters per call, {D['question_chars_source']}, over the tokens the API counted), "
             f"<strong>{D['ratio_verdict']}</strong> the assumed range. The pre-flight would have estimated {usd(hi)} to {usd(lo)} for this payload."]
    verdict = {"below": f"This vault tokenizes more densely than prose (logs, ids, code), so the pessimistic end of the estimate was light by {pct(D['cost_usd'] - lo, lo):.0f}%; the spend meter is what protects the bill on a vault like this.",
               "above": "This vault is prose-heavy and tokenizes lighter than the anchors; the estimate is conservative here.",
               "inside": "The estimate's range bracketed the real bill; nothing to adjust."}[D["ratio_verdict"]]
    can = [f"A vault this size needs <code>--max-usd {flag_amount(D['suggested_max_usd'])}</code> or more (the larger of this bill and the pessimistic estimate, rounded up to {usd(MAX_USD_STEP)}); the default ceiling is $2.00 and refuses a bill whose pessimistic end is above it.",
           f"The next scan with <code>--resume</code> sends only notes that changed, so the bill above is the ceiling, not the recurring cost, with one exception: a taxonomy, model or STATE_VERSION change re-sends everything at full price ({usd(D['full_rescan_usd'])} at this run's rate). {next_scan_price(D)}"]
    return "<section id='cost'><h2>Cost and measurement</h2>" + explain(shows, li(found), verdict, li(can), "") + "</section>"


def section_g(D):
    shows = "Graph facts are counts computed locally (links out and in, embeds, headings, words) plus an age in days; they are sent as numbers so Jev can tell a map of content from an orphan."
    found = []
    if D["linking_share"] is not None:
        found.append(f"<strong>{D['linking_share']:.0%} of judged notes link out at all.</strong> " +
                     (f"Under {LINKLESS_SHARE:.0%}, so `is_orphan` is <strong>unknown</strong> on this vault: in-degree is zero everywhere and says nothing." if D["orphan_unknown"] else f"{D['orphans']:,} notes have no links in and are reported as orphans."))
    found.append("<strong>Age sources:</strong> " + ", ".join(f"{esc(k)} {n:,}" for k, n in D["age_sources"].most_common()) + f". {D['age_zero_share']:.0%} of notes read as 0 days old.")
    why = ("A vault that references notes by path rather than by link has no graph to measure, and a subfolder scan cannot see links from the rest of the vault. "
           "Filesystem ages reset when a vault is moved, restored or re-synced, so a whole vault can read as brand new.")
    if D["just_cloned"]:
        why += (f" <strong>This copy was just cloned or copied:</strong> {D['age_mtime_share']:.0%} of ages are file mtimes and {D['age_zero_share']:.0%} read as 0 days (rule: both at or above {CLONED_SHARE:.0%}), so age carries nothing for this run.")
    can = []
    if D["age_mtime_share"] > 0.5:
        can.append(f"Add <code>created:</code> (or <code>date:</code>) frontmatter: {D['age_mtime_share']:.0%} of ages came from file mtimes. Age is sent as a band (0, 1, 7, 30, 90, 365, 1000 days), so a note's cache key survives ordinary edits.")
    if D["orphan_unknown"]:
        can.append("Nothing to do for orphans unless the vault starts linking; the report says unknown rather than counting zeros.")
    return "<section id='graph'><h2>Graph and age</h2>" + explain(shows, li(found), why, li(can), "") + "</section>"


def section_h(D):
    if not D["next_scan"]:
        return ""
    def effect(a):
        if a.get("dollars"):
            return usd(a["impact"])
        return f"{a['impact']:,}" if a["impact"] else "—"

    def overlap(a):
        if a.get("shared"):
            return f'<br><span class="muted">{a["shared"]:,} of these notes are already counted by an action above{"; mostly the same fix seen twice" if a.get("overlaps") else ""}</span>'
        return ""

    rows_html = "".join(
        f'<tr><td class="num">{i + 1}</td><td>{a["what"]}</td><td class="num">{effect(a)} {esc(a["unit"])}{overlap(a)}</td><td class="why">{esc(a["cost"])}</td></tr>'
        for i, a in enumerate(D["next_scan"]))
    return ("<section id='next'><h2>Next scan</h2><p class='dek'>The concrete actions from the sections above, ordered by estimated impact: notes that would clear from the pile if Jev splits its vote the same way under the edit, or dollars saved per scan. "
            f"Together they touch {D['next_scan_distinct']:,} distinct pile notes of {D['n_pile']:,}; where two actions share notes, the overlap is stated. Only a rerun confirms any of it.</p>"
            '<div class="tablewrap"><table><thead><tr><th>#</th><th>action</th><th>estimated effect</th><th>cost</th></tr></thead><tbody>' + rows_html + "</tbody></table></div></section>")


def build(rows, vault_name, out_path, journal_header=None, sensitive_list=None, sensitive_source=None):
    """Write the report. Returns ``(path, D)``; ``D`` is the diagnosis the page was rendered from."""
    D = diagnose(rows, journal_header=journal_header, sensitive_list=sensitive_list, sensitive_source=sensitive_source)
    votes = [r for r in rows if r.get("kind", "vote" if "bucket" in r else "") == "vote" and "bucket" in r]
    judged = [r for r in votes if r.get("judge", "jev") != "local"]
    skips = [r for r in rows if r.get("kind") == "skip" or ("kind" not in r and "bucket" not in r and "skipped" in r)]

    mode_chip = ('<span class="chip warn">OFFLINE — every vote below is from the keyword fixture, not from Jev. Nothing was sent.</span>' if D["offline"]
                 else '<span class="chip live">LIVE — votes from Jev. Excerpts were sent to TypeSafe.</span>')
    write_chip = ('<span class="chip crit">APPLIED — notes on disk were changed</span>' if D["applied"]
                  else '<span class="chip ok">DRY RUN — nothing on disk was changed</span>')

    table_html = "".join(
        f"""
        <tr>
          <td class="path">{esc(r['path'])}</td>
          <td><span class="bucket">{esc(r.get('bucket'))}</span></td>
          {conf_cell(r.get('confidence'))}
          <td class="num">{(r.get('bucket_margin') or 0):.2f}</td>
          <td class="persist">{esc(persist_label(r.get('persist')))}</td>
          <td class="flags">{flags(r)}</td>
        </tr>"""
        for r in sorted(votes, key=lambda r: (r.get("confidence") or 0))
    )
    pile_section = section_b(D).replace("</section>", spot_check(D, judged) + "</section>", 1) if section_b(D) else ""
    sections = section_a(D) + pile_section + section_c(D) + section_d(D, skips) + section_e(D) + section_f(D) + section_g(D) + section_h(D)

    page = TEMPLATE.format(
        vault=esc(vault_name),
        when=when_label(rows),
        mode_chip=mode_chip, write_chip=write_chip,
        model=esc(D["model"]), taxonomy=esc(D["taxonomy"]),
        total=D["n_votes"], n_review=D["n_pile"], n_quarantine=len(D["quarantined"]), n_skipped=D["n_withheld"],
        n_errors=D["n_errors"], n_redacted=D["n_redacted_notes"], n_dupes=D["n_dupes"], cost=usd(D["cost_usd"]),
        sections=sections, rows=table_html, floor=REVIEW_FLOOR, quoted=quoted_figures(D),
    )
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(page)
    return out_path, D


def run_time(rows):
    """The run's own clock: the latest ``at`` stamp on any row (ISO 8601 UTC), or None."""
    stamps = [r.get("at") for r in rows if isinstance(r, dict) and isinstance(r.get("at"), str)]
    return max(stamps) if stamps else None


def when_label(rows):
    """'run 2026-09-24 18:08 UTC' from the rows' own stamps; the render time, labelled, when they carry none."""
    stamp = run_time(rows)
    if stamp:
        try:
            t = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(timezone.utc)
            return "run " + t.strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            pass
    return "rendered " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") + " (the rows carry no time stamps)"


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Janitor Run Report</title>
<style>
/* Native font stacks only: this page lists unredacted vault paths, so opening it must make no
   network request (through 0.5.1 it fetched three families from Google Fonts). */
:root{{
  --ground:#F2F5F6; --surface:#FFFFFF; --sunk:#E7ECEE;
  --ink:#13191C; --ink-soft:#4F5C63; --ink-faint:#7C8990; --rule:#D5DDE0;
  --accent:#0F5468; --accent-soft:#DCEAEE;
  --ok:#2C6E49; --ok-soft:#DDEDE3;
  --warn:#8A5A12; --warn-soft:#F6EBD6;
  --crit:#9E4029; --crit-soft:#F4E2DC;
  --shadow:0 1px 2px rgba(19,25,28,.06);
}}
@media (prefers-color-scheme: dark){{
  :root:not([data-theme="light"]){{
    --ground:#0E1315; --surface:#161E21; --sunk:#1D272B;
    --ink:#E4ECEF; --ink-soft:#A3B1B7; --ink-faint:#7A888E; --rule:#2A363B;
    --accent:#6FB8CE; --accent-soft:#12303A;
    --ok:#7FC49B; --ok-soft:#16301F;
    --warn:#D9AC63; --warn-soft:#332713;
    --crit:#E08A6E; --crit-soft:#3A211A;
    --shadow:0 1px 2px rgba(0,0,0,.4);
  }}
}}
:root[data-theme="dark"]{{
  --ground:#0E1315; --surface:#161E21; --sunk:#1D272B;
  --ink:#E4ECEF; --ink-soft:#A3B1B7; --ink-faint:#7A888E; --rule:#2A363B;
  --accent:#6FB8CE; --accent-soft:#12303A;
  --ok:#7FC49B; --ok-soft:#16301F;
  --warn:#D9AC63; --warn-soft:#332713;
  --crit:#E08A6E; --crit-soft:#3A211A;
  --shadow:0 1px 2px rgba(0,0,0,.4);
}}
*{{box-sizing:border-box}}
body{{
  margin:0;background:var(--ground);color:var(--ink);
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:16px;line-height:1.6;
}}
.wrap{{max-width:1060px;margin:0 auto;padding:0 16px 90px}}
header.top{{padding:46px 0 22px;border-bottom:1px solid var(--rule);margin-bottom:30px}}
.eyebrow{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:11px;letter-spacing:.14em;
  text-transform:uppercase;color:var(--ink-faint);margin:0 0 12px}}
h1{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-weight:700;font-size:clamp(28px,4.4vw,38px);
  line-height:1.06;letter-spacing:-.02em;margin:0 0 14px;text-wrap:balance}}
.chips{{display:flex;flex-wrap:wrap;gap:8px;margin-top:4px}}
.chip{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:11px;letter-spacing:.04em;
  padding:4px 9px;border-radius:3px;background:var(--sunk);color:var(--ink-soft);white-space:nowrap}}
.chip.small{{font-size:10px;padding:2px 6px}}
.chip.ok{{background:var(--ok-soft);color:var(--ok)}}
.chip.warn{{background:var(--warn-soft);color:var(--warn)}}
.chip.crit{{background:var(--crit-soft);color:var(--crit)}}
.chip.live{{background:var(--crit-soft);color:var(--crit)}}
.meta{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:11.5px;color:var(--ink-faint);
  margin-top:14px;line-height:1.9}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:0 0 34px}}
.tile{{background:var(--surface);border-radius:5px;padding:16px 18px;box-shadow:var(--shadow)}}
.tile .n{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-weight:700;font-size:30px;line-height:1;
  letter-spacing:-.02em;font-variant-numeric:tabular-nums;display:block}}
.tile .k{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:10.5px;letter-spacing:.09em;
  text-transform:uppercase;color:var(--ink-faint);display:block;margin-top:8px}}
.tile.flag .n{{color:var(--warn)}}
.tile.stop .n{{color:var(--crit)}}
section{{margin:0 0 40px}}
h2{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-weight:600;font-size:20px;letter-spacing:-.01em;margin:0 0 10px}}
h3{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-weight:600;font-size:15px;margin:22px 0 8px}}
.dek{{color:var(--ink-faint);font-size:14.5px;margin:0 0 18px;max-width:70ch}}
.lede{{font-size:17px;line-height:1.65;max-width:78ch;background:var(--surface);border-radius:5px;padding:18px 20px;box-shadow:var(--shadow)}}
.explain{{background:var(--surface);border-radius:5px;box-shadow:var(--shadow);margin:0 0 18px;padding:6px 20px}}
.ex{{display:grid;grid-template-columns:190px 1fr;gap:14px;padding:12px 0;border-bottom:1px solid var(--rule);font-size:14.5px;line-height:1.55}}
.ex:last-child{{border-bottom:none}}
@media (max-width:680px){{.ex{{grid-template-columns:1fr}}}}
.exk{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--ink-faint);padding-top:3px}}
.exv ul{{margin:0;padding-left:18px}}
.exv li{{margin:0 0 6px}}
.exv q{{font-style:italic;color:var(--ink-soft)}}
.exv code{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:12.5px;background:var(--sunk);padding:1px 5px;border-radius:3px}}
.bars{{background:var(--surface);border-radius:5px;padding:18px 20px;box-shadow:var(--shadow);display:grid;gap:11px}}
.barrow{{display:grid;grid-template-columns:230px 1fr 40px;gap:14px;align-items:center}}
@media (max-width:680px){{.barrow{{grid-template-columns:1fr 1fr 34px}}}}
.barlabel{{display:flex;flex-direction:column;line-height:1.3}}
.bname{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:12.5px;color:var(--ink)}}
.bnote{{font-size:11.5px;color:var(--ink-faint)}}
.bartrack{{background:var(--sunk);border-radius:3px;height:14px;overflow:hidden}}
.barfill{{background:var(--accent);height:100%;border-radius:0 3px 3px 0;min-width:2px}}
.barval{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:13px;text-align:right;font-variant-numeric:tabular-nums;color:var(--ink-soft)}}
.tablewrap{{overflow-x:auto;background:var(--surface);border-radius:5px;box-shadow:var(--shadow)}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:10.5px;letter-spacing:.08em;
  text-transform:uppercase;color:var(--ink-faint);text-align:left;font-weight:400;
  padding:11px 14px;border-bottom:1px solid var(--rule);white-space:nowrap}}
td{{padding:10px 14px;border-bottom:1px solid var(--rule);vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:var(--sunk)}}
.path{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:12.5px;max-width:330px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.bucket{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:11.5px;background:var(--accent-soft);color:var(--accent);padding:3px 7px;border-radius:3px;white-space:nowrap}}
.num{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-variant-numeric:tabular-nums;font-size:12.5px;color:var(--ink-soft);white-space:nowrap}}
.conf{{min-width:118px}}
.cnum{{display:inline-block;width:34px}}
.ctrack{{display:inline-block;width:56px;height:6px;background:var(--sunk);border-radius:3px;overflow:hidden;vertical-align:middle;margin-left:6px}}
.cbar{{display:block;height:100%;background:var(--accent);border-radius:0 3px 3px 0}}
.cbar.low{{background:var(--warn)}}
.persist{{font-size:12.5px;color:var(--ink-soft);white-space:nowrap}}
.why{{font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:11.5px;color:var(--ink-faint)}}
.flags{{white-space:nowrap}}
.empty{{color:var(--ink-faint);font-style:italic;padding:18px 14px}}
.muted{{color:var(--ink-faint)}}
footer{{margin-top:50px;padding-top:20px;border-top:1px solid var(--rule);font-family:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;font-size:11px;color:var(--ink-faint);line-height:1.85}}
</style>
</head>
<body>
<div class="wrap">

<header class="top">
  <p class="eyebrow">jev-janitor · run report</p>
  <h1>{vault}</h1>
  <div class="chips">{mode_chip}{write_chip}</div>
  <p class="meta">
    {when} &nbsp;·&nbsp; model <strong>{model}</strong> &nbsp;·&nbsp; taxonomy fingerprint <strong>{taxonomy}</strong><br>
    The fingerprint identifies the exact wording that produced these votes. Change the taxonomy and these numbers stop being comparable.
  </p>
</header>

<div class="tiles">
  <div class="tile"><span class="n">{total}</span><span class="k">notes decided</span></div>
  <div class="tile flag"><span class="n">{n_review}</span><span class="k">need review &lt; {floor}</span></div>
  <div class="tile stop"><span class="n">{n_quarantine}</span><span class="k">quarantined</span></div>
  <div class="tile"><span class="n">{n_skipped}</span><span class="k">withheld</span></div>
  <div class="tile"><span class="n">{n_redacted}</span><span class="k">notes redacted</span></div>
  <div class="tile"><span class="n">{n_dupes}</span><span class="k">exact duplicates</span></div>
  <div class="tile stop"><span class="n">{n_errors}</span><span class="k">errors</span></div>
  <div class="tile"><span class="n">{cost}</span><span class="k">measured cost</span></div>
</div>

{sections}

<section>
  <h2>Every note</h2>
  <p class="dek">Sorted by confidence, least certain first. Persist is a weighted position on drop / park / promote, so "park–promote, leaning park" carries more than a single word would.</p>
  <div class="tablewrap">
    <table>
      <thead><tr><th>note</th><th>bucket</th><th>confidence</th><th>margin</th><th>persist</th><th>flags</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>

<footer>
  Generated by jev-the-janitor. This report is local only: it lists each note's vault-relative path as written, unredacted (the redacted form is what was sent), and never the excerpt, the frontmatter values or the aliases.<br>
  Votes are probabilistic. Read the margin, not the label. Every number above was computed from this run's own rows, and estimates are labelled; {quoted}
</footer>

</div>
</body>
</html>
"""


def main(argv=None) -> int:
    """Render a saved run: ``python -m janitor.report run.json out.html "Vault name" [journal.jsonl]``."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print(__doc__)
        return 2
    src, dest = argv[0], argv[1]
    name = argv[2] if len(argv) > 2 else "Vault run"
    journal = Path(argv[3]) if len(argv) > 3 else find_journal(src)  # 4th argument: the run's journal
    with open(src, encoding="utf-8-sig") as fh:  # PowerShell redirects write a BOM
        data = json.load(fh)
    header = load_journal_header(journal) if journal and Path(journal).exists() else None
    path, D = build(data, name, dest, journal_header=header)
    print(f"wrote {path}  ({D['n_votes']} notes, {D['n_pile']} need review; sensitive list from {D['sensitive_list_source']}; matcher: {D['matcher_source']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
