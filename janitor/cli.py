"""CLI for Jev the Janitor.

Default is dry-run. Nothing is written to the vault unless --apply.
In live mode a pre-flight summary is printed and confirmed before any request leaves.
Every run appends a journal (outside the vault by default) as it goes; --resume reads one back.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from janitor import __version__
from janitor.bill import DEFAULT_MAX_USD, build_bill, measured_line, over_budget_refusal, render_bill, taxonomy_chars
from janitor.client import FixtureClient, TypeSafeJanitorClient
from janitor.diff import diff_as_rows, diff_snapshots, list_journals, load_snapshot, render_diff
from janitor.journal import (
    STATE_VERSION,
    Journal,
    denylist_digest,
    journal_dir_for,
    new_run_id,
    read_journal,
    vault_id,
)
from janitor.redact import DEFAULT_SENSITIVE_PATH_PARTS
from janitor.resume import ResumePlan, load_resume, newest_journal, resume_summary
from janitor.frontmatter import HARD_EXCERPT_CAP, MAX_EXCERPT
from janitor.index import build_index
from janitor.map import build_map
from janitor.profile import Profile, find_profile
from janitor.scan import ScanAborted, plan_vault, preflight_summary, prepare_vault, root_refusal, run_prepared
from janitor.schema import build_questions, load_taxonomy, taxonomy_fingerprint
from janitor.survey import DEFAULT_SURVEY, survey_sample, survey_summary

EXIT_REFUSED = 1
EXIT_ERRORS = 2
EXIT_INTERRUPTED = 130  # Ctrl-C: the journal is marked interrupted and --resume continues from it


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="jev-janitor",
        description="Ask Jev which bucket a markdown note belongs in. Never writes the note body.",
    )
    p.add_argument("path", type=Path, help="Markdown file, or a vault/folder of .md files")
    p.add_argument("--apply", action="store_true", help="Write janitor frontmatter; quarantine suspected secrets (never deletes)")
    p.add_argument("--offline", action="store_true", help="Use the keyword fixture client instead of Jev; no API key required")
    p.add_argument("--plan", action="store_true", help="Print the pre-flight summary (what would be scanned and skipped) and exit; no key needed")
    p.add_argument("--yes", action="store_true", help="Skip the live-mode confirmation question (for scripts); the pre-flight summary is still printed")
    p.add_argument(
        "--include-sensitive",
        action="store_true",
        default=None,
        help="Also scan notes on sensitive paths (their titles are still never sent as sibling context)",
    )
    p.add_argument(
        "--sensitive-paths",
        default=None,
        help=f"Comma-separated folder names to treat as sensitive, matched as whole words of a folder name ('_Inbox' and '00 Inbox' match 'inbox', 'inboxes' does not); replaces the default ({','.join(DEFAULT_SENSITIVE_PATH_PARTS)})",
    )
    p.add_argument("--config", type=Path, metavar="FILE", help="Vault profile to read (default: <vault>/janitor.toml if present; see janitor.toml.example)")
    p.add_argument("--no-config", action="store_true", help="Read no profile, even if <vault>/janitor.toml exists")
    p.add_argument("--denylist", type=Path, help="Newline-separated names/terms to strip before the API call")
    p.add_argument("--taxonomy", type=Path, help="Override janitor/taxonomies/vault_memory.yaml")
    p.add_argument("--model", default=None, help="Model id to request (default: $TYPESAFE_DEFAULT_MODEL or jev-latest)")
    p.add_argument("--json", action="store_true", help="Print machine-readable rows only on stdout")
    p.add_argument("--show-payload", action="store_true",
                   help="Add the exact state sent for each note to the --json report as 'sent'. Local only: never written to the journal")
    p.add_argument("--git-unsafe-below", type=float, default=None, metavar="P",
                   help="Quarantine notes whose safe_to_leave_in_git is at or below P. Off by default: pick P on your own calibration set, not from this help text")
    p.add_argument(
        "--journal",
        default=None,
        metavar="WHERE",
        help="Where to append the run journal (one JSON line per note as it finishes): 'default' = the user cache dir, "
        "keyed by vault; 'vault' = <vault>/_janitor/runs/; 'off' = no journal; or a directory path",
    )
    p.add_argument(
        "--resume",
        nargs="?",
        const="auto",
        metavar="JOURNAL",
        help="Serve notes already voted in a journal instead of sending them; retry its errors. 'auto' (default) "
        "picks the newest run that is unfinished (interrupted, or stopped by the meter, a 402 or the error rate) "
        "and not already resumed by a newer run, else the newest run; the runs it resumed are served too. Still asks before sending.",
    )
    p.add_argument("--no-cache", action="store_true", help="With --resume: retry errors but send every note again")
    p.add_argument("--trust-cache-across-models", action="store_true", help="With --resume: keep serving cached votes even if the API now returns a different model version")
    # Default 8, measured optimum 16. Two probes on 2026-09-21 (one machine, one network, one
    # evening, while Jev is free and presumably lightly loaded) found no rate limit through 64
    # workers; a 400-call sustained probe kept scaling to 64, a 40-call probe saw p50 double past
    # 16. Defaulting below the optimum is partly about not being the reason a free service
    # grows a rate limiter. No token bucket or backoff ladder: error rows catch whatever appears.
    p.add_argument("--workers", type=int, default=None, help="Concurrent requests (default 8; 16 measured as the optimum, no refusals seen through 64). Rows are written by one thread")
    p.add_argument(
        "--excerpt-chars",
        default=None,
        metavar="N|full",
        help=f"How much of each note leaves the machine, after redaction: the first N characters (default {MAX_EXCERPT}), "
        f"or 'full' / 0 for whole notes (hard guard {HARD_EXCERPT_CAP:,} characters; the API refuses calls over 32,768 tokens). "
        "Changing this changes the cache key of every note longer than the smaller cap.",
    )
    p.add_argument("--journal-info", action="store_true", help="Print the newest journal for this vault (header, counts, cache hits for today) and exit; no key needed")
    p.add_argument("--diff", nargs="?", const="auto", metavar="JOURNAL",
                   help="What changed between two scans, from their journals alone: bucket changes, review in both directions, "
                        "quarantines, new duplicates, cap crossings, findings, locks. 'auto' (default) compares the two newest "
                        "journals for this vault; JOURNAL compares that run against the newest. Nothing is read or sent; exits")
    p.add_argument("--quiet", action="store_true", help="No progress lines on stderr (errors and the pre-flight still print)")
    p.add_argument("--no-local-triage", action="store_true",
                   help="Send every scannable note to the judge, including empty bodies, exact duplicates and notes with a "
                        "high-precision secret hit that code would otherwise decide locally (for measuring Jev against the local rules)")
    p.add_argument("--max-usd", type=float, default=None, metavar="USD",
                   help=f"Refuse a live run whose pessimistic cost estimate exceeds USD (default {DEFAULT_MAX_USD:.2f}; 0 = no ceiling)")
    p.add_argument("--over-budget", action="store_true",
                   help="Accept a bill over the ceiling for this run. Pass it together with --yes; a piped run still cannot consent")
    p.add_argument("--survey", nargs="?", const=DEFAULT_SURVEY, type=int, metavar="N",
                   help=f"Judge a stratified sample of N notes (default {DEFAULT_SURVEY}) drawn across folders, length bands and age bands, "
                        "then stop; same pre-flight as a full run. The votes go to the journal, so a later full scan serves them from cache")
    p.add_argument("--map", type=Path, metavar="FILE",
                   help="Write the brain map's data (per-folder rollups, graph facts, duplicates, one record per note; paths and "
                        "numbers only, no titles or text) as JSON to FILE. Nothing is written unless you pass this")
    p.add_argument("--review-pile", type=Path, metavar="FILE",
                   help="Write the notes routed to a human (needs_review, low confidence, quarantined) as a markdown list of wikilinks "
                        "to FILE, one place you choose; nothing is written unless you pass this. Lock a note you have decided with "
                        "janitor.locked: true and later scans skip it")
    return p.parse_args(argv)


def load_denylist(path: Path | None) -> list[str]:
    if path is None:
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def confirm(prompt: str) -> bool:
    """Ask on the terminal. A non-interactive stdin cannot consent, so it is a refusal."""
    if not sys.stdin or not sys.stdin.isatty():
        return False
    try:
        # The prompt belongs on stderr with the pre-flight it follows. input() writes its
        # own prompt to stdout, which put "Send these notes to TypeSafe? [y/N]" in the
        # middle of a --json report.
        print(prompt, end="", file=sys.stderr, flush=True)
        answer = input()
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


class Progress:
    """One line on stderr every N notes or T seconds. Overwritten in place on a TTY."""

    def __init__(self, total: int, *, every: int = 50, seconds: float = 5.0, quiet: bool = False) -> None:
        self.total = total
        self.every = every
        self.seconds = seconds
        self.quiet = quiet
        self.done = self.sent = self.cached = self.errors = 0
        self.started = time.perf_counter()
        self.last = self.started
        self.tty = bool(getattr(sys.stderr, "isatty", lambda: False)())
        self._wall_started = time.perf_counter()

    def note(self, row: dict) -> None:
        kind = row.get("kind")
        if kind == "vote":
            self.done += 1
            if row.get("cached"):
                self.cached += 1
            else:
                self.sent += 1
        elif kind == "error":
            self.done += 1
            self.sent += 1
            self.errors += 1
        elif kind == "skip":
            self.done += 1
        if self.quiet:
            return
        t = time.perf_counter()
        if self.done % self.every == 0 or t - self.last >= self.seconds:
            self.last = t
            self.emit()

    def emit(self, final: bool = False) -> None:
        if self.quiet:
            return
        remaining = self.total - self.done
        elapsed = time.perf_counter() - self._wall_started
        rate = elapsed / self.sent if self.sent else 0  # wall seconds per sent note, includes concurrency
        eta = f"~{max(1, int(remaining * rate / 60))} min left" if rate and remaining else ""
        line = f"  {self.done:,} / {self.total:,}   sent {self.sent:,}  cached {self.cached:,}  errors {self.errors:,}   {eta}"
        end = "\n" if (final or not self.tty) else "\r"
        print(line, end=end, file=sys.stderr, flush=True)


def review_pile(rows: list[dict], vault: Path) -> str:
    """The low-confidence pile as a markdown list of wikilinks, for a person to walk.

    Nothing is moved: moving a note would break the graph the person navigates. When they
    have accepted or corrected a label they add ``janitor.locked: true`` to the note and
    the next scan skips it; the pile shrinks by exactly the notes a human has read.
    """
    picked = [r for r in rows if r.get("kind") == "vote" and (r.get("suggested_bucket") or r.get("action") == "quarantine")]
    locked = sum(1 for r in rows if r.get("skipped") == "locked")
    lines = [f"# jev-janitor review pile: {len(picked)} notes under {vault.name}/ ({locked} already locked and skipped)", ""]
    lines.append("Decide each one in its own frontmatter, then add `locked: true` under `janitor:` so the next scan leaves it alone.")
    lines.append("")
    for r in picked:
        link = r["path"][:-3] if r["path"].lower().endswith(".md") else r["path"]
        if r.get("action") == "quarantine":
            where = r.get("applied") or "not moved (dry run)"
            lines.append(f"- [[{link}]] quarantine: {r.get('reason')} ({where})")
        else:
            lines.append(f"- [[{link}]] suggested `{r.get('suggested_bucket')}` at confidence {r.get('confidence')}, margin {r.get('bucket_margin')} ({r.get('judge')})")
    return "\n".join(lines) + "\n"


def parse_excerpt_chars(value) -> int:
    v = str(value).strip().lower()
    if v in ("full", "0", "all", "whole"):
        return 0
    try:
        n = int(v)
    except ValueError:
        raise SystemExit(f"--excerpt-chars must be a number or 'full', not {value!r}") from None
    if n < 200:
        raise SystemExit("--excerpt-chars must be at least 200, or 'full'")
    return n


def _today_header(args, vault: Path, sensitive_parts, denylist) -> dict:
    return {
        "janitor": __version__,
        "state_version": STATE_VERSION,
        "vault_id": vault_id(vault),
        "taxonomy": taxonomy_fingerprint(args.taxonomy),
        "model_requested": "fixture" if args.offline else args.model,
        "excerpt_cap": args.excerpt_chars,
        "include_sensitive": args.include_sensitive,
        "sensitive_parts": list(sensitive_parts),
        "denylist": denylist_digest(denylist),
        "apply": args.apply,
    }


def scan_diff(vault: Path, args) -> int:
    """--diff: compare two journals for this vault. Reads journals only; the vault is never opened."""
    directory = journal_dir_for(vault, args.journal)
    if directory is None:
        raise SystemExit("--diff needs journals; --journal off has none")
    journals = list_journals(directory)
    if args.diff == "auto":
        if len(journals) < 2:
            raise SystemExit(f"--diff needs two journals for this vault; found {len(journals)} under {directory}")
        before_path, after_path = journals[-2], journals[-1]
    else:
        before_path = Path(args.diff)
        if not before_path.exists():
            raise SystemExit(f"--diff: no such journal: {before_path}")
        after_path = next((j for j in reversed(journals) if j.resolve() != before_path.resolve()), None)
        if after_path is None:
            raise SystemExit(f"--diff: no other journal to compare against under {directory}")
    d = diff_snapshots(load_snapshot(before_path), load_snapshot(after_path))
    if args.json:
        print(json.dumps(diff_as_rows(d), indent=2))
    else:
        print(render_diff(d))
    return 0


def journal_info(vault: Path, args, sensitive_parts, denylist) -> int:
    directory = journal_dir_for(vault, args.journal)
    path = newest_journal(directory) if directory else None
    if path is None:
        print(f"no journal for this vault under {directory}")
        return 0
    today = _today_header(args, vault, sensitive_parts, denylist)
    plan = load_resume(path, today)
    header, rows, torn = read_journal(path)
    counts = {}
    for r in rows:
        counts[r.get("kind")] = counts.get(r.get("kind"), 0) + 1
    _, _, items, _ = prepare_vault(vault, taxonomy_path=args.taxonomy, include_sensitive=args.include_sensitive,
                                   sensitive_parts=sensitive_parts, denylist=denylist or None,
                                   model_requested=today["model_requested"], cache=plan.cached, excerpt_chars=args.excerpt_chars,
                                   local_triage=not args.no_local_triage)
    hits = sum(1 for it in items if it.cached_row is not None)
    print(f"journal: {path}")
    print(f"  run {header.get('run') if header else '?'} started {header.get('started') if header else '?'}  janitor {header.get('janitor') if header else '?'}  taxonomy {header.get('taxonomy') if header else '?'}")
    print(f"  rows: {counts}  completed: {plan.completed}  torn last line: {torn}")
    source = f"this journal and the {len(plan.chain)} run(s) it resumed" if plan.chain else "this journal"
    print(f"  today: {hits} of {len(items)} notes would be served from {source}; {len(plan.error_paths)} would be retried")
    for d in plan.differences:
        print(f"  differs today: {d}")
    return 0


# (argparse default, profile key). A flag given on the command line wins; then the profile; then this.
PROFILE_DEFAULTS: dict[str, tuple[object, str]] = {
    "sensitive_paths": (",".join(DEFAULT_SENSITIVE_PATH_PARTS), "sensitive_paths"),
    "denylist": (None, "denylist"),
    "taxonomy": (None, "taxonomy"),
    "excerpt_chars": (str(MAX_EXCERPT), "excerpt_chars"),
    "workers": (8, "workers"),
    "journal": ("default", "journal"),
    "model": (os.environ.get("TYPESAFE_DEFAULT_MODEL", "jev-latest"), "model"),
    "max_usd": (None, "max_usd"),
    "git_unsafe_below": (None, "git_unsafe_below"),
    "include_sensitive": (False, "include_sensitive"),
}


def apply_profile(args: argparse.Namespace, profile: Profile) -> None:
    """Fill every unset argument from the profile, then from the built-in default."""
    for attr, (default, key) in PROFILE_DEFAULTS.items():
        if getattr(args, attr) is not None:
            continue
        value = profile.get(key, default)
        if attr == "sensitive_paths" and isinstance(value, list):
            value = ",".join(value)
        if attr in ("denylist", "taxonomy") and value is not None:
            value = Path(value)
        setattr(args, attr, value)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    target = args.path.expanduser().resolve()
    if not target.exists():
        raise SystemExit(f"path not found: {target}")
    profile = find_profile(target, explicit=args.config, disabled=args.no_config)
    apply_profile(args, profile)
    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")
    args.excerpt_chars = parse_excerpt_chars(args.excerpt_chars)

    sensitive_parts = tuple(part.strip() for part in args.sensitive_paths.split(",") if part.strip())
    live = not args.offline
    denylist = load_denylist(args.denylist)
    vault, plan = plan_vault(target, include_sensitive=args.include_sensitive, sensitive_parts=sensitive_parts)

    if args.journal_info:
        return journal_info(vault, args, sensitive_parts, denylist)
    if args.diff is not None:
        return scan_diff(vault, args)

    # --- resume: read the journal back, classify every note locally -------------------------
    today = _today_header(args, vault, sensitive_parts, denylist)
    resume: ResumePlan | None = None
    if args.resume:
        directory = journal_dir_for(vault, args.journal)
        if directory is None:
            raise SystemExit("--resume needs a journal; --journal off has none")
        jpath = newest_journal(directory) if args.resume == "auto" else Path(args.resume)
        if jpath is None or not jpath.exists():
            raise SystemExit(f"no journal to resume under {directory}")
        resume = load_resume(jpath, today)

    cache = None if (resume is None or args.no_cache) else resume.cached
    index = build_index(target, include_sensitive=args.include_sensitive, sensitive_parts=sensitive_parts)
    root, plan, items, fingerprint = prepare_vault(
        target, taxonomy_path=args.taxonomy, include_sensitive=args.include_sensitive, sensitive_parts=sensitive_parts,
        denylist=denylist or None, model_requested=today["model_requested"], cache=cache, excerpt_chars=args.excerpt_chars,
        local_triage=not args.no_local_triage, index=index,
    )
    # Counted before a survey narrows `items`: the pre-flight's "served from the journal" is a
    # fact about the vault's cache, not about the sample (it read 0 or 1 under --survey).
    cached_hits = sum(1 for it in items if it.cached_row is not None)
    survey = None
    if args.survey:
        # A sample of what the judge would see; everything else stays home. Drawn after the
        # cache lookup so a survey never re-spends on notes the journal already answered.
        survey = survey_sample(items, args.survey, seed=vault_id(vault))
        items = survey.items
    guard_truncated = sum(1 for it in items if it.guard_truncated)
    fresh_items = [it for it in items if it.cached_row is None and it.error is None]
    retries = sum(1 for it in fresh_items if resume is not None and it.rel in resume.error_paths)
    summary = preflight_summary(vault, plan, sensitive_parts=sensitive_parts, live=live, cached=cached_hits,
                                excerpt_chars=args.excerpt_chars, guard_truncated=guard_truncated)
    if resume is not None:
        summary = resume_summary(resume, cached_hits=cached_hits, retries=retries, fresh=len(fresh_items) - retries) + "\n" + summary
    summary = "  " + profile.describe() + "\n" + summary
    if survey is not None:
        summary += "\n  " + survey.describe()
    refusal = root_refusal(target, sensitive_parts, include_sensitive=args.include_sensitive)
    if refusal:
        summary += "\n  " + refusal
    # The bill: from the actual payloads prepare_vault built, before consent. Printed in every
    # mode (an offline run shows what a live one would cost); enforced only when live.
    max_usd = DEFAULT_MAX_USD if args.max_usd is None else (args.max_usd or None)
    bill = build_bill(plan, items, question_chars=taxonomy_chars(load_taxonomy(args.taxonomy)), max_usd=max_usd)
    summary += "\n" + render_bill(bill, live=live)
    if live and bill.over_budget and not args.over_budget:
        refusal = refusal or over_budget_refusal(bill)
        summary += "\n  " + over_budget_refusal(bill)

    if args.plan:
        print(summary)
        return 0
    if refusal:
        # A vault mounted under a sensitive folder name, or a bill over the ceiling: nothing
        # should be judged. Say so and fail, rather than report a green run that did nothing
        # or send a bill nobody looked at (scheduled runs never read the pre-flight).
        print(summary, file=sys.stderr)
        return EXIT_REFUSED

    # What a live run would actually send: the bill's count, which excludes notes decided
    # locally, locked, empty or errored. len(fresh_items) counted those too, so a vault that
    # is all local decisions demanded a key and a confirmation for zero requests.
    sending = bill.to_send
    if not live:
        # The quick start tells people to run --offline first. That is the run where the
        # _Inbox near-miss warnings and the included-folder list matter most, and it used
        # to print nothing at all.
        print(summary, file=sys.stderr)
    if live:
        if not os.environ.get("TYPESAFE_API_KEY") and sending:
            raise SystemExit("TYPESAFE_API_KEY is not set. Export it, or pass --offline.")
        # Always printed, even with --yes: every live run leaves a record of what was sent.
        print(summary, file=sys.stderr)
        if sending == 0:
            print("nothing to send; every note is served from the journal or decided locally", file=sys.stderr)
        elif not args.yes and not confirm("Send these notes to TypeSafe? [y/N] "):
            raise SystemExit("Not confirmed. Nothing was sent. Re-run with --yes to skip the prompt, or --plan to review.")

    journal: Journal | None = None
    journal_dir = journal_dir_for(vault, args.journal)
    if journal_dir is not None:
        run_id = new_run_id()
        header = {"run": run_id, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **today,
                  "resumed_from": str(resume.journal.resolve()) if resume else None, "workers": args.workers,
                  "survey": len(survey.items) if survey is not None else None,
                  "question_chars": bill.question_chars}  # so a journal alone can recompute the measured line on the estimate's basis
        journal = Journal(Journal.new_path(journal_dir, run_id), header, fsync=args.apply)

    total = (len(items) + sum(1 for e in plan if e.status == "skip_sensitive")) if survey is not None \
        else sum(1 for e in plan if e.status in ("scan", "skip_sensitive"))
    progress = Progress(total, quiet=args.quiet)

    counts = {"errors": 0}

    def on_row(row: dict) -> None:
        if row.get("kind") == "error":
            counts["errors"] += 1
        if journal is not None:
            # --show-payload is for the operator reading one run, not for the journal. The
            # journal lives outside the vault and outlives the run; redacted vault text put
            # there would sit outside the vault permanently. Spec v0.2 section 9.
            journal.append({k: v for k, v in row.items() if k != "sent"} if "sent" in row else row)
        progress.note(row)

    taxonomy = load_taxonomy(args.taxonomy)
    questions = {} if args.offline else (build_questions(taxonomy) if sending else {})
    engine = FixtureClient() if args.offline else (TypeSafeJanitorClient(model=args.model) if sending else FixtureClient())

    rows: list[dict] = []
    aborted: ScanAborted | None = None
    interrupted = False
    completed = False  # set only when run_prepared returns; anything else is an unfinished run
    failure: str | None = None
    # The ceiling also meters the run: with --over-budget the accepted bill's pessimistic
    # end is the limit, so accepting a bill never means accepting an unbounded one.
    spend_limit = None if not live or max_usd is None else (max(max_usd, bill.usd_high) if args.over_budget else max_usd)
    try:
        rows = run_prepared(root, plan, items, engine=engine, questions=questions, fingerprint=fingerprint, apply=args.apply,
                            on_row=on_row, workers=args.workers, trust_cache_across_models=args.trust_cache_across_models,
                            git_unsafe_threshold=args.git_unsafe_below, payload=args.show_payload, spend_limit=spend_limit,
                            question_chars=bill.question_chars)
        completed = True
    except ScanAborted as exc:
        aborted = exc
        rows = exc.rows
    except KeyboardInterrupt:
        interrupted = True
    except BaseException as exc:
        failure = type(exc).__name__  # named in the footer; the exception itself propagates
        raise
    finally:
        errors = counts["errors"]
        if journal is not None:
            if completed or aborted is not None:
                journal.close({"rows": len(rows), "errors": errors, "aborted": aborted is not None, "interrupted": False,
                               "reason": aborted.reason if aborted is not None else None,
                               "exit": EXIT_ERRORS if (errors or aborted) else 0})
            else:
                # Ctrl-C, or anything else that left the run unfinished (a writer failure, a full
                # disk, a bug): closed as interrupted with the real count, so --resume prefers it.
                # Rows reach the journal one by one; the local list is empty here. Through 0.4.5
                # this footer said rows 0, exit 0: a clean completed run.
                journal.close({"rows": journal.rows, "errors": errors, "aborted": False, "interrupted": True,
                               "reason": f"failed:{failure}" if failure else "interrupted", "exit": EXIT_INTERRUPTED})
    progress.emit(final=True)
    if interrupted:
        n = journal.rows if journal is not None else 0
        where = f"; the journal is marked interrupted after {n:,} rows and --resume continues from it" if journal is not None else ""
        print(f"interrupted: nothing new was sent after the stop; requests that had completed were recorded, and a request still in flight "
              f"wrote no file (if it has no row, --resume judges it again){where}", file=sys.stderr)
        return EXIT_INTERRUPTED
    measured = measured_line(rows, question_chars=bill.question_chars, spend_limit=spend_limit)
    if measured:
        # The API's own token counts against payload plus question chars, the same basis the
        # pre-flight estimated on: the figure that replaces its two anchors with data from this vault.
        print(measured, file=sys.stderr)
    if survey is not None:
        print(survey_summary(survey, rows), file=sys.stderr)

    rows_out = sorted(rows, key=lambda r: r.get("path", ""))
    if args.map is not None:
        args.map.parent.mkdir(parents=True, exist_ok=True)
        args.map.write_text(json.dumps(build_map(index, rows_out, taxonomy=fingerprint, vault_name=vault.name), indent=2),
                            encoding="utf-8", newline="\n")
        print(f"map: {args.map}", file=sys.stderr)
    if args.review_pile is not None:
        args.review_pile.parent.mkdir(parents=True, exist_ok=True)
        args.review_pile.write_text(review_pile(rows_out, vault), encoding="utf-8", newline="\n")
        print(f"review pile: {args.review_pile}", file=sys.stderr)
    if args.json:
        print(json.dumps(rows_out, indent=2))
    else:
        print(f"jev-janitor  notes={len(rows_out)}  apply={args.apply}  offline={args.offline}  workers={args.workers}")
        for row in rows_out:
            if row.get("kind") == "event":
                print(f"  ! {row.get('event')}: {row.get('detail')}")
                continue
            bucket = row.get("bucket", row.get("skipped", ""))
            conf = row.get("confidence", "")
            cached = " (journal)" if row.get("cached") else ""
            print(f"  {row['path']:<42} {str(bucket):<18} conf={conf} action={row.get('action')}{cached}")
            if row.get("kind") == "error":
                print(f"    error: {row.get('error')}: {row.get('detail')}")
            if row.get("redacted"):
                print(f"    redacted: {', '.join(row['redacted'])}")
            if row.get("frontmatter_error"):
                print(f"    finding: frontmatter unreadable: {row['frontmatter_error']}")
            if row.get("skipped") == "undecodable":
                print(f"    finding: {row.get('detail')}")
    unreadable = [r["path"] for r in rows_out if r.get("frontmatter_error")]
    undecodable = [r["path"] for r in rows_out if r.get("skipped") == "undecodable"]
    if index.graph_sparse and not index.single_file and any(r.get("kind") == "vote" for r in rows_out):
        scanned = sum(1 for n in index.notes.values() if n.note is not None)
        print(f"graph: {100 * (1 - index.linking_share):.0f}% of {scanned} scanned notes have no outgoing [[wikilink]] or markdown link, so "
              f"in_links and is_orphan say nothing here and is_orphan is reported as unknown; a subfolder scan also cannot see links "
              f"from the rest of the vault.", file=sys.stderr)
    aged = [r for r in rows_out if r.get("kind") == "vote" and r.get("age_source")]
    from_mtime = sum(1 for r in aged if r["age_source"] == "mtime")
    if aged and from_mtime:
        print(f"findings: {from_mtime} of {len(aged)} judged notes ({100 * from_mtime / len(aged):.0f}%) have no creation date in their frontmatter; "
              f"their age comes from the filesystem and will reset if you move, clone, restore or re-sync this vault.", file=sys.stderr)
    if unreadable or undecodable:
        print(f"findings: {len(unreadable)} note(s) have frontmatter no YAML reader can parse and {len(undecodable)} are not valid UTF-8; "
              f"rows carry `findings` and the reason. A header that will not parse is a fact about the vault, not a failure of the run.", file=sys.stderr)
    if journal is not None:
        print(f"journal: {journal.path}", file=sys.stderr)
    if aborted is not None:
        print(f"ABORTED: {aborted}", file=sys.stderr)
        return EXIT_ERRORS
    if errors:
        print(f"{errors} note(s) failed; rows marked action=error. Re-run with --resume to retry only those. Exit {EXIT_ERRORS}.", file=sys.stderr)
        return EXIT_ERRORS
    return 0


if __name__ == "__main__":
    sys.exit(main())
