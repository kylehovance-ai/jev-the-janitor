"""`jev-records`: judge a JSONL file of records against a question set. Rows out; the source is never written."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from janitor.bill import DEFAULT_MAX_USD, taxonomy_chars, usd
from janitor.cli import EXIT_ERRORS, EXIT_INTERRUPTED, EXIT_REFUSED, confirm, load_denylist
from janitor.frontmatter import MAX_EXCERPT
from janitor.records import (
    FixtureRecordClient,
    TypeSafeRecordClient,
    journal_dir_for_records,
    judge_records,
    load_cache,
    load_records,
    prepare_records,
    records_bill,
    render_records_preflight,
    render_table,
)
from janitor.scan import ScanAborted
from janitor.schema import load_question_set, review_choice, taxonomy_fingerprint


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="jev-records", description="Judge records (one JSON object per line, with `id` and `sent`) against a question set. Only `sent` leaves the machine; the source file is never written.")
    p.add_argument("records", type=Path, help="JSONL file: {\"id\": ..., \"sent\": {field: value}} per line")
    p.add_argument("--questions", type=Path, required=True, metavar="FILE", help="Question set YAML (the `questions:` layout; see janitor/taxonomies/vault_memory.yaml)")
    p.add_argument("--offline", action="store_true", help="Use the fixture stand-in; nothing leaves the machine")
    p.add_argument("--plan", action="store_true", help="Print the pre-flight and the bill, send nothing, exit 0")
    p.add_argument("--yes", action="store_true", help="Skip the confirmation question (the pre-flight is still printed)")
    p.add_argument("--json", action="store_true", help="Print every row as a JSON array on stdout instead of the table")
    p.add_argument("--out", type=Path, metavar="FILE", help="Also write every row as JSONL to this sidecar file (never the source)")
    p.add_argument("--show-payload", action="store_true", help="Put the exact `sent` state on each row (--json/--out only; never journaled)")
    p.add_argument("--review-choice", metavar="NAME", help="The choice the review floor applies to (default: the file's review_choice, else its first choice)")
    p.add_argument("--denylist", type=Path, metavar="FILE", help="Terms to redact locally, one per line")
    p.add_argument("--excerpt-chars", default=str(MAX_EXCERPT), metavar="N|full", help="Cut every string value at N chars after redaction (default 16000; full = the 60,000 guard)")
    p.add_argument("--model", default="jev-latest")
    p.add_argument("--journal", default=None, metavar="default|off|DIR", help="Where the run journal goes and the cache is read from (default: the user cache dir, keyed by a hash of the records path)")
    p.add_argument("--no-cache", action="store_true", help="Do not serve rows from the newest journal")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--max-usd", type=float, default=None, help=f"Refuse a live run whose pessimistic estimate is over this (default {DEFAULT_MAX_USD}; 0 = none)")
    p.add_argument("--over-budget", action="store_true", help="With --yes: accept a bill over the ceiling for this run")
    p.add_argument("--quiet", action="store_true")
    return p.parse_args(argv)


class RefusingRecordClient:
    """For a live run whose bill says nothing will be sent: any call is a bug, not a vote."""

    def judge(self, state, questions, payloads):
        raise RuntimeError("nothing should be sent in this run: the bill counted zero records to send")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    live = not args.offline
    excerpt = 0 if str(args.excerpt_chars).lower() == "full" else int(args.excerpt_chars)
    max_usd = DEFAULT_MAX_USD if args.max_usd is None else (args.max_usd or None)
    try:
        recs = load_records(args.records, load_denylist(args.denylist))
        qset = load_question_set(args.questions)
    except ValueError as exc:
        raise SystemExit(f"refused: {exc}") from exc
    denylist = load_denylist(args.denylist)
    fingerprint = taxonomy_fingerprint(args.questions)
    review = args.review_choice or review_choice(qset)
    journal_dir = journal_dir_for_records(args.records, args.journal)
    model_requested = "fixture" if args.offline else args.model
    cache = {} if args.no_cache else load_cache(journal_dir, model_requested)
    items = prepare_records(recs, fingerprint=fingerprint, model_requested=model_requested, denylist=denylist, excerpt_chars=excerpt, cache=cache)
    bill = records_bill(items, question_chars=taxonomy_chars(qset), max_usd=max_usd)
    summary = render_records_preflight(items, bill, live=live, fingerprint=fingerprint, review=review, excerpt_chars=excerpt)
    refusal = None
    if live and bill.over_budget and not args.over_budget:
        refusal = f"REFUSED: the pessimistic estimate of {usd(bill.usd_high)} is over the ceiling of {usd(bill.max_usd)}. Nothing was sent. Raise it with --max-usd, or pass --over-budget with --yes."
        summary += "\n  " + refusal
    if args.plan:
        print(summary)
        return 0
    print(summary, file=sys.stderr)
    if refusal:
        return EXIT_REFUSED
    if live:
        if bill.to_send and not os.environ.get("TYPESAFE_API_KEY"):
            raise SystemExit("TYPESAFE_API_KEY is not set. Export it, or pass --offline.")
        if bill.to_send and not args.yes and not confirm("Send these records to TypeSafe? [y/N] "):
            raise SystemExit("Not confirmed. Nothing was sent. Re-run with --yes to skip the prompt, or --plan to review.")
    # The SDK client only when something will be sent: a live run whose records are all served
    # or held needs no key and no SDK. It gets a client that refuses, not the fixture, so a
    # disagreement between the bill and the run can never record fixture votes as live ones.
    client = FixtureRecordClient() if args.offline else (TypeSafeRecordClient(args.model) if bill.to_send else RefusingRecordClient())
    out_fh = None
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        out_fh = args.out.open("w", encoding="utf-8", newline="\n")

    def on_row(row: dict) -> None:
        if out_fh is not None:
            out_fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    aborted = None
    try:
        rows = judge_records(args.records, args.questions, offline=args.offline, client=client, denylist=denylist, model=args.model,
                             excerpt_chars=excerpt, max_usd=max_usd, over_budget=args.over_budget, workers=args.workers,
                             journal_dir=journal_dir, use_cache=not args.no_cache, review=review, on_row=on_row, payload=args.show_payload)
    except ScanAborted as exc:
        aborted = exc
        rows = exc.rows
    except KeyboardInterrupt:
        where = ", and the journal is marked interrupted" if journal_dir is not None else ""
        print(f"interrupted: nothing new was sent after the stop; requests that had completed were recorded{where}", file=sys.stderr)
        return EXIT_INTERRUPTED
    finally:
        if out_fh is not None:
            out_fh.close()
    rows_out = sorted(rows, key=lambda r: str(r.get("id", "")))  # the report is by id; the sidecar keeps completion order
    if args.json:
        print(json.dumps(rows_out, indent=2, ensure_ascii=False))
    elif not args.quiet:
        print(render_table(rows_out))
    errors = sum(1 for r in rows if r.get("kind") == "error")
    held = sum(1 for r in rows if r.get("judge") == "local")
    print(f"records: {len(rows):,} rows, {held:,} held back by a local credential hit, {errors:,} errors"
          + (f"; journal: {journal_dir}" if journal_dir is not None else ""), file=sys.stderr)
    if aborted is not None:
        print(str(aborted), file=sys.stderr)
    return EXIT_ERRORS if (errors or aborted) else 0


if __name__ == "__main__":
    raise SystemExit(main())
