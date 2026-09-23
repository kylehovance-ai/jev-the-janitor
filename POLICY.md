# What the janitor will and will not keep

This is the policy the default taxonomy and thresholds encode. If your rules differ,
edit `janitor/taxonomies/vault_memory.yaml` (what Jev is told) and `janitor/policy.py` (what the
code does with the vote).

Promote, park and drop are **labels written to frontmatter**, not file movements. The only
thing this tool moves is a quarantined note, and the only thing it deletes is nothing.

## Promote (long-term memory or decision log)

- Standing facts about a person, place, or project that will still matter next month
- Dated decisions that future work must honor
- Preferences that change how later notes should be written or routed

## Park (keep the file where it is, do not lift it into long-term memory)

- Code notes, commands, schemas, benchmarks
- Reference links and quotes
- Log entries: dated run reports, scans, digests, snapshots, kept as history
- Mixed notes that are useful in place but are not a single fact

## Drop (mark only, never auto-delete)

- Moods, "tired today", session chatter
- One-off debugging
- Empty or boilerplate files

## Quarantine (move, unchanged, to `_janitor/quarantine/<vault-relative path>`, git-ignored, logged in `manifest.jsonl`)

- **A local redaction hit on a credential format** the machine can check: `KEY`, `JWT`,
  `PEM`, `AWS_SECRET`, `BEARER`. This fires on its own, before the vote is consulted at
  all. Redaction runs before the request, so Jev is shown `[KEY]` rather than the key and
  cannot confirm what it never saw; waiting for it to agree was the 0.1.1 behaviour and it
  meant a note with a live key in it got a frontmatter stamp and stayed put.
- **Only this note's own title and body count.** A key inside a *neighbour's* title is
  redacted and reported, and never moves this file.
- `EMAIL`, `PHONE`, `CARD`, `NAME` and `SSN` never quarantine. Those patterns
  false-positive on ordinary prose, and quarantine is a file move.
- `contains_secret` at or above 0.7.
- Notes the vote says are not safe to leave in a public repository — **only when you pass
  `--git-unsafe-below P`.** It is off by default on purpose: 0.55 was chosen by running a
  calibration set, and a threshold that moves people's files should be picked the same way,
  on your vault, not taken from a README.

## Skip (never read, never sent)

- Any note whose relative path contains one of the sensitive folder names
  (default `family`, `private`, `personal`, `secrets`, `inbox`; override with
  `--sensitive-paths`) unless `--include-sensitive` is passed
- Their titles are never sent as sibling context, with or without that flag

## What the journal holds (and what a pasted journal reveals)

The journal lives outside the vault by default and outlives the run, and it is the file an
operator will paste into a bug report. It holds paths, labels, numbers and fixed phrases,
and no free text the operator asked us to strip: the title on a row is the redacted one
(`title_sent`), a parser error is its structural message with quoted tokens dropped, an
error row's detail is redacted, and no excerpt is ever written. The path is still raw, and
a path is often more revealing than a title: `projects/mom-diagnosis-timeline.md` says
plenty. That is load-bearing, because the whole tool exists to tell you which notes to
open, so it stays, and it is stated here rather than left to be discovered. The journal is
not scrubbed of vault identity and cannot be.

## Never

- Store credentials, even if a note says "remember this password"
- Send a whole vault, or a whole note body
- Let Jev write, summarize, or rewrite anything
- Rewrite a note body on `--apply`; the body is spliced back byte-for-byte
- Delete anything
- Treat a vote's probability as proof
- Write a hard `bucket` for a vote below the confidence floor. Those are stamped
  `bucket: needs_review`, keeping the model's pick as `suggested_bucket` and the distance
  to the runner-up as `bucket_margin`, and they are left where they are.
