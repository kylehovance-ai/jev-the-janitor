# AGENTS.md

Guidance for coding agents and automation working in or with this repository.

## What the janitor is

A pre-write gate. Jev votes on a note; code decides what to do. Jev never writes.

## When to call it

- Before promoting a scratch note into long-term memory
- Before committing vault markdown to a public repository
- After a tool or model dumps a transcript into the vault

## When not to call it

- To draft, summarize, or explain a note
- To compute dates, costs, or token counts (keep arithmetic in code)
- On sensitive paths without an explicit human flag

## Contract

1. Redact locally.
2. Send exactly seven fields, every text field redacted: `title`, `path` (vault-relative, posix), `aliases`,
   `frontmatter_keys` (names only, never values, never the tool's own `janitor` key), `excerpt` (the body, cut at
   `--excerpt-chars`, 16,000 by default), `other_note_titles` (same-folder siblings, ranked by overlap, at most 80)
   and `graph` (counts and flags only, exactly these nine keys: `words` (banded), `headings`, `age_days` (banded),
   `out_links`, `in_links`, `embeds`, `unresolved_links`, `is_moc`, `is_orphan`). Nothing else.
   `tests/test_docs_accuracy.py` compares this list with a real `sent` object.
3. Read `bucket`, `bucket_confidence`, `persist`, `contains_secret` and, only under `--git-unsafe-below`,
   `safe_to_leave_in_git` (`janitor/policy.py`, `decide`).
4. Code decides: frontmatter, quarantine, or skip.
5. Anything that writes prose runs after the vote, never instead of it.

## Rules for changes

- `--apply` must stay byte-preserving on bodies. `tests/test_apply_roundtrip.py` is the gate.
- Sensitive-path titles must never appear in outgoing state. `tests/test_titles_privacy.py` is the gate.
- The `path` field in outgoing state must stay relative and posix. `tests/test_state_path.py` is the gate.
- Every file open passes `encoding="utf-8"`. Windows defaults to a legacy codepage.
- Fixtures are invented. Never add a real secret, a real person's fact, or real business data.
- Do not widen what leaves the machine without a human deciding it.

## Composing questions

Ask one narrow judgment per question and combine the answers in code. Do not ask Jev a
compound "if durable and not secret then promote". Split it, then branch.
