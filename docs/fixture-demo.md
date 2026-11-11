# Fixture demo

`fixtures/notes/` is an invented vault. Nothing in it is real. The offline client classifies it by keyword so CI runs without a key; the right-hand column is what live Jev said about the same files:

| note | offline bucket | live Jev bucket (confidence) |
|---|---|---|
| durable-plot-fee.md | durable_memory | durable_memory (1.00) |
| durable-routing-rule.md | durable_memory | durable_memory (0.92) |
| duplicate-routing-rule.md | durable_memory | junk (0.83) |
| project-decision.md | project_decision | project_decision (1.00) |
| code-note.md | code_note | code_note (1.00) |
| reference-link.md | reference | reference (1.00) |
| nightly-run-log.md | log_entry | log_entry (1.00) |
| ephemeral-scratch.md | ephemeral | ephemeral (0.97) |
| ephemeral-mood.md | ephemeral | ephemeral (0.99) |
| junk-lorem.md | junk | junk (0.96) |
| secret-leak.md | needs_review, quarantine | quarantine (contains_secret 0.87) |
| family/private-skip-me.md | skipped, never read | skipped, never read |

**The offline client is not Jev.** It is a handful of keyword rules so the plumbing can be tested. Its labels will be wrong on real notes.
