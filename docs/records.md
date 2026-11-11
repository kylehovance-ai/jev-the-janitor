# Records in, rows out: `jev-records`

The same machine for things that are not files in a vault. Hand it a JSONL file of records and a question set, and get one row per record: every Choice's pick with full probabilities and margin, every Score, every Noul, the model that answered, the fingerprint of the question set, the API's token count, and an action. No vault walk, nothing written to the source, results to stdout or a sidecar.

```bash
jev-records ./examples/records.jsonl --questions ./examples/triage.yaml --offline          # table on stdout
jev-records ./examples/records.jsonl --questions ./examples/triage.yaml --plan             # the pre-flight and the bill, no key needed
jev-records ./examples/records.jsonl --questions ./examples/triage.yaml --json --show-payload   # what would leave, per record
jev-records ./records.jsonl --questions ./triage.yaml --yes --out ./rows.jsonl             # live; rows to a sidecar
```

```python
from pathlib import Path
from janitor.records import judge_records
rows = judge_records(Path("records.jsonl"), Path("triage.yaml"), offline=True, journal_dir=None)
```

**A record is one JSON object per line, and two keys are read.** `id` is the row's address: a string, unique in the file, raw on the row and in the journal exactly as the vault path is, so the caller can join rows back. It is **not sent**: an address is not evidence, and if something should be judged it goes under `sent`. `sent` is the only thing that leaves: an object of strings, numbers, booleans or lists of strings, keyed by identifier-shaped names (`[A-Za-z_][A-Za-z0-9_]{0,63}`), because field names are sent too and a name is caller text; a name the redactor or the denylist would change refuses the file (through 0.4.6 the names skipped the denylist, so `john_smith` was accepted under a denylist holding `john`). A nested object, a list holding anything but strings, a name that is not an identifier, a missing or duplicate `id`, or an empty `sent` refuses the whole file before any request, naming the line and never quoting the text. Everything else on the line is never read.

**What leaves, per record:** `{"fields": {name: value}, "field_names": [...]}`, and nothing else. Every string is redacted with the denylist and then cut at `--excerpt-chars` (16,000 by default; `full` is the 60,000 guard), so a secret straddling the cap cannot leave as a fragment. Every number is redacted in its string form: a 16-digit integer that passes Luhn and starts with a payment network's digit, 2 to 6, is a `[CARD]` (`1000000000000008` passes Luhn, starts with 1, and is sent as a number) and a phone-shaped one a `[PHONE]` whatever the JSON type, and a number that redaction did not change is sent as a number. Lists are redacted element by element. A secret split across two elements or two fields is two fragments to a regex and is not caught, the same limit as the vault scan. Two records with identical `sent` share a cache key and are judged once per run; the second row says `same_as` the first.

**A credential hit means the record is never sent.** Any `[KEY]`, `[WEBHOOK]`, `[JWT]`, `[PEM]`, `[AWS_SECRET]`, `[BEARER]` or `[URL_CREDENTIAL]` hit in `sent` makes a `judge: local, action: quarantine` row with null votes and no request. This is the vault scan's default behaviour, and on the records path it is not switchable off. `quarantine` on a record row means held back; there is no file to move. After a vote, a `contains_secret` Noul at or above 0.7 quarantines too, and the 0.55 review floor applies to the Choice named by `review_choice` in the question set (or `--review-choice`), defaulting to the file's first Choice; the row says which.

**Rows, journal, bill.** No string from `sent` reaches a row, the stdout table (id, pick, confidence, action, reason) or the journal: labels, numbers and fixed phrases only. `--show-payload` puts the exact `sent` state on each row of `--json` or `--out`, never in the journal; it is the audit instrument, the same as for the vault scan, and what a grader needs. The journal lives in the user cache dir under a hash of the records file's path (`--journal DIR|off|default`), and the newest one serves identical records on the next run unless `--no-cache`; for a double run to score stability, use `--journal off` or a fresh directory per run. The bill, the `--max-usd` ceiling, `--over-budget`, the concurrency and the error-rate stop are the vault scan's. The key comes from `TYPESAFE_API_KEY`, outside any file. The example question set, [`examples/triage.yaml`](../examples/triage.yaml), triages product ideas into lanes; any Choice, Scores and Nouls in the `questions:` layout work.
