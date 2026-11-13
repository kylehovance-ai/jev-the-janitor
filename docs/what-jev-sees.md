# What Jev sees

For each note it judges, a live run sends one object and the taxonomy's questions. This page uses TypeSafe's word for that object: the [state](https://docs.typesafe.ai/concepts/state). The full contract, with every edge case and its history, is [the privacy contract](privacy-contract.md).

## The state: exactly seven fields

`build_state` in [`janitor/scan.py`](../janitor/scan.py) builds the state, and it has these seven keys and no others:

| field | what it is | what is redacted or cut |
|---|---|---|
| `title` | the note's title | redacted |
| `path` | the note's path inside the vault, in posix form | redacted one folder or file name at a time, with the `/` separators kept |
| `frontmatter_keys` | the names of the note's frontmatter keys | names only, never values; each name is redacted; the tool's own `janitor` key is left out |
| `aliases` | the frontmatter `aliases`, or `alias` when there is no `aliases` key | each alias is redacted like the title |
| `excerpt` | the body | redacted first, then cut at the excerpt cap |
| `other_note_titles` | the titles of other notes in the same folder | the closest by word overlap with this note's title, at most 80, each redacted and then cut to 80 characters. Never listed: a note on a sensitive path, under a hidden folder or `_janitor/`, one that was not read, or one whose title holds a credential (the seven formats below). A title with any other hit, such as an `EMAIL`, `PHONE`, `CARD` or `SSN` match or a denylist match (`NAME`), is listed in its redacted form, with the label in place of the match |
| `graph` | counts and flags about the note's place in the vault | exactly nine keys: `words` (banded), `headings`, `age_days` (banded), `out_links`, `in_links`, `embeds`, `unresolved_links`, `is_moc`, `is_orphan` |

## The defaults

- The excerpt is the first 16,000 characters of the redacted body (`MAX_EXCERPT`). `--excerpt-chars N` sends the first N instead, and `--excerpt-chars full` sends whole notes up to the 60,000-character hard guard (`HARD_EXCERPT_CAP`), which also bounds any N.
- Up to 80 sibling titles are sent (`MAX_TITLES`), each cut to 80 characters (`MAX_TITLE_CHARS`).
- The graph has the nine keys above.

## The questions

Every live call also carries the seven questions in [`janitor/taxonomies/vault_memory.yaml`](../janitor/taxonomies/vault_memory.yaml): the `bucket` choice, the `persist` score and five nouls (`contains_secret`, `looks_like_duplicate`, `records_a_decision`, `is_actionable`, `safe_to_leave_in_git`). They are sent as written in that file: they are not redacted, and the denylist does not apply to them. Their wording is on [What Jev is asked](what-jev-is-asked.md).

## What never leaves

What never leaves the machine includes the following; the list is not exhaustive.

- **Frontmatter values**, except these: a non-empty `title` string becomes the state's `title` (and this note's entry in other notes' `other_note_titles`); `aliases`, or `alias` when there is no `aliases` key, becomes `aliases`; and the earliest parseable `created`, `date`, `created_at` or `creation_date`, or else the date in `janitor.created_from_mtime`, becomes `graph.age_days`, as a band of days, never as the date itself. Every other value stays local: the state carries the key names only.
- **The absolute path.** The state's `path` is relative to the vault.
- **Notes under a hidden folder, and hidden files**, any name starting with `.` inside the folder you scan: they are planned as `skip_hidden` and never opened, and `--include-sensitive` does not change that. A hidden folder you name as the target is scanned as named. A single note you name is skipped when a folder above it is hidden.
- **Notes under `_janitor/`**, the tool's own working folder, including when you name it or a folder inside it: they are planned as `skip_janitor` and never opened, whatever the flags.
- **Notes under sensitive folders**, unless you pass `--include-sensitive`. Even then, their titles are never listed as another note's sibling, and they are sent with no sibling titles of their own.
- **A note with a credential hit** (`KEY`, `WEBHOOK`, `JWT`, `PEM`, `AWS_SECRET`, `BEARER` or `URL_CREDENTIAL`) in its own title, aliases, path, frontmatter key names or body: it is decided locally as a quarantine and is not sent. This is local triage, so `--no-local-triage` turns it off, and the note is then sent with the hit redacted.
- **A note local triage decides.** The rules, in the order `janitor/triage.py` checks them: a credential hit (above), an empty body or one with only headings, and an exact duplicate of a note earlier in plan order (the first copy is sent). Under `--show-payload` such a row says `sent: null`; without that flag no row has a `sent` key. `--no-local-triage` sends these to Jev instead.
- **A locked note** (`janitor.locked: true`): it is skipped with no request, whatever the flags.
- **A note that is not valid UTF-8, or that cannot be read**: its row is a `skip_undecodable` skip or an error, nothing of it is sent, and it is never listed as another note's sibling.
- **The body past the excerpt cap.** The body is redacted whole and then cut, so only the first `--excerpt-chars` characters of the redacted body leave (16,000 by default; `full` is still cut at the 60,000-character guard).
- **The original text of a redaction hit**, such as an `EMAIL`, `PHONE`, `CARD` or `SSN` match or a denylist match: it is replaced by its label, such as `[EMAIL]` or `[NAME]`, in every text field before sending, while the note itself still leaves. Redaction is best-effort: a format it does not recognise leaves as written (see [the privacy contract](privacy-contract.md)).

## An example

One real state from the [demo vault](../examples/demo-vault), the note `Areas/Health/Running.md`, printed with these two commands (nothing is sent, and no key is needed):

```bash
jev-janitor examples/demo-vault --offline --json --show-payload --journal off --quiet > rows.json
python -c "import json; print(json.dumps(next(r for r in json.load(open('rows.json', encoding='utf-8')) if r.get('path') == 'Areas/Health/Running.md')['sent'], indent=2))"
```

```json
{
  "title": "Running",
  "path": "Areas/Health/Running.md",
  "frontmatter_keys": [
    "aliases",
    "created"
  ],
  "aliases": [
    "Running plan"
  ],
  "excerpt": "# Running\n\nStanding plan: three runs a week, one long, one easy, one with some effort. The river loop is 5.1 km; the long route over the hill is 11.4 km.\n\nShoes last about 700 km for me; the current pair started at 0 in [[Running log]].\n\nResting heart rate has drifted from 62 to 55 over two years of this. That is the only number I track that I trust.",
  "other_note_titles": [
    "Running log",
    "Doctor visit summary",
    "Sleep notes",
    "Stretches"
  ],
  "graph": {
    "words": 71,
    "headings": 1,
    "age_days": 1000,
    "out_links": 1,
    "in_links": 1,
    "embeds": 0,
    "unresolved_links": 0,
    "is_moc": false,
    "is_orphan": false
  }
}
```

The note is short, so the excerpt is the whole body, untrimmed.

## Check it yourself

Run `jev-janitor PATH --offline --json --show-payload` on your own vault. Each row's `sent` object is exactly the state a live run would transmit for that note (`null` for a note decided locally), and nothing leaves the machine while you read it. The questions are not in it; they are the taxonomy file, as written.
