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
| `other_note_titles` | the titles of other notes in the same folder | the closest by word overlap with this note's title, at most 80, each redacted and then cut to 80 characters; a note on a sensitive path, or one whose title holds a credential, is never listed |
| `graph` | counts and flags about the note's place in the vault | exactly nine keys: `words` (banded), `headings`, `age_days` (banded), `out_links`, `in_links`, `embeds`, `unresolved_links`, `is_moc`, `is_orphan` |

## The defaults

- The excerpt is the first 16,000 characters of the redacted body (`MAX_EXCERPT`). `--excerpt-chars N` sends the first N instead, and `--excerpt-chars full` sends whole notes up to the 60,000-character hard guard (`HARD_EXCERPT_CAP`), which also bounds any N.
- Up to 80 sibling titles are sent (`MAX_TITLES`), each cut to 80 characters (`MAX_TITLE_CHARS`).
- The graph has the nine keys above.

## The questions

Every live call also carries the seven questions in [`janitor/taxonomies/vault_memory.yaml`](../janitor/taxonomies/vault_memory.yaml): the `bucket` choice, the `persist` score and five nouls (`contains_secret`, `looks_like_duplicate`, `records_a_decision`, `is_actionable`, `safe_to_leave_in_git`). They are sent as written in that file: they are not redacted, and the denylist does not apply to them. Their wording is on [What Jev is asked](what-jev-is-asked.md).

## What never leaves

- **Frontmatter values**, other than `aliases` (or `alias`): the state carries the key names only.
- **The absolute path.** The state's `path` is relative to the vault.
- **Notes under hidden folders**, a folder or file name starting with `.`: they are never read, and `--include-sensitive` does not change that.
- **Notes under sensitive folders**, unless you pass `--include-sensitive`. Even then, their titles are never listed as another note's sibling.
- **A note with a credential hit** (`KEY`, `WEBHOOK`, `JWT`, `PEM`, `AWS_SECRET`, `BEARER` or `URL_CREDENTIAL`) in its own title, aliases, path, frontmatter key names or body: it is decided locally as a quarantine and is not sent. This is local triage, so `--no-local-triage` turns it off, and the note is then sent with the hit redacted.
- **Any note a local triage rule decides** (an empty body, an exact duplicate, a credential hit): its row says `sent: null`. `--no-local-triage` sends these to Jev instead. A locked note (`janitor.locked: true`) is skipped with no request whatever the flags.

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
