# Security

In live mode this tool sends redacted note excerpts to TypeSafe's hosted Jev API.
`--offline` sends nothing.

## Exactly what is sent, per note

This list is the same as the README's "What leaves the machine" and is what `build_state`
in `janitor/scan.py` assembles; nothing else is sent.

- title, after local redaction
- the frontmatter `aliases`, redacted exactly like the title (the one frontmatter value sent)
- vault-relative posix path (never absolute, never the OS username)
- frontmatter key names only
- the first 16,000 characters of the body by default, after local redaction; `--excerpt-chars N`
  sends the first N and `--excerpt-chars full` sends whole notes up to a 60,000-character
  guard. The body is redacted first, then cut. (Through 0.2.0 the default was 1,200; this
  file said 1,200 until 0.4.1, which understated what leaves.)
- titles of other notes in the same folder: the 80 closest by word overlap with the note's
  own title, each cut to 80 characters, with sensitive and hidden paths excluded unconditionally
- graph facts as numbers: word, heading and link counts, in-degree, embeds, age band,
  `is_moc`, `is_orphan`. Counts only; no link target is named, and a link into a sensitive or
  hidden path is counted with its name omitted

## What is never sent

- bodies of notes on sensitive paths (`family`, `private`, `personal`, `secrets`, `inbox`
  by default; override with `--sensitive-paths`)
- titles of notes on sensitive paths as sibling context for any other note, even when
  `--include-sensitive` scans their bodies (a note you opt in is judged by its own title)
- absolute paths, frontmatter values other than `aliases`, anything past the excerpt cap
- the bodies of the notes a note links to
- the API key, other than in the SDK's request header

## Records (`jev-records`)

For a JSONL record, only the values under `sent` leave, as
`{"fields": {name: value}, "field_names": [...]}`: every string redacted then cut at the
excerpt cap, every number redacted in its string form (a 16-digit Luhn-valid integer is a
`[CARD]`), lists element by element. Field names are sent and must be identifiers, or the
file is refused before any request. The `id` is never sent; it is on the row and in the
journal raw, like the vault path. Nothing else on the line is read. A record with a
credential-format hit (`KEY`, `WEBHOOK`, `JWT`, `PEM`, `AWS_SECRET`, `BEARER`) is never sent
at all, and that is not switchable off. No value from `sent` reaches a row, the table or the
journal; `--show-payload` puts the exact sent state on report rows only. The source file is
never written.

## Pre-flight

In live mode the CLI prints how many notes will be sent, which folders are included, and
which are skipped with the rule that skipped them, then the bill as a range, then requires
confirmation. `--plan` prints the same without a key; `--yes` skips only the question,
never the summary.
Sensitive folder names match as whole words of a folder name, case-insensitively: the name
is split into its alphanumeric words and the sensitive name must appear as a run of whole
words. `_Inbox`, `00 Inbox`, `Private Notes` and `_private` are skipped (through 0.4.0 the
match was exact and all four were scanned); `private-equity` is skipped too, and every
skipped folder is named in the pre-flight so an over-match is visible. `inboxes` or `myinbox`
is a different word, is scanned, and is listed as a near-miss warning. The warnings cover
only folders that hold a sensitive name inside a longer word. A sensitive folder with an
unrelated name (`Governance/`, `core/identity/`) produces no warning; the included-folders
list is the only control for it, and reading it is the operator's job. A sensitive name
above the folder you name refuses the run with exit code 1 rather than skipping everything.
Folders and files beginning with `.` are skipped by a separate rule that `--include-sensitive`
does not lift.

## Redaction is best-effort

`janitor/redact.py` replaces, before the call, in the note's title, its aliases, its
excerpt and the sibling titles alike:

- credentials in these documented formats, and only these: OpenAI and Anthropic (`sk-`);
  Stripe secret and restricted keys (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`) and
  webhook signing secrets (`whsec_`); AWS access key ids (`AKIA`); Google API keys (`AIza`)
  and OAuth client secrets (`GOCSPX-`); GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`,
  `ghr_`, `github_pat_`); GitLab personal access tokens (`glpat-`); Slack tokens (`xoxb-`,
  `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xoxe-`, `xapp-`) and incoming webhook URLs; Discord
  webhook URLs; SendGrid keys (`SG.`); npm tokens (`npm_`); Hugging Face tokens (`hf_`);
  Telegram bot tokens (an 8-to-10-digit id, a colon, a 35-character secret starting with
  `A`, in prose, after `token:`, in an `=` assignment, quoted, or inside a Bot API URL;
  0.4.1 leaked the last two, and an AWS ARN's 12-digit account id is not an id). Each becomes
  `[KEY]` or `[WEBHOOK]` and quarantines the note locally. The match is on the vendor's
  documented case: `GHO_` is not a GitHub token (through 0.4.0 the key line was case-blind).
  (Through 0.4.0 only the oldest prefix of the first five vendors was covered, and a
  Telegram bot token left as `[PHONE]:` followed by its secret half.)
- bearer tokens, JWTs, PEM private-key blocks, AWS secrets (`[BEARER]`, `[JWT]`, `[PEM]`,
  `[AWS_SECRET]`; these quarantine too)
- emails, phone numbers, card numbers, SSNs and denylisted names (`[EMAIL]`, `[PHONE]`,
  `[CARD]`, `[SSN]`, `[NAME]`; these redact but do not quarantine, because they
  false-positive on ordinary prose)

Regexes miss things. Run `--offline --json --show-payload` and read the `sent.excerpt`
fields before scanning a vault that matters. Use `--denylist` for names and codenames that
must never leave.

## Writes

`--apply` generates the `janitor:` frontmatter block only; every other header line and
the whole body are spliced back byte-for-byte via a temp file and atomic replace. It never deletes. Quarantine moves a
note unchanged to `_janitor/quarantine/<its vault-relative path>`, writes a `.gitignore`
containing `*` into that folder on the first move, and appends a line per move to
`_janitor/quarantine/manifest.jsonl` (original path, destination, reason, time). The
ignore rule keeps the moved note out of a future commit; it does not remove the note's
old path from history if it was ever committed there.

## Keys

Never commit `.env` or a real `TYPESAFE_API_KEY`. The `.gitignore` excludes `.env`.

## Reporting

If you find a way for note content to leave the machine that this document does not
describe, report it privately to the repository owner rather than in a public issue.
