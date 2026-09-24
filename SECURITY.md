# Security

In live mode this tool sends redacted note excerpts to TypeSafe's hosted Jev API.
`--offline` sends nothing.

## Exactly what is sent, per note

This list is the same as the README's "What leaves the machine" and is what `build_state`
in `janitor/scan.py` assembles; nothing else is sent.

- title, after local redaction
- the frontmatter `aliases`, redacted exactly like the title (the one frontmatter value sent)
- vault-relative posix path, redacted like the title one segment at a time (never absolute,
  never the OS username; through 0.4.6 it left as written, so a denylisted name in a
  filename and a key in a folder name went out)
- frontmatter key names only, redacted like the title (through 0.4.6 as written)
- the first 16,000 characters of the body by default, after local redaction; `--excerpt-chars N`
  sends the first N and `--excerpt-chars full` sends whole notes up to a 60,000-character
  guard. The body is redacted first, then cut. (Through 0.2.0 the default was 1,200; this
  file said 1,200 until 0.4.1, which understated what leaves.)
- titles of other notes in the same folder: the 80 closest by word overlap with the note's
  own title, each redacted and then cut to 80 characters (through 0.4.6 cut first, so a name
  or key straddling the cut left as a fragment), with sensitive and hidden paths and any note
  whose own title holds a credential excluded unconditionally
- graph facts as numbers: word, heading and link counts, in-degree, embeds, age band,
  `is_moc`, `is_orphan`. Counts only; no link target is named, and a link into a sensitive or
  hidden path is counted with its name omitted
- the taxonomy's questions, exactly as written in the file, with every call: not redacted,
  and the denylist does not apply to them

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
`[CARD]`), lists element by element. Field names are sent and must be identifiers that
neither the redactor nor the denylist would change, or the file is refused before any
request (through 0.4.6 the names skipped the denylist). The `id` is never sent; it is on the row and in the
journal raw, like the vault path. Nothing else on the line is read. A record with a
credential-format hit (`KEY`, `WEBHOOK`, `JWT`, `PEM`, `AWS_SECRET`, `BEARER`, `URL_CREDENTIAL`) is never sent
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
does not lift; for a single file the hidden folders above it count too, from the vault root
(the nearest `.obsidian/`) down, or every ancestor without a marker (through 0.4.6 only the
file's own name was tested), while a hidden directory you name is scanned as named.

## Redaction is best-effort

`janitor/redact.py` replaces, before the call, in the note's title, its aliases, its path,
its frontmatter key names, its excerpt and the sibling titles alike:

- credentials in these documented formats, and only these: OpenAI and Anthropic (`sk-`);
  Stripe secret and restricted keys (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`) and
  webhook signing secrets (`whsec_`); AWS access key ids, permanent (`AKIA`) and temporary
  (`ASIA`; through 0.4.6 an assume-role id went out); Google API keys (`AIza`)
  and OAuth client secrets (`GOCSPX-`); GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`,
  `ghr_`, `github_pat_`); GitLab personal access tokens (`glpat-`); Slack tokens (`xoxb-`,
  `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xoxe-`, `xapp-`) and incoming webhook URLs; Discord
  webhook URLs; SendGrid keys (`SG.`); npm tokens (`npm_`); Hugging Face tokens (`hf_`);
  Telegram bot tokens (an 8-to-10-digit id, a colon, a 35-character secret starting with
  `A`, in prose, after `token:`, in an `=` assignment, quoted, or inside a Bot API URL;
  0.4.1 leaked the last two, and an AWS ARN's 12-digit account id is not an id). Each becomes
  `[KEY]` or `[WEBHOOK]` and quarantines the note locally. The match is on the vendor's
  documented case: `GHO_` is not a GitHub token (through 0.4.0 the key line was case-blind).
  A key is taken after a JSON escape (a literal `\n` or `\t`), after a percent-encoded byte
  (`%3D`) and, for a JWT, after an underscore, and still not when glued to a letter (through
  0.4.6 all four went out with no hit).
  (Through 0.4.0 only the oldest prefix of the first five vendors was covered, and a
  Telegram bot token left as `[PHONE]:` followed by its secret half.)
- a password inside a URL: `scheme://user:password@host`, or `scheme://:password@host` with no
  user, whatever the scheme (`postgres://`, `mongodb+srv://`, `redis://`, `amqp://`, `https://`,
  the two-part `jdbc:mysql://` and the rest). The user and the password become
  `[URL_CREDENTIAL]` together; the scheme and host stay; the note quarantines. The password
  is every non-whitespace character up to the last `@` of the run, so an unencoded `@`, `:`,
  `#`, `?`, `/` or quote inside it leaves no fragment; only whitespace ends it. A host and port
  followed by a later `@` is not a credential: one to five digits, or a `${PORT}`-style
  placeholder, followed by `/`, `?` or `#` is a port, but only when something follows, so
  digits that run straight into the `@` (`root:1234@`, `admin:12345@`) are a password and
  quarantine, and the phishing shape, an `http://` URL whose authority reads
  `localhost:8080@evil.example.com`, counts as a credential too, on purpose; a user never
  runs past a `?` or `#`
  (`obsidian://open?vault=Main:Notes@home` is not a credential); and `[` starts an IPv6
  literal, not a user. A placeholder password is left alone
  and does not quarantine: `${VAR}` in any case, a bare `$VAR` or `%VAR%` only in upper case
  with digits and underscores (so `$Zq7vR2mW9x` is a password, and an all-caps password that
  starts with `$` is the residual that reads as a placeholder), `{{ var }}`, `<password>`,
  `[password]`, the words `password`, `passwd`, `pass`, `pwd`, `secret`, `changeme` and
  `changeit` in any case, and a run of `x`, `*` or dots. This rule runs before every other. (Through 0.4.6 a
  `localhost` or IP-address URL's password went out in the clear, and a dotted-host one was
  masked as `[EMAIL]` with the user still sent and no quarantine. Key-and-value forms such as
  `Password=…;` are not covered.)
- bearer tokens, JWTs, PEM and PGP private-key blocks, AWS secrets (`[BEARER]`, `[JWT]`,
  `[PEM]`, `[AWS_SECRET]`; these quarantine too). A block without its END line runs to the
  first blank line or the end of the text (through 0.4.6 a PGP block and an unterminated
  block went out whole); an AWS secret is taken with any spacing around the `=` or `:`
  (through 0.4.6 a padded line went out), and under `SecretAccessKey`, `secret_access_key`,
  `SessionToken` and `session_token` with no `aws` in front (through 0.4.6 no hit at all)
- emails, phone numbers, card numbers, SSNs and denylisted names (`[EMAIL]`, `[PHONE]`,
  `[CARD]`, `[SSN]`, `[NAME]`; these redact but do not quarantine, because they
  false-positive on ordinary prose). A denylist entry matches across any run of whitespace,
  a line break included, and in its own redacted form; entries under three characters are
  ignored and the CLI says so. A card after a leading count or year is still found. A number
  with a leading `+` and country code is a phone; `case`, `id` and `part` mark an identifier
  only with an explicit `#`, `no.` or `number` after them (through 0.4.6 each of these went
  out)

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
