# Jev the Janitor

A janitor for markdown vaults. It asks [TypeSafe Jev](https://typesafe.ai) which bucket each note belongs in. It never deletes a note and never rewrites a note's body; the most it does is add a block of frontmatter or move a suspected secret to a quarantine folder.

This project is not affiliated with, endorsed by, or supported by TypeSafe. It calls their public API.

**What Jev is.** Jev is a "System One" model from TypeSafe: instead of generating text, it takes a piece of state and a set of typed questions and returns typed answers with calibrated probabilities. A `Choice` picks one of your options, a `Score` places the state on your rubric, a `Noul` is the probability a statement is true. It cannot emit prose, so it cannot invent a folder name or "improve" a sentence. This tool uses that as a traffic light for tidying notes.

**Who this is for.** Anyone with a folder of `.md` files that has grown past what they can hand-sort: Obsidian vaults, wikis, the notes directory a team of tools keeps dumping into. Nothing here depends on Obsidian.

**Does it work.** Yes, with limits stated below. It has been run against live Jev on an invented fixture vault and on 26 real notes from one production vault, with the results measured and reported in this README. It has not been calibrated on anyone else's vault. Expect to edit the taxonomy after your first dry run.

```
note excerpt (redacted locally)
        +
seven typed questions: bucket, persist, secret, duplicate, decision, actionable, git-safe
        ->
Jev (System One)
        ->
typed vote with probabilities
        ->
dry-run report  |  --apply: frontmatter, or quarantine
```

Jev votes. Your code files. You review the low-confidence pile.

## Quick start

Offline first. This uses a keyword stand-in instead of Jev, needs no key, and sends nothing anywhere:

```bash
git clone https://github.com/kylehovance-ai/jev-the-janitor.git
cd jev-the-janitor
pip install -e ".[dev]"
pytest -q
jev-janitor ./fixtures/notes --offline
```

Then live. `--plan` shows what would be sent without sending it:

```bash
pip install -e ".[jev]"           # adds typesafe-sdk
export TYPESAFE_API_KEY=...       # from TypeSafe
jev-janitor ./fixtures/notes --plan
jev-janitor ./fixtures/notes --json
```

Dry run is the default. Nothing is written until you pass `--apply`.

```bash
# Write janitor.* frontmatter onto each note; move suspected secrets to _janitor/quarantine/
jev-janitor ./vault --apply

# Your own sensitive folder names (replaces the default list; matched as whole words of a folder name)
jev-janitor ./vault --sensitive-paths family,private,_inbox,clients

# Strip names or terms locally before anything is sent
jev-janitor ./vault --denylist ./my-denylist.txt
```

Full usage:

```
jev-janitor PATH [--plan] [--apply] [--offline] [--yes] [--include-sensitive]
                 [--sensitive-paths a,b,c] [--denylist FILE]
                 [--taxonomy FILE] [--model jev-latest] [--json] [--show-payload]
                 [--git-unsafe-below P]
                 [--journal default|vault|off|DIR] [--resume [JOURNAL]] [--no-cache]
                 [--workers N] [--excerpt-chars N|full] [--journal-info] [--quiet]
                 [--no-local-triage] [--max-usd USD] [--over-budget]
                 [--config FILE] [--no-config] [--review-pile FILE] [--diff [JOURNAL]] [--survey [N]] [--map FILE]
```

`python -m janitor.cli` works the same way without installing the script. Requires Python 3.11+.

## The privacy contract

**What leaves the machine**, per note, in live mode only:

- the title, after local redaction
- the vault-relative path in posix form, redacted like the title one folder or file name at a time with the separators kept: never the absolute path, never your username or directory tree. (Through 0.4.6 the path left as written, so a denylisted name in a filename went out in the clear while the title showed `[NAME]`, and a key in a folder name never quarantined. A ten-digit run in a filename now reads as `[PHONE]`, which over-redacts an identifier in the safe direction.) A filename stem that the redactor would change is used as the fallback title as written, not with its `-` and `_` turned into spaces, so a token-shaped filename with no title and no H1 is redacted rather than split into words no pattern matches; and a note whose own title holds a credential is never listed as a sibling title (through 0.4.6 such a title went out in the clear in every neighbour's list) The report's own `path` column is local and stays as written
- the names of frontmatter keys, redacted like the title, never their values (through 0.4.6 the names left as written)
- the first 16,000 characters of the body after local redaction by default; `--excerpt-chars N` sends the first N, `--excerpt-chars full` sends whole notes up to a 60,000-character guard. The body is redacted first, then cut, so a larger cap means more text redacted, never less, and a secret straddling the cap cannot leave as a fragment
- the titles of the other notes in the same folder, for duplicate detection, with sensitive paths excluded unconditionally: the 80 closest by word overlap with the note's own title, each redacted and then cut to 80 characters, for a directory scan and a single-file scan alike (through 0.3.0 it was the alphabetical first 80, uncut, so in a large folder a near-duplicate was never listed; through 0.4.7 a single-file scan still took the alphabetical first 80, so with 81 siblings it dropped the one near-duplicate the directory scan kept; through 0.4.6 the cut came before redaction, so a name or key straddling the cut left as a fragment with no token)
- graph facts as numbers, computed locally from one index pass: word, heading and link counts, in-degree, embeds, age in days, `is_moc`, `is_orphan`. Age is *creation* age: days since the earliest parseable `created`, `date`, `created_at` or `creation_date` in the frontmatter, with the file's mtime used only when none of them parses. For a note that carries a parseable one, editing it does not make it younger and a fresh clone does not make it new; a note without one, or whose value does not parse (`created: not-a-date` counts as none), takes the filesystem's date, which resets when the vault is moved, cloned, restored or re-synced (each row says which, as `age_source`). (Through 0.3.0 it was days since last touched, which made `is_orphan` unreachable on any cloned, restored or synced vault.) `is_orphan` is reported as unknown, not as a count, when fewer than one scanned note in twenty links out at all: on a vault that references notes by path rather than by link, in-degree is zero everywhere and says nothing, and the run's last lines say so. A subfolder scan also cannot see links from the rest of the vault. Counts only: the facts name no link target, and a link into a sensitive or hidden path is counted with its name omitted. (A `[[wikilink]]` you wrote in a body is body text and leaves inside the excerpt like any other text; that was always so.) Words are sent to two significant figures and age as a band (0, 1, 7, 30, 90, 365, 1000 days). The key hashes the whole state, so it changes whenever any sent field changes: the title, the aliases, the path, the frontmatter key names, the excerpt, the sibling titles, or any of the nine graph facts (`words` to two figures, `headings`, `age_days` as a band, `out_links`, `in_links`, `embeds`, `unresolved_links`, `is_moc`, `is_orphan`). A heading or a link added past the excerpt cap therefore changes the key, because `headings` and `out_links` count the whole note; and three facts depend on other notes, so a key can change without the note being edited: `in_links` when another note links to it or stops, `unresolved_links` when a note it links to is created or removed, and `is_orphan` through `in_links` and through the vault's linking share, which turns it to unknown on a vault that barely links. `is_moc` does not: it is the note's own link count against its own word count, and a target appearing or vanishing moves neither (through 0.4.9 this sentence named `is_moc` here instead of `unresolved_links`). A key also changes at midnight UTC on the day a note crosses a band edge: on any given day that is the notes turning exactly 1, 7, 30, 90, 365 or 1000 days old, about half a percent of a vault spread over three years. (Measured on a real 26-note vault: 25 of 26 keys stable across a day; the one that moved had turned a band age.)
- the frontmatter `aliases`, or the singular `alias` when there is no `aliases` key (with both present only `aliases` is sent), redacted exactly like the title. This is the one frontmatter value that is sent: an alias is a second title
- the taxonomy's questions, exactly as written in the file, with every call: they are not redacted and the denylist does not apply to them, so keep names and secrets out of a question file

**What never leaves:**

- the body of any note on a sensitive path unless you pass `--include-sensitive`, and even then its title is never listed as sibling context for any other note
- absolute filesystem paths
- anything past the excerpt cap (16,000 characters unless you change it)
- frontmatter values, other than `aliases` (or `alias`)
- the bodies of the notes a note links to. A linked note's title does leave when it is one of the sibling titles listed for a note in the same folder, redacted like any other title; its path never does, other than as you wrote it inside the linking note's own body
- your API key, other than in the request header the SDK builds

**Sensitive paths** are folder names matched as whole words, per path segment, case-insensitively: a folder name is split into its alphanumeric words, and the sensitive name has to appear as a run of whole words. So `_Inbox`, `00 Inbox`, `0 - Inbox`, `Private Notes` and `_private` are skipped (through 0.4.0 the match was exact and every one of these was scanned), and `private-equity/` is skipped too, which is the safe way to be wrong; the pre-flight names every skipped folder, so an over-match is visible there. `inboxes/` or `myinbox/` is a different word, is scanned, and is named as a near-miss. The file's own name never counts. The default list is `family`, `private`, `personal`, `secrets`, `inbox`. Replace it with `--sensitive-paths`; a multi-word entry such as `Private Notes` matches those words in that order. Folders and files beginning with `.` are skipped by a separate rule that `--include-sensitive` does not lift; for a single file the hidden folders above it count too, from the vault root (the nearest `.obsidian/`) down, or every ancestor when there is no marker (through 0.4.6 only the file's own name was tested, so `jev-janitor ./vault/.trash/x.md` scanned a note that `jev-janitor ./vault` skipped), while a directory you name that is itself hidden is scanned as named. The path you name is tested too, against its own absolute folder names, so `jev-janitor ./vault/family` skips everything under it just as `jev-janitor ./vault` skips `family/`. A sensitive name *above* the folder you name is a different case: a vault that itself lives under a folder called `personal` says nothing about the notes inside it, so rather than skip everything and report a green run that judged nothing, the janitor refuses with exit code 1 and names both ways through, `--include-sensitive` or `--sensitive-paths` with that name dropped from the list. `--plan` shows the refusal and exits 0. A single file under a sensitive folder is skipped quietly either way. When the vault carries an `.obsidian/` folder at its root, that root is where "inside" and "above" are measured from: `jev-janitor ./vault/family/2024` skips quietly because `family` is your own taxonomy, and `~/personal/vault` refuses because `personal` is where the vault was mounted. Without the marker, position alone cannot tell the two apart, and everything above the folder you name counts as above. These comparisons are local; the absolute path never leaves the machine.

**Redaction is best-effort.** Before the call, local regexes replace credentials in these documented formats, and only these: OpenAI and Anthropic (`sk-`), Stripe secret and restricted keys (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`) and webhook signing secrets (`whsec_`), AWS access key ids, permanent (`AKIA`) and temporary (`ASIA`; through 0.4.6 an assume-role id went out), Google API keys (`AIza`) and OAuth client secrets (`GOCSPX-`), GitHub tokens of every prefix (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), GitLab personal access tokens (`glpat-`), Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xoxe-`, `xapp-`) and incoming webhook URLs, Discord webhook URLs, SendGrid keys (`SG.`), npm tokens (`npm_`), Hugging Face tokens (`hf_`) and Telegram bot tokens; plus bearer tokens, JWTs, PEM and PGP private-key blocks, AWS secrets, emails, phone numbers, card numbers, SSNs and anything in your denylist, all with typed tokens such as `[KEY]`, `[WEBHOOK]`, `[JWT]`, `[PEM]` and `[NAME]`. A password inside a URL is a credential in its own right: any `scheme://user:password@host`, or `scheme://:password@host` with no user, whatever the scheme (`postgres://`, `postgresql+psycopg2://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://`, `https://`, `ftp://`, `smtp://`, `ldap://`, the two-part `jdbc:mysql://`), becomes `scheme://[URL_CREDENTIAL]@host`: the user and the password go together, because the user is identifying too, and the scheme and host stay, so the model still sees a local postgres URL. The password is every non-whitespace character up to the last `@` of the run, so an unencoded `p@ss:w0rd#1`, with `@`, `:`, `#`, `?`, `/` or a quote inside it, leaves no fragment; only whitespace ends it. A host and port followed by a later `@` (`http://localhost:8080/x?email=a@b.com`, `http://localhost:${PORT}/api/users/@me`) is not a credential: one to five digits or a `${PORT}`-style placeholder followed by `/`, `?` or `#` is a port, but only when something follows, so digits that run straight into the `@` (`root:1234@localhost`, `admin:12345@`, the weak defaults dev notes hold) are a password and quarantine, and the phishing shape, an `http://` URL whose authority reads `localhost:8080@evil.example.com`, counts as a credential too, which is the right side to be wrong on; a user never runs past a `?` or `#`, so `obsidian://open?vault=Main:Notes@home` and `x-callback-url://run?name=a:b@c` are not credentials either; and `[` starts an IPv6 literal, not a user. A placeholder where the password goes is left untouched and does not quarantine: template syntax (`${VAR}` in any case; a bare `$VAR` or `%VAR%` only in upper case with digits and underscores, so `$Zq7vR2mW9x` is a password, and an all-caps password that starts with `$` is the residual that reads as a placeholder; `{{ var }}` in any case; one layer of `{…}`, `<…>` or `[…]` only when what is inside is itself a placeholder: an UPPER_SNAKE name (`{DB_PASSWORD}`), one of the placeholder words alone or as a whole word (`<password>`, `[password]`, `<your password here>`), or a run of `x`, `*` or dots, so `{MyRealPassword}` and `<MyRealPassword>` are passwords and quarantine (through 0.4.7 any bracketed value read as a placeholder and those went out with no hit), except that a bracketed password whose user or host is itself a template (`{user}`, `${HOST}`, `<host>`, `%HOST%`) reads as a template too, so an f-string URL such as `postgres://{user}:{db_pw}@{host}/{db}` is code and gets no hit, while `app:{db_pw}@localhost`, with a literal user and host, still counts), the words `password`, `passwd`, `pass`, `pwd`, `secret`, `changeme` and `changeit` in any case, and a run of `x`, `*` or dots. Anything else counts, a default such as `guest` with the password `guest` included. This rule runs first, before every vendor format and before the email rule. (Through 0.4.6 there was no such rule: a `localhost` or IP-address URL's password went out in the clear with no hit at all, and a dotted-host one was masked as `[EMAIL]` from the password's first character to the end of the host, with the user still sent and no quarantine. Key-and-value forms such as `Password=…;` are not covered.) (Through 0.4.0 the list was the first five vendors' oldest prefix each, and the sentence here claimed "GitHub, Google and Slack formats" while `gho_`, `GOCSPX-` and Slack webhooks went out in the clear; a Telegram bot token went out as `[PHONE]:` followed by the secret, because its bot id is phone-shaped and the phone rule ran first. Every credential format now runs before the phone and card rules.) The match is on the vendor's documented case: `gho_` is a GitHub token and `GHO_` is not (through 0.4.0 the key line was case-blind). A key is taken after a JSON escape (a literal `\n` or `\t`), after a percent-encoded byte (`%3D`) and, for a JWT, after an underscore, and still not when glued to a letter (through 0.4.6 all four went out with no hit). A private-key block is taken with or without its END line: an unterminated block runs to the first blank line or the end of the text (through 0.4.6 a PGP block and a block pasted without its END line went out whole). An AWS secret is taken with any spacing around the `=` or `:` (through 0.4.6 a padded `key   =   value` line, as a linter aligns it, went out), and under the names the SDKs print with no `aws` in front, `SecretAccessKey`, `secret_access_key`, `SessionToken`, `session_token` (through 0.4.6 those had no hit at all). And a Telegram token is an 8-to-10-digit id, a colon and a 35-character secret starting with `A`, taken whole after a space, a colon, an `=`, a quote or the `bot` of a Bot API URL (0.4.1 leaked it after a bare colon and inside `api.telegram.org/bot…` URLs; a wider shape had taken an AWS SNS ARN's account id and topic name on a real vault; the Bot API docs' own six-digit example is not a token and is left alone). A note with any credential-format hit is quarantined locally, without asking the model. Denylist terms match whole words (`Ann` no longer turns `Anniversary` into `[NAME]iversary`) across any run of whitespace, a line break included (through 0.4.6 `Jane` at the end of one line and `Doe` at the start of the next did not match `Jane Doe`); an entry that itself holds an email or another pattern hit is matched in its redacted form as well, since the patterns run first; entries under three characters are ignored, and the run says so when it loads the file. Card numbers are replaced only when they pass the Luhn check, have a card's shape (contiguous, 4-4-4-4, or 4-6-5; a 12-digit account id followed by a year is not one, though one such run in ten passes Luhn) *and* start with a payment network's digit, 2 to 6 (sixteen zeros pass Luhn and the shape rule; no card starts with 0); a card after a count or a year (`qty 2 4111 ...`) is still found (through 0.4.6 the leading digit group was taken with it, the shape was refused, and the card went out). A phone-shaped number right after `order`, `invoice`, `ticket`, `ref`, `sku`, `po`, `tracking` or `serial`, or after `case`, `id` or `part` with an explicit `#`, `no.` or `number`, is treated as an identifier, not a phone (through 0.4.6 a bare `case`, `id` or `part` was enough, so `in case: 555-123-4567` went out); a number with a leading `+` and country code (`+44 20 7946 0958`) is a phone, and no bare-digit international shape is attempted, because it would take dates and ids (through 0.4.6 only North American shapes were phones). This applies to the note's title, its aliases, its path, its frontmatter key names, its excerpt, and the sibling titles alike. Regexes miss things. Run `--offline --json --show-payload` and read the `sent` object before pointing this at a vault that matters: it is exactly the seven-field state a live run would transmit for that note (`sent.excerpt` is the body part), and beside it every call carries the taxonomy's questions as written. Without `--show-payload` a row carries the labels that fired (`redacted`), the redacted title (`title_sent`) and the number of sibling titles sent (`sibling_titles_sent`), but neither the excerpt nor the sibling titles themselves; `--show-payload` adds the whole `sent` object to the report and is never written to the journal, because the journal outlives the run and lives outside the vault. `redacted` describes the whole body, not the payload: redaction runs over the full note before the cut, so a hit can be reported that sat past the excerpt cap and never appeared in anything sent. That is conservative on purpose; `sent` is the payload, and `sent.excerpt` is the part of it the body became.

TypeSafe's terms say customer input is not used for training. That is a contract, not physics. This is a cloud round trip to a US-hosted API. If a note must never leave the house, put it on a sensitive path or do not scan it.

### Pre-flight: see the membrane before you cross it

In live mode the janitor prints, before anything is sent, how many notes will go, which folders they are in, which folders are skipped and by which rule, and then asks. Illustrative output:

```
  profile: none (built-in defaults; put a janitor.toml at the vault root to make a scan repeatable)
jev-janitor pre-flight: 25 of 39 notes under vault/ will be sent to TypeSafe
  excerpt: the first 16,000 characters of each note after redaction (default)
  graph facts: word, heading and link counts, age in days, is_moc, is_orphan, and frontmatter aliases redacted like the title ride along; link targets never do
  folders included (3):
    inboxes/                                    2 notes
    notes/                                     12 notes
    projects/garden/                           11 notes
  folders skipped (4):
    .obsidian/                                  6 notes   hidden folder or file '.obsidian' (starts with '.')
    _Inbox/                                     3 notes   sensitive path part '_Inbox'
    _janitor/quarantine/                        1 notes   janitor working folder '_janitor'
    family/                                     4 notes   sensitive path part 'family'
  WARNING: folders that contain a sensitive name inside a longer word and do NOT match it (matching is by whole words of the folder name):
    'inboxes' contains 'inbox' but will be scanned. Add it with --sensitive-paths if it should be skipped.
  bill (estimate): 24 notes to send, 0 served from the journal, 1 decided locally, 0 locked, 14 skipped, 0 undecodable, 0 unreadable
    payload 10,015 chars + questions -> ~15,811 to 21,457 input tokens (3.8 down to 2.8 chars/token, the range measured on real notes), ~$0.0007 to $0.0009 at $0.042 per million
    age: 25 of 25 readable notes (100%) have no creation date in their frontmatter; their age comes from the filesystem and resets if this vault is moved, cloned, restored or re-synced
    ceiling $2.00: under at the pessimistic end (change it with --max-usd or max_usd in janitor.toml; 0 = none)
    largest folders by payload:
      notes/                                          4,929 chars     12 notes
      projects/garden/                                4,813 chars     11 notes
      inboxes/                                          273 chars      1 notes
```

That is the output of `--plan` on a 39-note fixture vault, verbatim. Without `--plan`, a live run ends it with `Send these notes to TypeSafe? [y/N]`.

The third line (after the profile line and the header) always names the excerpt cap, and in capitals when it is not the default, because consenting to send whole notes is a different consent from consenting to send openings. `--plan` prints this and exits. `--yes` skips the question for scripts; the summary is still printed to stderr on every live run, so there is always a record of what was sent. A piped run without `--yes` refuses, because a non-interactive stdin cannot consent.

The warning block catches folders that hold a sensitive name inside a longer word: `inboxes` or `myinbox` against `inbox`. (`_Inbox` and `00 Inbox` need no warning since 0.4.1: they are `inbox` and appear under **folders skipped**.) It cannot warn about a folder that is sensitive but shares no word with the list. `Governance/` or `core/identity/` get no warning, because there is nothing to near-miss against. For those, the **folders included** list is the only control, and it only works if you read it.

**The bill is part of the pre-flight.** After the index pass and before any request, the pre-flight prints how many notes will be sent, served from the journal, decided locally, locked and skipped, then the estimated input tokens and cost computed from the actual redacted payloads (not a per-note constant), and the largest folders by payload, so a flat folder of long notes is visible before it dominates the bill. The estimate divides the payload plus the taxonomy's questions, which ride along with every call (2,086 characters at the default taxonomy: the questions' serialized wire form, counted since 0.4.3; through 0.4.2 a 1,681-character proxy that left out two sentences), by a characters-per-token ratio; the range is 3.8 down to 2.8, measured on real notes, and it has held for prose and been breached by logs: the first live run of 0.4.0 on 31 real notes (350,090 payload characters, 117,633 tokens) came in at 3.53 characters per token overall, the first live run on a synthetic test corpus (182 short synthetic notes, 287,073 tokens) at 3.15, and a live run on a 1,120-note public CC0 wiki (1,015 notes sent) at 3.23. A live run on a 25,107-note real vault (17,140 notes sent, most of them machine-generated logs and task records) measured 2.78, just under the floor: the pessimistic estimate was $2.50 against $2.51 measured, 0.4% light. That is the case the meter below exists for, and it is why the anchors are not moved on one measurement: the floor is a claim about notes, and a vault that is mostly logs can sit at or under it. A real 18,738-note pass at the default cap prints $1.39 to $1.88 and projects to about $1.49 at the 31-note ratio; it has not been run live at this version, so that is a projection, and the $2.00 ceiling clears its pessimistic end by 6%. The 25,107-note vault above did not clear it: its pessimistic end was $2.50, so the default ceiling would have refused that run before sending anything, and it ran under `--max-usd 3.00`. A vault of that size needs the ceiling raised on purpose; the refusal prints both ends of the bill so the choice is informed. (Through 0.4.0 this paragraph said that pass "measured $1.22": that was a payload-only ratio applied to the payload, an inference on the wrong basis. The same paragraph reported the 31-note run as 2.98, which is the payload alone over tokens that included the questions (3.42 with the 1,681-character proxy, 3.53 with the questions as sent); on that basis the measured line flagged the synthetic-corpus run as 1.83 and outside the range, advice that would have inflated every future bill by half, when the pre-flight's own range had bracketed the real bill. The first anchors before any live run, 5.37 from invented prose and 3.66 inferred from refusals, were wrong in the dangerous direction. Each correction came from a measurement, never from a re-read of the code.) The measured line after a run says when a vault falls outside the assumed range. A live run whose *pessimistic* end is over the ceiling ($2.00 by default, `--max-usd`, `0` for none) refuses with exit code 1 before looking for a key, printing the optimistic end in the same breath; `--over-budget` with `--yes` accepts that bill for one run. **The ceiling also meters the run.** The anchors were measured on notes, and text that is not notes breaks them: the first live run on the 2,000-note synthetic corpus (1,468 notes, 2,604,345 tokens) measured 2.17 characters per token, 2.04 to 3.53 per note, on generated ids, hashes and log-like filler that tokenizes far more densely than prose, so the pessimistic estimate was 22.5% light (2.17 against the 2.8 anchor; the bill came in 29% over it). No constant moves on synthetic text, but a vault full of generated logs, ids or code will look like it, so the run itself stops, with exit code 2 and `--resume` able to continue, when the API's own `input_tokens` have cost more than the ceiling, whatever the estimate said. A stop (the meter, the error-rate stop, a 402) sends nothing new: queued requests are cancelled, the requests that had already left for the API (about one per worker) complete and are recorded, and the abort message states exactly how many. (Through 0.4.5 the in-flight window was never waited on, so a stop left nearly the whole run queued and every queued request still ran, was billed and lost its row.) With `--over-budget` the accepted bill's pessimistic end is the meter's limit, so an accepted bill is never an unbounded one. After a live run the measured figure is printed: payload plus question characters over the `input_tokens` the API actually counted, next to the range assumed on the same basis. That is how the anchors get replaced by data from your vault. An offline run prints the same bill as what a live run would send. Below a dime the bill is shown to the hundredth of a cent. **Measured against a real invoice, once:** for 2026-09-22 UTC the TypeSafe dashboard charged $5.04 against a usage export of 118,975,559 input and 8,436,363 output tokens; input-only at $0.042 per million comes to $4.997, within 0.9%, so the bill's input-only model holds, the published price is current, and any charge for output tokens is at most about $0.005 per million.

### What `--apply` guarantees

- It never deletes a note.
- It never rewrites a body. The body is spliced back byte-for-byte. Trailing whitespace, a missing final newline, CRLF line endings and a UTF-8 BOM all survive as they were. A note without a final newline stays without one, on purpose.
- It never rewrites your frontmatter either. Only the `janitor:` block is generated, replaced in place or appended; every other header line comes back as you wrote it, so `draft: no` stays `no`, `port: 0777` stays `0777`, and comments and quoting survive. (Through 0.2.1 the whole header went through a YAML serialiser, which turned those into `false` and `511`.)
- Writes are atomic: new content goes to a temp file and is swapped in with `os.replace`, so a crash mid-write cannot leave a truncated note.
- A note that is not valid UTF-8 is never sent, becomes a `skip` row with `findings: ["undecodable"]`, and is left untouched; the run continues.
- Quarantine is a move, not a rewrite. The note goes to `_janitor/quarantine/<its vault-relative path>`, so two notes with the same file name in different folders stay distinct. The first move writes a `.gitignore` containing `*` into that folder, and every move appends a line to `_janitor/quarantine/manifest.jsonl` with the original path, the destination, the reason and the time.

The test for this is `tests/test_apply_roundtrip.py`: notes containing an emoji, curly quotes, an em-dash, indented lines, trailing spaces, CRLF and a BOM go through `--apply` and must come out with identical body bytes.

After `--apply`, a note gains:

```yaml
janitor:
  bucket: project_decision
  persist: 1.25
  confidence: 0.83
  bucket_margin: 0.41
  contains_secret: 0.28
  safe_to_leave_in_git: 0.71
  action: frontmatter
  reason: normal vote
  model: jev-1.13.0
  taxonomy: be00a24c7a68
  at: 2026-09-18T12:00:00Z
```

`taxonomy` is a short hash of the taxonomy file that produced the vote, so a stamp can be interpreted after the wording changes. The `--json` report additionally carries `bucket_probabilities`, `bucket_margin` (top-1 minus top-2), `exact_duplicate_of` (the first note with identical content, computed locally by hash), `title_sent` (the title as it left, after redaction; on every vote row, with or without `--show-payload`) and `sibling_titles_sent` (a count: how many sibling titles were listed), `redacted_own` (the subset of `redacted` found in this note itself rather than in a neighbour's title -- only that subset can quarantine it) and `quarantine_triggers`. A note whose stamp did not need to change reports `applied: unchanged` and is not rewritten, so a re-scan does not dirty every note in git.

## The run journal

Every run appends one JSON line per note to a journal **as each note finishes**, so a long run is never all-or-nothing:

- **Progress** is printed to stderr every 50 notes or 5 seconds (`--quiet` silences it). stdout stays clean under `--json`.
- **A failed note does not end the run.** It becomes an `error` row with the exception name and message, the scan continues, and the exit code is 2 so scripts can tell "finished with failures" from "declined" (exit 1). Once 50 notes have been sent, if more than 20% of all the notes sent so far have failed (a running total, checked after every send; through 0.4.7 the message said "of the first 50"), the run stops, because that is a broken key or an outage rather than bad notes.
- **The journal lives outside the vault by default**, in the user cache directory keyed by the vault's path, so a dry run still changes nothing inside the vault. Its path is printed at the end of every run. `--journal vault` puts it under `<vault>/_janitor/runs/` instead; `--journal off` disables it.
- It records **decisions, not the payload**: the `sent` object is dropped from every row, so no excerpt and no sibling titles reach the journal; the redacted `title_sent` and the graph numbers stay on the row, as they do in the report. Each row carries the bucket, the probabilities, the action, the taxonomy fingerprint, and a `key` that hashes exactly the state that was sent, so a later run can tell whether a vote is still the vote it would get today.

**Resume and cache.** `--resume` picks the newest journal for the vault that is unfinished (interrupted, or stopped by the meter, a 402 or the error rate) and not already resumed by a newer run; otherwise the newest run. An unfinished run still beats newer finished runs that did not resume it, deliberately: an `--offline` run after a live Ctrl-C must not win and hide the live cache. It serves the votes of that run and of the runs it resumed, keyed by exactly what was sent (newest row per key wins), so a resume that is itself stopped part-way never makes the next one re-send what an earlier run had done, a finished resume is not beaten by the old stop it continued, and a later run with different keys does not hide the earlier live votes. (Through 0.4.5 the newest run without a footer, a crashed run, won outright and for ever, and a Ctrl-C wrote a footer that called the run completed, so `--resume` skipped it.) It serves every note whose key still matches from the journal instead of sending it, retries every note whose last row was an error, and sends only what is new or changed. Before anything leaves it prints what it found:

```
resuming run 3f9c1a7e from 2026-09-21T18:02:11Z (interrupted after 19014 notes)
  taxonomy unchanged (be00a24c7a68)
  19000 already voted and unchanged: served from the journal, not sent
  14 previous errors: will be retried
  1980 new or changed: will be sent
jev-janitor pre-flight: 1994 of 20994 notes under vault/ will be sent to TypeSafe (19000 served from the journal, not sent)
```

The consent question is still asked whenever anything will be sent, and skipped only when nothing will. Edit the taxonomy, the denylist, a note's text within the cap, or a sibling's title, and the affected keys change, so those notes are re-sent; nothing is ever served for a changed input. If the API returns a different model version than the cached votes came from, the run says so and stops serving cached votes (`--trust-cache-across-models` overrides). `--no-cache` retries errors but re-sends everything. `--journal-info` prints the newest journal and how many notes it would serve today, with no key.

**Workers.** `--workers N` sends N requests at a time; the default is 8 and 16 is the measured optimum. Two probes on invented notes in September 2026 found no rate limit through 64 workers: zero refusals in about 2,000 calls. A 400-call sustained probe kept scaling to 64 (219 calls per second, latency flat at about 200 ms); a 40-call probe saw throughput peak at 16 and per-call latency double beyond it, which reads as queuing, not refusal. So a 20,000-note vault at 16 workers is roughly seven minutes, and re-scanning after a taxonomy edit becomes cheap enough to do repeatedly. The default sits below the optimum on purpose: one machine, one evening, on a free service, is not a licence to be the reason it grows a limiter. Rows are always written by one thread, whatever N is, so the journal stays well-formed.

## A vault profile: `janitor.toml`

A scheduled scan should not depend on retyping flags. Put a `janitor.toml` at the vault root (or point at one with `--config FILE`) and the janitor reads it: sensitive folder names, denylist and taxonomy paths (relative to the file), excerpt cap, workers, journal location, model, the token ceiling, the git-safety threshold, `include_sensitive`. A flag on the command line overrides the matching key for that one run; a key you leave out keeps the built-in default; `--no-config` reads none. The pre-flight names the profile it used and its fingerprint on every run, or says `profile: none`. Unknown keys are refused, not ignored: a misspelled `sensitive_paths` that silently did nothing would be a privacy hole with a config file's confidence. The tool never writes this file. Start from [`janitor.toml.example`](janitor.toml.example), which carries the current defaults with comments.

## Local triage: what code decides before anything is sent

Most of a large vault is arithmetic, and arithmetic is code's job. Before any request, one pass over the vault builds an index (every scanned note read exactly once; notes on hidden paths are never opened, and notes on sensitive paths only under `--include-sensitive`), and four kinds of note are decided there with no model and no request:

| note | decided as | why |
|---|---|---|
| empty body, or headings only | `junk`, persist 0 | there is nothing to judge |
| exact duplicate of an earlier note in the plan (same body, ignoring a leading H1 and line endings) | `junk`, persist 0, `exact_duplicate_of` names the first copy | the taxonomy's own words: duplicate noise. The first copy is judged normally |
| a high-precision secret hit (`KEY`, `WEBHOOK`, `JWT`, `PEM`, `AWS_SECRET`, `BEARER`, `URL_CREDENTIAL`) in the note's own title, aliases, path, frontmatter key names or body | `needs_review`, action `quarantine` | a credential format matched by regex is not a question for a model. `EMAIL`, `PHONE`, `CARD` and `NAME` are not in this list: they false-positive on prose, and the note goes to Jev with the tokens in place |
| `janitor.locked: true` in frontmatter | skipped: no request, no header rewrite, no new `at` | a person decided. Unlock by deleting the key |

Every row says who decided it: `judge: local` or `judge: jev` (`model: local` on the stamp). Jev is spent on the ambiguous middle. Nothing here reads prose to decide; if a rule would need to, it belongs in the taxonomy, not here. `--no-local-triage` sends everything to the judge instead, which is how to measure Jev against these rules on a corpus with an answer key.

**Findings: notes your tools cannot read.** A header between `---` fences that YAML cannot parse (`status: blocked: waiting on review` is the usual shape, and agents write it) is a fact about the vault, not a failure of the run. Such a note is judged on its body, with no frontmatter keys and none of the unreadable header text sent; its row carries `findings: ["unreadable_frontmatter"]` and the parser's reason; the pre-flight counts them and the run's closing lines total them. `--apply` leaves that header exactly as it is, because a header the janitor cannot read is one it must not rewrite, though a note holding a credential is still quarantined, since a move needs no parse. A file that is not valid UTF-8 is the other finding: a skip row with `findings: ["undecodable"]`, never sent, never retried. Neither is an `error` row; error rows are for failures of the run, which `--resume` retries. A third finding needs no new state: the share of judged notes with no parseable creation date in their frontmatter, whose age therefore comes from the filesystem and resets if the vault is moved, cloned, restored or re-synced. Each row says `age_source: frontmatter` or `mtime`; the pre-flight and the run's closing lines give the count. (On one real 295-note sample it was 54%, and no tool the owner had ever mentioned it.)

**The review pile and the lock.** "You review the low-confidence pile" at vault scale: `--review-pile FILE` writes the notes routed to a human (stamped `needs_review` with a `suggested_bucket`, or quarantined) as a markdown list of wikilinks to one file you name: a low-confidence note's line carries the suggested bucket, the confidence and the margin; a quarantined note's line carries the reason and where the note now sits, or `not moved (dry run)`. Nothing is moved, because moving a note breaks the graph you navigate, and nothing is written unless you pass the flag. When you have accepted or corrected a label, add `locked: true` under `janitor:` in that note. Later scans skip it entirely: no request, no header rewrite, no new `at`. The pre-flight and the pile count locked notes as the part of the brain a person has already read. Unlocking is deleting the key.

## Survey first, full scan second

Nobody lets an unknown tool make 20,000 calls over their private notes on first contact, and the published taxonomy was fit to one vault. `--survey` (75 notes by default, `--survey N`) draws a stratified sample across top-level folders, length bands (stub, short, medium, long by word count) and age bands, round-robin so every stratum gets one note before any gets a second, seeded by the vault so the same vault draws the same sample. It runs the same pre-flight, with the header and the bill naming the sample (through 0.4.7 the header said every scanned note would be sent while the bill named the sample), judges only the sample, and prints how the sample voted per stratum. Notes code decides on its own (empty, duplicate, credential, locked) and notes the journal already answered are not candidates: the survey is spent on what the judge would actually see. The votes go to the journal, so the full scan that follows, run with `--resume`, serves them from cache and sends only the rest. Edit the taxonomy, re-run the survey, compare, then scan in full.

## The scan diff: the second scan is a delta

The first scan is a map. The second is what moved. `--diff` compares the two newest journals for the vault (or `--diff JOURNAL` compares that run against the newest) and prints, from the journals alone: notes in both, new and gone; bucket changes with the confidence and the judge on each side; notes that went into review and out of it; quarantines since and releases; new exact duplicates; notes that crossed the excerpt cap; findings fixed and new; locks. It says out loud when the taxonomy wording or the model changed between the runs, because then a label change may be the wording and not the note. Nothing is read from the vault and nothing is sent; the journals hold no excerpts, so neither does the diff. `--json` has every row; the text view caps each list.

## Records in, rows out: `jev-records`

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

**Rows, journal, bill.** No string from `sent` reaches a row, the stdout table (id, pick, confidence, action, reason) or the journal: labels, numbers and fixed phrases only. `--show-payload` puts the exact `sent` state on each row of `--json` or `--out`, never in the journal; it is the audit instrument, the same as for the vault scan, and what a grader needs. The journal lives in the user cache dir under a hash of the records file's path (`--journal DIR|off|default`), and the newest one serves identical records on the next run unless `--no-cache`; for a double run to score stability, use `--journal off` or a fresh directory per run. The bill, the `--max-usd` ceiling, `--over-budget`, the concurrency and the error-rate stop are the vault scan's. The key comes from `TYPESAFE_API_KEY`, outside any file. The example question set, [`examples/triage.yaml`](examples/triage.yaml), triages product ideas into lanes; any Choice, Scores and Nouls in the `questions:` layout work.

## The brain map: data layer

The brain map is the product and the terminal table is the debug view. What exists today is the half that can be built before a real corpus: `--map FILE` writes, as JSON, everything a map needs to know about one run. Per-folder rollups with every ancestor folder included (notes, judged, buckets, local versus Jev, review, quarantined, locked, skipped by rule, findings, orphans, maps of content, words, age bands, in- and out-links, unresolved links); vault-wide totals and the bucket distribution; graph facts (nodes, edges, hubs by in-degree, degree histograms); exact-duplicate clusters; and one record per note with its path, folder, status, label, judge, action, findings, age source and graph numbers. Paths, labels, counts and bands only: no titles, no excerpts, no text, so the file can be handed to a renderer or a person without a second privacy review. Nothing is written unless you pass the flag. The drawing waits for a corpus to be shaped around.

## What Jev is asked

The taxonomy is [`janitor/taxonomies/vault_memory.yaml`](janitor/taxonomies/vault_memory.yaml). Its sentences are the whole knowledge base Jev has for this job; there is no built-in notion of "durable" or "scratch". Every word Jev is asked is in that file, and it is sent exactly as written, with every call: the questions are not redacted and the denylist does not apply to them, so keep names and secrets out of a question file. Each entry under `questions` is one question with a `type` (`choice` with `options`, `score` with `levels`, or `noul`), its `instructions`, and its criteria, sent in file order, so the fingerprint stamped on every vote covers all of the wording. (Through 0.4.2 the `instructions` sentences of `bucket` and `persist` were Python strings outside the fingerprint; 0.4.3 moved them into the file without changing a word, and the state plus serialized questions for every note of a 192-note corpus was byte-identical before and after.) The format describes a whole question set, not this tool's questions, so a file with a different Choice, its own Scores and its own Nouls loads the same way; the vault scan itself requires a `bucket` choice, a `persist` score and the five nouls below. A file in the 0.4.x layout (`buckets`, `persist`, `nouls` at the top level) still loads and sends exactly what it did, with the two built-in sentences filled in; its fingerprint does not cover those two sentences until you convert it.

**Choice `bucket`**

- `durable_memory`: a standing fact worth keeping across sessions
- `project_decision`: a dated choice future work must honor
- `code_note`: implementation, command, schema, benchmark
- `reference`: third-party docs, quotes, links
- `log_entry`: a dated run report, scan, digest or snapshot, kept as a record of the day
- `ephemeral`: scratch, chat debris, moods
- `junk`: empty, boilerplate, noise
- `needs_review`: not enough signal, a human should look

**Score `persist`**: drop / park / promote. Jev returns a probability-weighted position on the rubric, so 1.25 means "between park and promote, leaning park", not an index.

**Nouls**: `contains_secret`, `looks_like_duplicate`, `records_a_decision`, `is_actionable`, `safe_to_leave_in_git`. Each is a probability in [0, 1]. Decision and actionability are separate questions on purpose; see the calibration notes.

All seven go in one call against the same redacted state. Thresholds that turn votes into actions live in [`janitor/policy.py`](janitor/policy.py). Change them there, not in the questions.

Measured API limits (September 2026): 32,768 input tokens per call including the questions, at most 255 options in a Choice, at most 10 levels in a Score, and at least 1,000 questions per call before the token ceiling binds. Loading a taxonomy that exceeds the option or level limit fails locally, before any request.

**Edit the descriptions and the votes move. Re-calibrate after any change.** The YAML is not configuration. It is sensitive to phrasing in ways you cannot predict by reading it, and the numbers below show how much.

## Fixture demo

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

## Calibration notes: what was measured

All figures from live `jev-1.13.0`, September 2026, on 26 notes from one production vault (21 long dated reports of 9 to 51 KB, 5 near-empty stubs) plus the invented fixture vault. Raw numbers are reproducible with the taxonomy fingerprints given. The fingerprints below were recorded when the two instruction sentences lived outside the file; 0.4.3 moved them in without changing a word, so the current file fingerprints as `be00a24c7a68` at wording identical to `65bd5bfc7207`, and every figure recorded under `65bd5bfc7207` stands for it.

**Wording is the model.** Same 26 notes, same model, three taxonomy revisions:

| change | fingerprint | effect on the 26 notes (21 scans, 5 stubs) |
|---|---|---|
| baseline | `869d90f3047f` | the 21 scans split 9 project_decision / 7 durable_memory / 5 ephemeral, median confidence 0.33 |
| split one compound noul into two, buckets untouched | `86dab0bbb6c6` | 23 of 26 labels unchanged; 3 near-ties flipped; every answer within noise |
| add one bucket, `log_entry`, one sentence | `65bd5bfc7207` | 21 of 21 to `log_entry` at confidence 1.00; control vault unaffected |

**The strongest single number.** The 21 scans went from a three-way split at median confidence 0.33 to 21 of 21 in `log_entry` at 1.00, from one added sentence. Two caveats so that reads as evidence rather than a boast. Ceiling confidence on every note is unusual, not just good: it means the description fits the material exactly, and it is a fitted result on the corpus that motivated the fit. And it came with a control: the invented fixture vault, run live under the same taxonomy, put `log_entry` at 0.00 on all ten non-log notes and 1.00 on the one invented run log, and every other question on the 26 real notes stayed within the noise band. A result with a control is worth several without one.

A missing bucket shows up as a low-confidence spread, and no amount of extra context fixes it. On one 51 KB note sent at 1,200 / 3,000 / 6,000 / 12,000 characters and in full under the baseline taxonomy, bucket confidence stayed between 0.24 and 0.43 whatever Jev saw. Adding the bucket took the same note to 1.00 at 1,200 characters.

Adding the bucket also corrected a neighbouring classification nobody was trying to fix. Five near-empty stubs, each recording that a scheduled run had found nothing, had been `junk` at 0.86. Under the new taxonomy they went to `log_entry` at 0.97. That is the better answer: a record that a run happened and found nothing is information, and the corpus itself treats zero-result nights as state. `junk` implies no information value.

**Questions are isolated: a vendor claim, now measured.** TypeSafe documents that questions in one call are evaluated in parallel and in isolation. Until this run that was taken on their word. The middle row above is a direct test: adding and renaming nouls moved the bucket and score answers by a mean absolute 0.035, max 0.11, all near-ties. The bottom row is a second: changing only the bucket set moved every noul and the score by a mean absolute 0.03 or less. It holds on this corpus, and it matters to anyone composing a battery of questions.

**Jev is not deterministic, and the confidence floor is the answer.** The identical input sent twice moved bucket probabilities by 0.03 to 0.04 and flipped the winning bucket on a near-tie (0.34 versus 0.36). The 0.55 confidence floor in `policy.py` routes every such near-tie to human review regardless of which label won, so across two full runs on the same notes, 3 labels flipped and 0 actions did. Do not "optimise" the floor away as an arbitrary constant. `bucket_margin` in the report is the number to watch.

**Compound questions get half-answered.** The baseline had one noul, `actionable_decision`. On a note reading "Recommendation: the owner should schedule a review", it scored 0.84; Jev had answered the "actionable" half. Split into `records_a_decision` and `is_actionable`, the same note scored 0.22 and 0.92. Ask one thing per question.

**Score benefits from more text; Choice does not.** On the fixed-note experiment, `persist` climbed steadily from 1.35 to 1.66 as the excerpt grew and its confidence rose from 0.31 to 0.48, while bucket confidence plateaued after the first substantive section. Spend excerpt budget on Score questions.

**Latency is flat in input size.** Steady-state calls returned in 170 to 310 ms whether the state was 1,700 tokens or 15,000. First call in a session about 530 ms for connection setup. Excerpt strategy is a judgment-quality question, not a latency one.

**Redaction order changed in 0.1.2.** Up to 0.1.1 the excerpt was cut to 1,200 characters and then redacted; since 0.1.2 the body is redacted and then cut. On a note with a redaction hit in its first 1,200 characters the excerpt Jev sees is therefore slightly different from what the recorded runs below saw, and its vote can move. Of the 26 calibration notes exactly one had such a hit; every figure below was recorded under the old order and is reported as recorded.

**The excerpt cap can land on preamble.** On the 21 real scans, the 1,200-character excerpt covered 2.3% to 11.8% of the body, and in 20 of 21 it was entirely the note's opening status preamble; the substance began below the cap. Under the baseline taxonomy Jev was judging headers. The cap is not the bug; taking the first 1,200 characters is. A smarter excerpt for structured notes is v0.2 work.

**Exact duplicates are arithmetic.** Five stubs with identical content under date-differing headings scored 0.13 to 0.17 on the title-based duplicate noul. Jev answered the question it was given. Identical content is now detected locally by hash, ignoring a leading heading, and reported as `exact_duplicate_of`. The noul stays for near-duplicates.

**Note age is not a question for Jev.** `persist` showed no gradient across four months of dated notes (r = 0.18). Jev cannot do date arithmetic and TypeSafe says so. Compute age in code.

## Limitations

- **The offline client is not Jev.** Keyword rules for CI and demos. Its labels are wrong on real notes.
- **Calibrated on one vault.** The taxonomy was tuned against 26 notes from one production vault plus invented fixtures. Your notes will disagree with some votes. Edit the YAML, re-run, compare fingerprints.
- **Duplicate detection is titles plus a content hash, not semantics.** Sibling titles go to Jev; identical content is hashed locally. Two notes that say the same thing in different words are not caught.
- **The default excerpt is the first 16,000 characters** (1,200 before 0.2.1). On a real 18,712-note vault that reads 93.6% of notes in full, against 17% at 1,200, and uses about a fifth of the API's 32,768-token ceiling. Notes longer than the cap are still judged on their opening, so a very long note with a preamble can still be misread; `--excerpt-chars full` sends whole notes up to the 60,000-character guard. Changing the cap changes the cache key of every note longer than the smaller cap, so a resume at a different cap re-sends exactly those notes.
- **Large vaults.** Sequential is about a quarter of a second per note, so pass `--workers`. Progress is visible, every finished note is on disk as it completes, one failed note never discards the run, and `--resume` continues an interrupted run without re-sending what is done (under `--apply`, a note's file is stamped or moved by the one writer thread right before its row is recorded, never by a worker, so a Ctrl-C leaves at most one stamped note without a row, the one it landed on; through 0.4.7, since 0.4.6, workers wrote their own files ahead of the writer, so an interrupt inside the writer could leave several stamped or moved notes with no row, which `--resume` then re-sent). The prepare phase reads every note before the first request, which on a 20,000-note vault is some seconds of local I/O with no progress line yet.
- **The cache is the journal.** Nothing is served unless `--resume` is passed; a plain run re-sends every note. At $0.042 per million input tokens a 26-note run cost well under a tenth of a cent, so this is a correctness limitation more than a cost one.
- **Regex redaction misses things regexes miss, and over-redacts things that look like what it hunts.** A card number is replaced only when it passes Luhn, has a card's grouping and starts with a payment network's digit (2 to 6); a 16-digit string that fails any of those stays in the excerpt. The residual the other way: a contiguous 13-to-19-digit run that starts 2 to 6 and happens to pass Luhn still becomes `[CARD]`, which is about one millisecond timestamp beginning `2026...` in ten. That is inherent to regex redaction; the number is stated so it is known rather than discovered.
- **Not affiliated with, endorsed by, or supported by TypeSafe.** It calls their public API.

## Development

```bash
pip install -e ".[dev,jev]"
pytest -q
```

The suite runs without `TYPESAFE_API_KEY`. One test replays a recorded live response through the SDK's own response model and skips if the SDK is not installed. CI runs on Linux and Windows, Python 3.11 and 3.12, plus one leg that installs `.[dev]` alone with no SDK, which is the path this README documents.

MIT. Copyright (c) 2026 Vanced Corporation. Built and maintained by Kyle Hovance.
