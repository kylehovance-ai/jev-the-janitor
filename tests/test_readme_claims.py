"""Tests that exist because the README makes the claim. One claim per test, named for it.

If a sentence on the front page is not backed by a test, it goes here or it gets softened.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import frontmatter
import pytest
import yaml

from janitor.client import FixtureClient
from janitor.frontmatter import MAX_EXCERPT
from janitor.redact import redact
from janitor.scan import scan_vault
from janitor.schema import DEFAULT_TAXONOMY, REQUIRED_NOULS, load_taxonomy

ROOT = Path(__file__).resolve().parent.parent

README = Path(__file__).resolve().parent.parent / "README.md"


class Recording(FixtureClient):
    def __init__(self):
        self.states = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


# --- "the names of frontmatter keys, never their values" -----------------------------------

def test_frontmatter_values_never_leave(tmp_path: Path):
    (tmp_path / "n.md").write_text("---\ntitle: Public title\nclient: ACME-SECRET-CLIENT\ntags: [SECRET-TAG]\n---\n# Public title\n\nbody\n", encoding="utf-8")
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True)
    blob = json.dumps(rec.states)
    assert rec.states[0]["frontmatter_keys"] == ["client", "tags", "title"]
    assert "ACME-SECRET-CLIENT" not in blob
    assert "SECRET-TAG" not in blob


def test_frontmatter_values_never_leave_from_a_note_with_a_bom(tmp_path: Path):
    """Through 0.2.0 the reader and the writer were different parsers. The reader did not
    strip a UTF-8 BOM, saw no frontmatter, reported no keys, and sent the whole header as
    the excerpt. After --apply the header grew a janitor block and was sent again."""
    note = tmp_path / "n.md"
    note.write_bytes("\ufeff---\ntitle: Public title\nclient: ACME-CODE-99\n---\n# Public title\n\nbody\n".encode("utf-8"))
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True)
    assert rec.states[0]["frontmatter_keys"] == ["client", "title"]
    assert rec.states[0]["title"] == "Public title"
    assert rec.states[0]["excerpt"] == "# Public title\n\nbody"
    assert "ACME-CODE-99" not in json.dumps(rec.states)

    scan_vault(tmp_path, offline=True, apply=True)
    assert note.read_bytes().startswith(b"\xef\xbb\xbf---")
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True)
    assert rec.states[0]["frontmatter_keys"] == ["client", "janitor", "title"]
    assert "ACME-CODE-99" not in json.dumps(rec.states)
    assert "bucket" not in rec.states[0]["excerpt"]


def test_reader_and_writer_share_one_frontmatter_parser():
    """The BOM leak was two parsers disagreeing. There is now one, and both sides import it."""
    from janitor import apply, frontmatter

    assert apply.split_frontmatter is frontmatter.split_frontmatter


# --- "the first N characters of the body" / "anything past the cap" never leaves --------

def test_excerpt_cap_holds_and_nothing_past_it_leaves(tmp_path: Path):
    head = "# Long\n\n" + ("preamble line of filler text.\n" * (MAX_EXCERPT // 25))
    assert len(head) > MAX_EXCERPT
    (tmp_path / "long.md").write_text(head + "BELOW-THE-CAP-SENTINEL\n", encoding="utf-8")
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True)
    assert len(rec.states[0]["excerpt"]) <= MAX_EXCERPT == 16000
    assert "BELOW-THE-CAP-SENTINEL" not in json.dumps(rec.states)


# --- "the body of any note on a sensitive path" never leaves without --include-sensitive ----

def test_sensitive_body_never_leaves_by_default(tmp_path: Path):
    (tmp_path / "family").mkdir()
    (tmp_path / "family" / "x.md").write_text("# Family\n\nFAMILY-BODY-SENTINEL\n", encoding="utf-8")
    (tmp_path / "ok.md").write_text("# Ok\n\nfine\n", encoding="utf-8")
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True)
    assert [s["path"] for s in rec.states] == ["ok.md"]
    assert "FAMILY-BODY-SENTINEL" not in json.dumps(rec.states)


# --- redaction token list: KEY, BEARER, AWS_SECRET, EMAIL, PHONE, CARD, SSN, NAME -----------

@pytest.mark.parametrize("text,label,must_go", [
    ("token sk-abcdefghijklmnopqrstuvwxyz012345 end", "KEY", "sk-abcdefghijklmnopqrstuvwxyz012345"),
    ("id AKIAABCDEFGHIJKLMNOP end", "KEY", "AKIAABCDEFGHIJKLMNOP"),
    ("Authorization: Bearer abc.def-ghi_jkl.mno", "BEARER", "abc.def-ghi_jkl.mno"),
    ("aws_secret_access_key = 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY'", "AWS_SECRET", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"),
    ("mail ops@example.com now", "EMAIL", "ops@example.com"),
    ("call 555-867-5309 today", "PHONE", "555-867-5309"),
    ("card 4111 1111 1111 1111 on file", "CARD", "4111 1111 1111 1111"),
    ("ssn 123-45-6789 here", "SSN", "123-45-6789"),
    # Formats 0.1.0 missed:
    ("openai sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90 end", "KEY", "sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90"),
    ("anthropic sk-ant-api03-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90Uv end", "KEY", "sk-ant-api03-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90Uv"),
    ("google AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q end", "KEY", "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
    ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEFghiJKLmnoPQRstuVWXyz0123456789 end", "JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEFghiJKLmnoPQRstuVWXyz0123456789"),
    ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----", "PEM", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"),
    ("aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "AWS_SECRET", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"),
])
def test_every_documented_redaction_token(text, label, must_go):
    result = redact(text)
    assert label in result.hits
    assert f"[{label}]" in result.text
    assert must_go not in result.text


def test_denylist_name_token():
    result = redact("met Ada Lovelace", denylist=["Ada Lovelace"])
    assert "[NAME]" in result.text and "Lovelace" not in result.text


# --- "It never deletes a note" / "Quarantine is a move, not a rewrite" -----------------------

def test_apply_never_deletes_and_quarantine_is_a_byte_identical_move(tmp_path: Path):
    secret_body = "# Leak\n\nkey sk-abcdefghijklmnopqrstuvwxyz012345\n— keep these bytes \U0001F331\n"
    (tmp_path / "leak.md").write_bytes(secret_body.encode("utf-8"))
    (tmp_path / "fine.md").write_bytes(b"# Fine\n\nbody\n")
    before = sorted(p.name for p in tmp_path.rglob("*.md"))
    rows = {r["path"]: r for r in scan_vault(tmp_path, offline=True, apply=True)}
    assert rows["leak.md"]["action"] == "quarantine"
    moved = tmp_path / "_janitor" / "quarantine" / "leak.md"
    assert moved.exists() and not (tmp_path / "leak.md").exists()
    assert moved.read_bytes().endswith(secret_body.encode("utf-8"))  # frontmatter prepended, body untouched
    after = sorted(p.name for p in tmp_path.rglob("*.md"))
    assert after == before  # same files exist, one relocated


# --- the frontmatter block shown in the README has exactly these keys ------------------------

def test_stamp_has_the_documented_keys(tmp_path: Path):
    (tmp_path / "n.md").write_text("# N\n\nbody\n", encoding="utf-8")
    scan_vault(tmp_path, offline=True, apply=True)
    post = frontmatter.load(tmp_path / "n.md", encoding="utf-8")
    assert list(post.metadata["janitor"]) == ["bucket", "persist", "confidence", "bucket_margin", "contains_secret",
                                              "safe_to_leave_in_git", "action", "reason", "model", "taxonomy", "at"]


# --- "the --json report additionally carries bucket_probabilities, bucket_margin, exact_duplicate_of"

def test_json_rows_have_the_documented_extra_fields(tmp_path: Path):
    (tmp_path / "n.md").write_text("# N\n\nbody\n", encoding="utf-8")
    row = scan_vault(tmp_path, offline=True)[0]
    for key in ("bucket_probabilities", "bucket_margin", "exact_duplicate_of", "taxonomy", "model", "records_a_decision", "is_actionable"):
        assert key in row


# --- the bucket list and noul list in the README match the taxonomy on disk -----------------

def test_readme_bucket_and_noul_lists_match_taxonomy():
    from janitor.schema import buckets, nouls

    tax = load_taxonomy()
    readme = README.read_text(encoding="utf-8")
    for bucket in buckets(tax):
        assert f"- `{bucket}`:" in readme, f"bucket {bucket} not documented in README"
    assert set(buckets(tax)) == {"durable_memory", "project_decision", "code_note", "reference", "log_entry", "ephemeral", "junk", "needs_review"}
    for noul in REQUIRED_NOULS:
        assert f"`{noul}`" in readme, f"noul {noul} not documented in README"
    assert set(nouls(tax)) == set(REQUIRED_NOULS)


def test_readme_default_sensitive_list_matches_code():
    from janitor.redact import DEFAULT_SENSITIVE_PATH_PARTS

    readme = README.read_text(encoding="utf-8")
    documented = "`family`, `private`, `personal`, `secrets`, `inbox`"
    assert documented in readme
    assert DEFAULT_SENSITIVE_PATH_PARTS == ("family", "private", "personal", "secrets", "inbox")


# --- "seven questions in one call" ------------------------------------------------------------

def test_seven_questions_are_built_and_recorded():
    pytest.importorskip("typesafe_sdk")
    from janitor.schema import build_questions

    questions = build_questions(load_taxonomy())
    assert len(questions) == 7
    fixture = Path(__file__).resolve().parent / "fixtures" / "jev_response.json"
    recorded = json.loads(fixture.read_text(encoding="utf-8"))
    assert set(recorded["answers"]) == set(questions)


# --- the README's fixture table (offline column) ------------------------------------------------

def test_fixture_table_offline_column():
    fixtures = Path(__file__).resolve().parent.parent / "fixtures" / "notes"
    rows = {r["path"]: r for r in scan_vault(fixtures, offline=True)}
    expected = {
        "durable-plot-fee.md": "durable_memory", "durable-routing-rule.md": "durable_memory",
        "duplicate-routing-rule.md": "durable_memory", "project-decision.md": "project_decision",
        "code-note.md": "code_note", "reference-link.md": "reference", "nightly-run-log.md": "log_entry",
        "ephemeral-scratch.md": "ephemeral", "ephemeral-mood.md": "ephemeral", "junk-lorem.md": "junk",
        "secret-leak.md": "needs_review",
    }
    for path, bucket in expected.items():
        assert rows[path]["bucket"] == bucket, path
    assert rows["secret-leak.md"]["action"] == "quarantine"
    assert rows["family/private-skip-me.md"]["action"] == "skip_sensitive"


# --- the taxonomy fingerprint printed in the README matches the file -------------------------

def test_readme_fingerprint_matches_current_taxonomy():
    from janitor.schema import taxonomy_fingerprint

    readme = README.read_text(encoding="utf-8")
    assert f"taxonomy: {taxonomy_fingerprint()}" in readme, "README frontmatter example shows a stale fingerprint"
    assert yaml.safe_load(DEFAULT_TAXONOMY.read_text(encoding="utf-8"))["questions"]["bucket"]["options"]["log_entry"].startswith("A dated run report")


# --- README:83 "even then its title is never listed as sibling context for any other note" ---

def test_readme_states_the_sibling_context_clause_and_code_enforces_it(tmp_path: Path):
    readme = README.read_text(encoding="utf-8")
    assert "and even then its title is never listed as sibling context for any other note" in readme
    (tmp_path / "family").mkdir()
    (tmp_path / "family" / "mom.md").write_text("# Mom Zebra Diagnosis\n\nbody\n", encoding="utf-8")
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "x.md").write_text("# X\n\nbody\n", encoding="utf-8")
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True, include_sensitive=True)
    own = next(s for s in rec.states if s["path"] == "family/mom.md")
    assert own["title"] == "Mom Zebra Diagnosis"  # the opted-in note is judged by its own title
    for s in rec.states:
        assert "Zebra" not in json.dumps(s["other_note_titles"])  # never as sibling context


def test_readme_states_that_the_named_path_is_tested_against_its_own_folders():
    readme = README.read_text(encoding="utf-8")
    assert "The path you name is tested too, against its own absolute folder names" in readme
    assert "`jev-janitor ./vault/family` skips everything under it" in readme


# --- 0.4.8: every README and SECURITY claim true (an outside claim-audit of 0.4.7) ----------------

def _write_notes(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


class _Recording(FixtureClient):
    def __init__(self) -> None:
        self.states: list[dict] = []

    def vote(self, state, questions):
        self.states.append(state)
        return super().vote(state, questions)


def test_single_file_and_directory_scans_rank_sibling_titles_the_same_way(tmp_path: Path):
    """README: "the 80 closest by word overlap … for a directory scan and a single-file scan alike".
    Through 0.4.7 the single-file path took the alphabetical first 80, so with 81 siblings it
    dropped the one near-duplicate title the directory scan kept."""
    files = {"f/zoning-appeal.md": "# Zoning appeal\n\nbody zoning\n", "f/zz.md": "# Zoning appeal hearing notes\n\nbody hearing\n"}
    for i in range(80):
        files[f"f/a{i:03d}.md"] = f"# Alpha note {i}\n\nbody {i}\n"
    _write_notes(tmp_path, files)
    d = _Recording()
    scan_vault(tmp_path, client=d, offline=True)
    from_dir = next(s for s in d.states if s["path"].endswith("zoning-appeal.md"))["other_note_titles"]
    s = _Recording()
    scan_vault(tmp_path / "f" / "zoning-appeal.md", client=s, offline=True)
    [single] = s.states
    assert from_dir == single["other_note_titles"]
    assert from_dir[0] == "Zoning appeal hearing notes" and len(from_dir) == 80


def test_readme_placeholder_words_equal_the_code_and_a_bracketed_real_password_counts():
    """README and SECURITY list the placeholder words; the code's list is the same one, and a
    bracketed value is a placeholder only when what is inside is itself one."""
    from janitor.redact import URL_PASSWORD_WORDS, redact

    for doc in ("README.md", "SECURITY.md"):
        text = (ROOT / doc).read_text(encoding="utf-8")
        m = re.search(r"the words\s+(`\w+`(?:,\s+`\w+`)*\s+and\s+`\w+`)\s+in any case", text)
        assert m, doc
        listed = tuple(re.findall(r"`(\w+)`", m.group(1)))
        assert listed == URL_PASSWORD_WORDS, (doc, listed)
        assert "`{MyRealPassword}`" in text or "`<MyRealPassword>`" in text, doc
    real = "".join(("MyReal", "Password"))
    for wrapped in ("{" + real + "}", "<" + real + ">", "[" + real + "]"):
        assert redact("postgres://app:" + wrapped + "@localhost/db").hits == ["URL_CREDENTIAL"], wrapped
    for placeholder in ("{DB_PASSWORD}", "<password>", "[password]", "<your password here>", "{{ db_password }}", "{xxxx}"):
        assert redact("postgres://app:" + placeholder + "@localhost/db").hits == [], placeholder


def test_error_rate_stop_message_and_readme_say_a_running_total():
    from janitor import scan as scan_module

    src = (ROOT / "janitor" / "scan.py").read_text(encoding="utf-8")
    assert "notes sent so far failed" in src and "of the first {" not in src
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Once 50 notes have been sent, if more than 20% of all the notes sent so far have failed" in readme
    assert scan_module.ERROR_STOP_WINDOW == 50 and scan_module.ERROR_STOP_RATIO == 0.2


def test_survey_header_names_the_sample(tmp_path: Path):
    from janitor.plan import plan_vault
    from janitor.scan import preflight_summary

    _write_notes(tmp_path, {f"n{i}.md": f"# Note {i}\n\nbody {i}\n" for i in range(6)})
    root, plan = plan_vault(tmp_path)
    full = preflight_summary(root, plan, live=True)
    assert full.splitlines()[0] == f"jev-janitor pre-flight: 6 of 6 notes under {root.name}/ will be sent to TypeSafe"
    sampled = preflight_summary(root, plan, live=True, survey=2)
    assert sampled.splitlines()[0] == (f"jev-janitor pre-flight: 2 of 6 notes under {root.name}/ will be sent to TypeSafe "
                                       "(a survey sample; the other 4 eligible notes are not sent)")


def test_preflight_line_order_matches_the_readme(tmp_path: Path):
    """README: the profile line, the header, then the excerpt line third."""
    _write_notes(tmp_path, {"a.md": "# A\n\nbody a\n", "b.md": "# B\n\nbody b\n"})
    proc = subprocess.run([sys.executable, "-X", "utf8", "-m", "janitor.cli", str(tmp_path), "--plan", "--no-config"],
                          capture_output=True, text=True, env={**os.environ, "TYPESAFE_API_KEY": "not-a-real-key"})
    lines = proc.stdout.splitlines()  # --plan prints the pre-flight to stdout and exits 0
    assert proc.returncode == 0 and len(lines) >= 3, (proc.returncode, proc.stderr[:400], proc.stdout[:400])
    assert lines[0].startswith("  profile:"), lines[:3]
    assert lines[1].startswith("jev-janitor pre-flight:"), lines[:3]
    assert lines[2].startswith("  excerpt: the first 16,000 characters"), lines[:3]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "The third line (after the profile line and the header) always names the excerpt cap" in readme
    # the illustrative block is real output: its header counts agree with its folder lists
    block = re.search(r"```\n  profile: [^\n]*\n(jev-janitor pre-flight: .*?)\n```", readme, re.S).group(1)
    head = re.match(r"jev-janitor pre-flight: (\d+) of (\d+) notes", block)
    sending, total = int(head.group(1)), int(head.group(2))
    inc_part, skip_part = block.split("folders skipped", 1)
    included = [int(n) for n in re.findall(r"^\s{4}\S+/\s+(\d+) notes$", inc_part, re.M)]
    skipped = re.search(r"folders skipped \((\d+)\):", block)
    skipped_rows = [int(n) for n in re.findall(r"^\s{4}\S+/\s+(\d+) notes {3}\S", skip_part.split("WARNING")[0], re.M)]
    assert int(skipped.group(1)) == len(skipped_rows) == 4
    assert sum(included) + sum(skipped_rows) == total
    assert sending == sum(included)


def test_stamp_example_in_readme_has_exactly_the_keys_stamp_writes(tmp_path: Path):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = re.search(r"```yaml\njanitor:\n(.*?)```", readme, re.S).group(1)
    documented = [line.strip().split(":")[0] for line in block.splitlines() if line.strip()]
    note = tmp_path / "n.md"
    note.write_text("# N\n\nbody\n", encoding="utf-8")
    scan_vault(tmp_path, client=FixtureClient(), offline=True, apply=True)
    written = frontmatter.load(str(note)).metadata["janitor"]
    assert documented == list(written.keys()), (documented, list(written.keys()))


def test_review_pile_line_shapes_match_the_readme(tmp_path: Path):
    from janitor.cli import review_pile

    rows = [
        {"kind": "vote", "path": "a.md", "suggested_bucket": "reference", "confidence": 0.41, "bucket_margin": 0.05, "judge": "jev", "action": "frontmatter"},
        {"kind": "vote", "path": "b.md", "action": "quarantine", "reason": "local redaction hit: KEY", "applied": None},
        {"kind": "vote", "path": "c.md", "action": "quarantine", "reason": "local redaction hit: KEY", "applied": "_janitor/quarantine/c.md"},
    ]
    text = review_pile(rows, tmp_path)
    assert "- [[a]] suggested `reference` at confidence 0.41, margin 0.05 (jev)" in text
    assert "- [[b]] quarantine: local redaction hit: KEY (not moved (dry run))" in text
    assert "- [[c]] quarantine: local redaction hit: KEY (_janitor/quarantine/c.md)" in text
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "a quarantined note's line carries the reason and where the note now sits, or `not moved (dry run)`" in readme


def test_undecodable_is_a_skip_row_as_the_readme_says(tmp_path: Path):
    (tmp_path / "bad.md").write_bytes(b"# T\n\n\xff\xfe not utf-8\n")
    (tmp_path / "ok.md").write_text("# OK\n\nbody\n", encoding="utf-8")
    rows = scan_vault(tmp_path, client=FixtureClient(), offline=True)
    bad = next(r for r in rows if r["path"] == "bad.md")
    assert bad["kind"] == "skip" and bad.get("findings") == ["undecodable"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert 'becomes a `skip` row with `findings: ["undecodable"]`' in readme


def test_readme_names_every_creation_key():
    from janitor.index import CREATION_KEYS

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for key in CREATION_KEYS:
        assert f"`{key}`" in readme, key


def test_records_card_rule_is_the_first_digit_rule_too():
    from janitor.records import build_record_state

    state, hits = build_record_state({"n": 1000000000000008, "card": 4111111111111111}, None)
    assert state["fields"]["n"] == 1000000000000008 and state["fields"]["card"] == "[CARD]" and hits == ["CARD"]
    for doc in ("README.md", "SECURITY.md"):
        assert "starts with" in (ROOT / doc).read_text(encoding="utf-8")


def test_the_two_self_disagreeing_numbers_now_agree():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.count("median confidence 0.33") == 2 and "median confidence 0.35" not in readme
    assert "effect on the 26 notes (21 scans, 5 stubs)" in readme


def test_a_templated_user_or_host_makes_a_bracketed_password_a_template():
    """README: an f-string URL is code, not a leak; a literal user and host still count."""
    from janitor.redact import redact

    for text in ("postgres://{user}:{db_pw}@{host}/{db}", "postgres://app:{pw}@${HOST}/db", "mysql://<user>:{secretish}@localhost", "postgres://%USER%:{x1}@localhost"):
        assert redact(text).hits == [], text
    real = "".join(("MyReal", "Password"))
    for text in ("postgres://app:" + "{db_pw}" + "@localhost/db", "postgres://app:{" + real + "}@localhost", "postgres://app:" + real + "@{host}/db"):
        assert redact(text).hits == ["URL_CREDENTIAL"], text
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "whose user or host is itself a template" in readme and "with a literal user and host, still counts" in readme


# --- 0.4.9: the six claims an outside re-check of 0.4.8 still found untrue ----------------------

def test_readme_lists_exactly_the_graph_facts_the_index_sends(tmp_path: Path):
    """README: "any of the nine graph facts (...)". The list must equal the keys facts() returns,
    and a heading past the excerpt cap must change the key, because `headings` counts the whole note."""
    from janitor.index import build_index

    (tmp_path / "a.md").write_text("# A\n\nbody\n", encoding="utf-8")
    index = build_index(tmp_path)
    keys = list(index.facts("a.md").keys())
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"any of the nine graph facts \((.*?)\)\.", readme)
    assert m, "the README no longer lists the graph facts"
    listed = re.findall(r"`(\w+)`", m.group(1))
    assert listed == keys == ["words", "headings", "age_days", "out_links", "in_links", "embeds", "unresolved_links", "is_moc", "is_orphan"]
    body = "# T\n\n" + ("filler line of text.\n" * (MAX_EXCERPT // 20))
    (tmp_path / "long.md").write_text(body, encoding="utf-8")
    before = {r["path"]: r["key"] for r in scan_vault(tmp_path, client=FixtureClient(), offline=True)}
    (tmp_path / "long.md").write_text(body + "## x\n", encoding="utf-8")
    after = {r["path"]: r["key"] for r in scan_vault(tmp_path, client=FixtureClient(), offline=True)}
    assert before["long.md"] != after["long.md"] and before["a.md"] == after["a.md"]


def test_a_key_can_change_without_the_note_being_edited(tmp_path: Path):
    """in_links depends on other notes: a neighbour that starts linking to a note changes its key."""
    (tmp_path / "a.md").write_text("# A\n\nbody a\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("# B\n\nbody b\n", encoding="utf-8")
    before = {r["path"]: r["key"] for r in scan_vault(tmp_path, client=FixtureClient(), offline=True)}
    (tmp_path / "b.md").write_text("# B\n\nbody b links to [[a]]\n", encoding="utf-8")
    after = {r["path"]: r["key"] for r in scan_vault(tmp_path, client=FixtureClient(), offline=True)}
    assert before["a.md"] != after["a.md"]  # a.md was not edited


def test_an_unparseable_creation_key_falls_back_to_mtime(tmp_path: Path):
    (tmp_path / "bad.md").write_text("---\ncreated: not-a-date\n---\n# A\n\nbody\n", encoding="utf-8")
    (tmp_path / "good.md").write_text("---\ncreated: 2024-01-15\n---\n# B\n\nbody\n", encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True)}
    assert rows["bad.md"]["age_source"] == "mtime" and rows["good.md"]["age_source"] == "frontmatter"
    assert "whose value does not parse (`created: not-a-date` counts as none)" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_alias_is_read_only_when_aliases_is_absent(tmp_path: Path):
    (tmp_path / "both.md").write_text("---\naliases: [Plural One]\nalias: Singular\n---\n# A\n\nbody a\n", encoding="utf-8")
    (tmp_path / "single.md").write_text("---\nalias: Singular\n---\n# B\n\nbody b\n", encoding="utf-8")
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True)
    sent = {s["path"]: s["aliases"] for s in rec.states}
    assert sent["both.md"] == ["Plural One"] and sent["single.md"] == ["Singular"]
    for doc in ("README.md", "SECURITY.md"):
        assert "when there is no `aliases` key (with both present only `aliases` is sent)" in (ROOT / doc).read_text(encoding="utf-8"), doc


def test_vault_and_records_error_rate_stop_messages_agree():
    """Standing rule: one quantity, one wording. Both paths stop on a running total once the window is full."""
    scan_src = (ROOT / "janitor" / "scan.py").read_text(encoding="utf-8")
    records_src = (ROOT / "janitor" / "records.py").read_text(encoding="utf-8")
    assert "notes sent so far failed; that is the run, not the notes." in scan_src
    assert "records sent so far failed; that is the run, not the records." in records_src
    assert "of the first" not in scan_src and "of the first" not in records_src


def test_row_carries_title_sent_and_a_sibling_count_but_no_excerpt_without_show_payload(tmp_path: Path):
    (tmp_path / "a.md").write_text("# Alpha ops@example.com\n\nSECRET-BODY-SENTINEL\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("# Beta\n\nbody b\n", encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True)}
    a = rows["a.md"]
    assert a["title_sent"] == "Alpha [EMAIL]" and a["sibling_titles_sent"] == 1 and "sent" not in a
    assert "SECRET-BODY-SENTINEL" not in json.dumps(a) and "Beta" not in json.dumps(a)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "the redacted title (`title_sent`) and the number of sibling titles sent (`sibling_titles_sent`), but neither the excerpt nor the sibling titles themselves" in readme


# --- 0.4.10: which graph facts depend on other notes, pinned per clause -----------------------

def test_creating_a_links_missing_targets_changes_unresolved_links_and_the_key_but_not_is_moc(tmp_path: Path):
    """A hub with ten links to missing notes, untouched: when the ten notes are created,
    out_links and is_moc stay as they were (the note's own counts), unresolved_links goes
    10 to 0, and the key changes. Through 0.4.9 the README named is_moc, not
    unresolved_links, as the third fact that depends on other notes."""
    (tmp_path / "hub.md").write_text("# Hub\n\n" + " ".join(f"[[t{i}]]" for i in range(10)) + "\n", encoding="utf-8")
    before = next(r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True) if r["path"] == "hub.md")
    for i in range(10):
        (tmp_path / f"t{i}.md").write_text(f"# T{i}\n\nbody {i}\n", encoding="utf-8")
    after = next(r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True) if r["path"] == "hub.md")
    assert before["graph"]["out_links"] == after["graph"]["out_links"] == 10
    assert before["graph"]["is_moc"] is True and after["graph"]["is_moc"] is True
    assert before["graph"]["unresolved_links"] == 10 and after["graph"]["unresolved_links"] == 0
    assert before["key"] != after["key"]


def test_readme_names_exactly_the_facts_that_depend_on_other_notes(tmp_path: Path):
    """The README's clause lists in_links, unresolved_links and is_orphan. Pinned against
    behaviour: for each of the nine facts, whether editing OTHER notes (never the note
    itself) can move it. Exactly those three move; the other six do not."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    clause = re.search(r"three facts depend on other notes, so a key can change without the note being edited: (.*?)\. `is_moc` does not", readme).group(1)
    named = re.findall(r"`(\w+)`", clause)
    assert [n for n in ["in_links", "unresolved_links", "is_orphan"] if n in named] == ["in_links", "unresolved_links", "is_orphan"]
    assert "is_moc" not in named and "words" not in named and "headings" not in named
    # behaviour: an aging, linked-to hub in a linking vault, before and after its neighbours change
    hub = "# Hub\n\n" + " ".join(f"[[t{i}]]" for i in range(10)) + "\n"
    (tmp_path / "hub.md").write_text(hub, encoding="utf-8")
    for i in range(10):
        (tmp_path / f"t{i}.md").write_text(f"# T{i}\n\nbody {i} links [[hub]]\n", encoding="utf-8")
    before = next(r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True) if r["path"] == "hub.md")["graph"]
    for i in range(10):  # neighbours stop linking to the hub; one target disappears
        (tmp_path / f"t{i}.md").write_text(f"# T{i}\n\nbody {i}\n", encoding="utf-8")
    (tmp_path / "t9.md").unlink()
    after = next(r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True) if r["path"] == "hub.md")["graph"]
    moved = {k for k in before if before[k] != after[k]}
    assert moved == {"in_links", "unresolved_links"} | ({"is_orphan"} if before["is_orphan"] != after["is_orphan"] else set())
    assert before["in_links"] == 10 and after["in_links"] == 0 and before["unresolved_links"] == 0 and after["unresolved_links"] == 1
    for own in ("words", "headings", "age_days", "out_links", "embeds", "is_moc"):
        assert before[own] == after[own], own


# --- 0.4.10 self-audit, per clause: sentences that list several behaviours, each clause run ------

def test_a_link_added_past_the_excerpt_cap_changes_the_key(tmp_path: Path):
    """README:85 clause: "A heading or a link added past the excerpt cap … changes the key".
    The heading half has its own test; this is the link half."""
    body = "# T\n\n" + ("filler line of text.\n" * (MAX_EXCERPT // 20))
    (tmp_path / "long.md").write_text(body, encoding="utf-8")
    before = {r["path"]: r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True)}
    (tmp_path / "long.md").write_text(body + "see [[elsewhere]]\n", encoding="utf-8")
    after = {r["path"]: r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True)}
    assert before["long.md"]["graph"]["out_links"] == 0 and after["long.md"]["graph"]["out_links"] == 1
    assert before["long.md"]["key"] != after["long.md"]["key"]


def test_a_dated_note_does_not_get_younger_when_edited_or_cloned(tmp_path: Path):
    """README:85 clauses: "For a note that carries a parseable one, editing it does not make it
    younger and a fresh clone does not make it new". Editing and re-writing the file (which
    is what a clone does to mtime) leaves age_days and the key alone."""
    from janitor.index import build_index

    (tmp_path / "old.md").write_text("---\ncreated: 2020-01-15\n---\n# Old\n\nbody\n", encoding="utf-8")
    first = build_index(tmp_path).facts("old.md")
    (tmp_path / "old.md").write_text("---\ncreated: 2020-01-15\n---\n# Old\n\nbody\n", encoding="utf-8")  # rewritten: a fresh mtime
    second = build_index(tmp_path).facts("old.md")
    assert first["age_days"] == second["age_days"] == 1000  # the top band, from the frontmatter date
    (tmp_path / "new.md").write_text("# New\n\nbody\n", encoding="utf-8")  # no date: mtime, just written
    assert build_index(tmp_path).facts("new.md")["age_days"] == 0


def test_age_bands_include_the_thousand_day_edge(tmp_path: Path):
    """README:85 clause: "the day a note crosses a band edge … 1, 7, 30, 90, 365 or 1000 days old"."""
    from datetime import date, timedelta

    from janitor.index import AGE_BANDS, build_index

    assert AGE_BANDS == (0, 1, 7, 30, 90, 365, 1000)
    for days, band in ((0, 0), (1, 1), (6, 1), (7, 7), (999, 365), (1000, 1000), (5000, 1000)):
        d = (date.today() - timedelta(days=days)).isoformat()
        (tmp_path / f"n{days}.md").write_text(f"---\ncreated: {d}\n---\n# N\n\nbody {days}\n", encoding="utf-8")
    index = build_index(tmp_path)
    for days, band in ((0, 0), (1, 1), (6, 1), (7, 7), (999, 365), (1000, 1000), (5000, 1000)):
        assert index.facts(f"n{days}.md")["age_days"] == band, days


def test_an_undecodable_note_is_left_untouched_and_the_run_continues(tmp_path: Path):
    """README:140 clauses beyond the row shape: "is left untouched; the run continues"."""
    raw = b"# T\n\n\xff\xfe not utf-8\n"
    (tmp_path / "bad.md").write_bytes(raw)
    (tmp_path / "ok.md").write_text("# OK\n\nbody\n", encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True, apply=True)}
    assert rows["bad.md"]["kind"] == "skip" and rows["ok.md"]["kind"] == "vote" and rows["ok.md"].get("applied") == "frontmatter"
    assert (tmp_path / "bad.md").read_bytes() == raw


def test_hidden_notes_are_never_opened_and_sensitive_ones_only_under_the_flag(tmp_path: Path):
    """README:213 clauses: "notes on hidden paths are never opened, and notes on sensitive paths
    only under --include-sensitive". A note that is not UTF-8 produces an undecodable finding
    only if it is opened, so it is the probe."""
    (tmp_path / ".trash").mkdir()
    (tmp_path / ".trash" / "h.md").write_bytes(b"# H\n\n\xff\xfe\n")
    (tmp_path / "family").mkdir()
    (tmp_path / "family" / "f.md").write_bytes(b"# F\n\n\xff\xfe\n")
    (tmp_path / "ok.md").write_text("# OK\n\nbody\n", encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True)}
    hidden = rows.get(".trash/h.md", {})  # a hidden note gets no vote row and no finding: it was never opened
    assert hidden.get("kind") in (None, "skip") and hidden.get("findings") is None
    assert rows["family/f.md"]["kind"] == "skip" and rows["family/f.md"].get("findings") is None
    rows = {r["path"]: r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True, include_sensitive=True)}
    assert rows["family/f.md"].get("findings") == ["undecodable"]  # opened now, and found unreadable
    assert rows.get(".trash/h.md", {}).get("findings") is None  # still never opened
