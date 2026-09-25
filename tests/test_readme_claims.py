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
    assert rec.states[0]["frontmatter_keys"] == ["client", "title"]  # the tool's own `janitor` key is not sent (0.5.0)
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
                                              "safe_to_leave_in_git", "action", "reason", "model", "taxonomy", "at",
                                              "created_from_mtime"]  # the last only on a note with no creation date (0.5.2)
    (tmp_path / "d.md").write_text("---\ncreated: 2024-02-02\n---\n# D\n\nbody d\n", encoding="utf-8")
    scan_vault(tmp_path, offline=True, apply=True)
    assert "created_from_mtime" not in frontmatter.load(tmp_path / "d.md", encoding="utf-8").metadata["janitor"]


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
    # the header names what will be sent: the included notes minus those code decides locally (the bill says so)
    bill = re.search(r"bill \(estimate\): (\d+) notes to send, \d+ served from the journal, (\d+) decided locally", block)
    assert sending == int(bill.group(1)) and sending + int(bill.group(2)) == sum(included)


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
    from datetime import datetime, timedelta, timezone

    from janitor.index import AGE_BANDS, build_index

    assert AGE_BANDS == (0, 1, 7, 30, 90, 365, 1000)
    # the janitor ages notes by the UTC date; date.today() is the local one and was a day behind
    # for a few hours every evening west of Greenwich, which read a 0-day note as 1 day old
    today = datetime.now(timezone.utc).date()
    for days, band in ((0, 0), (1, 1), (6, 1), (7, 7), (999, 365), (1000, 1000), (5000, 1000)):
        d = (today - timedelta(days=days)).isoformat()
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


# --- 0.5.0 round 3: a cold review's findings, each reproduced on 0.4.10 before it was fixed --------

def test_a_denylisted_name_matches_across_hyphens_and_underscores_in_paths_and_wikilinks(tmp_path: Path):
    """#1. Through 0.4.10 `jane-doe.md`, `Jane_Doe.md` and `[[jane-doe]]` left as written while the
    title read [NAME]. The residual, `JaneDoe` run together, is documented and pinned below."""
    NL = chr(10)
    (tmp_path / "jane-doe.md").write_text("# T1" + NL + NL + "see [[jane-doe]] and [[Jane_Doe]] and JaneDoe" + NL, encoding="utf-8")
    (tmp_path / "Jane_Doe.md").write_text("# T2" + NL + NL + "another body" + NL, encoding="utf-8")
    rec = Recording()
    scan_vault(tmp_path, client=rec, offline=True, denylist=["Jane Doe"])
    paths = sorted(s["path"] for s in rec.states)
    assert paths == ["[NAME].md", "[NAME].md"]
    excerpt = next(s for s in rec.states if s["title"] == "T1")["excerpt"]
    assert "[[[NAME]]] and [[[NAME]]]" in excerpt
    assert "JaneDoe" in excerpt  # the documented residual: no separator, no match
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "run together with no separator" in readme


def test_an_apply_run_does_not_invalidate_its_own_cache(tmp_path: Path, monkeypatch, capsys):
    """#2. Stamping adds a `janitor` key; it is the tool's own and is not sent, so --resume after
    --apply serves every note."""
    from janitor import cli

    vault = tmp_path / "v"
    vault.mkdir()
    for i in range(6):
        (vault / f"n{i}.md").write_text(f"# N{i}\n\nbody {i}\n", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    assert cli.main([str(vault), "--offline", "--no-config", "--apply", "--yes"]) == 0
    capsys.readouterr()
    assert cli.main([str(vault), "--offline", "--no-config", "--resume"]) == 0
    err = capsys.readouterr().err
    assert "6 already voted and unchanged: served from the journal, not sent" in err
    assert "0 new or changed: will be sent" in err


def test_denylist_entries_apply_longest_first():
    """#3."""
    assert redact("met Jane Doe today", ["Jane", "Jane Doe"]).text == "met [NAME] today"
    assert redact("Acme Robotics Ltd", ["Acme", "Acme Robotics Ltd"]).text == "[NAME]"
    assert redact("met Jane today", ["Jane", "Jane Doe"]).text == "met [NAME] today"


def test_a_served_row_names_the_note_it_is_served_to(tmp_path: Path, monkeypatch, capsys):
    """#4. Two notes whose redacted states are identical share a key. On --resume each row must
    name its own path, and under --apply each file gets a row that names it."""
    from janitor import cli

    vault = tmp_path / "v"
    vault.mkdir()
    # the bodies differ (so neither is an exact duplicate), but redaction makes them identical
    (vault / "call 555-123-4567.md").write_text("# call\n\nring 555-123-4567 tomorrow\n", encoding="utf-8")
    (vault / "call 555-987-6543.md").write_text("# call\n\nring 555-987-6543 tomorrow\n", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    assert cli.main([str(vault), "--offline", "--no-config", "--json"]) == 0
    first = json.loads(capsys.readouterr().out)
    keys = {r["key"] for r in first if r.get("kind") == "vote"}
    assert len(keys) == 1
    assert cli.main([str(vault), "--offline", "--no-config", "--resume", "--apply", "--json"]) == 0
    rows = [r for r in json.loads(capsys.readouterr().out) if r.get("kind") == "vote"]
    assert sorted(r["path"] for r in rows) == ["call 555-123-4567.md", "call 555-987-6543.md"]
    assert all(r.get("cached") and r.get("applied") == "frontmatter" for r in rows)
    for name in ("call 555-123-4567.md", "call 555-987-6543.md"):
        assert "janitor:" in (vault / name).read_text(encoding="utf-8")


def test_records_cache_survives_across_generations(tmp_path: Path):
    """#5. Calls went 10, 0, 10, 0 through 0.4.10 because served rows were dropped from the cache."""
    from janitor.records import FixtureRecordClient, judge_records

    class Counting(FixtureRecordClient):
        calls = 0

        def judge(self, *a, **k):
            Counting.calls += 1
            return super().judge(*a, **k)

    p = tmp_path / "r.jsonl"
    p.write_text("".join(json.dumps({"id": str(i), "sent": {"t": f"idea {i}"}}) + "\n" for i in range(5)), encoding="utf-8")
    jd = tmp_path / "j"
    jd.mkdir()
    counts = []
    for _ in range(4):
        Counting.calls = 0
        judge_records(p, ROOT / "examples" / "triage.yaml", offline=False, client=Counting(), journal_dir=jd)
        counts.append(Counting.calls)
    assert counts == [5, 0, 0, 0]


def test_one_failed_stamp_is_one_row_and_the_run_continues(tmp_path: Path, monkeypatch):
    """#6. A header whose `janitor` value is not a mapping, and a file that cannot be replaced:
    the vote is recorded once with applied "error: <Type>", no temp file is left, the run goes on."""
    import os as _os

    (tmp_path / "ok.md").write_text("# ok\n\nbody ok\n", encoding="utf-8")
    (tmp_path / "locked.md").write_text("---\njanitor: locked\n---\n# locked\n\nbody locked\n", encoding="utf-8")
    (tmp_path / "yes.md").write_text("---\njanitor: yes\n---\n# yes\n\nbody yes\n", encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True, apply=True)}
    assert rows["ok.md"]["applied"] == "frontmatter"
    assert rows["locked.md"]["applied"] == "error: ValueError" and rows["yes.md"]["applied"] == "error: ValueError"
    assert rows["locked.md"]["kind"] == "vote" and rows["locked.md"]["bucket"]
    assert not list(tmp_path.glob("*.janitor-tmp"))
    # a replace that fails (a file held open by a sync client on Windows): no debris, one error row
    real_replace = _os.replace

    def failing_replace(src, dst):
        if str(dst).endswith("held.md"):
            raise PermissionError("held open")
        return real_replace(src, dst)

    (tmp_path / "held.md").write_text("# held\n\nbody held\n", encoding="utf-8")
    monkeypatch.setattr(_os, "replace", failing_replace)
    rows = {r["path"]: r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True, apply=True)}
    assert rows["held.md"]["applied"] == "error: PermissionError"
    assert not list(tmp_path.glob("*.janitor-tmp"))
    assert (tmp_path / "held.md").read_text(encoding="utf-8") == "# held\n\nbody held\n"


def test_402_is_a_status_not_a_substring():
    """#8."""
    from janitor.records import out_of_credits

    class E(Exception):
        pass

    assert out_of_credits(E("timeout after 1402 ms")) is False
    assert out_of_credits(E("HTTP 402 Payment Required")) is True
    assert out_of_credits(E("status 402")) is True
    assert out_of_credits(E("402: no available credits")) is True

    class S(Exception):
        status_code = 402

    assert out_of_credits(S("whatever")) is True


def test_truncated_is_computed_on_the_redacted_text(tmp_path: Path):
    """#9. A note whose raw body is over the cap but whose redacted body is under it is not truncated."""
    body = "# T\n\n" + ("ops@example.com " * (MAX_EXCERPT // 16 + 20))
    (tmp_path / "a.md").write_text(body, encoding="utf-8")
    [row] = scan_vault(tmp_path, client=FixtureClient(), offline=True)
    assert len(body) > MAX_EXCERPT and len(redact(body).text) < MAX_EXCERPT
    assert row["truncated"] is False


def test_stamp_keeps_the_headers_line_ending_and_handles_a_quoted_key(tmp_path: Path):
    """#10. An LF header stays LF when only the body holds a CRLF; a quoted "janitor": key is
    the same key, not a second block."""
    from janitor.apply import stamp
    from janitor.client import Vote
    from janitor.policy import decide

    vote = Vote(bucket="reference", bucket_probabilities={"reference": 0.9}, bucket_confidence=0.9, persist=1.0, persist_confidence=0.9,
                contains_secret=0.0, looks_like_duplicate=0.0, records_a_decision=0.0, is_actionable=0.0, safe_to_leave_in_git=0.9, model="fixture")
    action = decide(vote)
    lf = tmp_path / "lf.md"
    lf.write_bytes(b"---\ntitle: T\n---\n# T\n\nline one\r\nline two\n")
    stamp(lf, vote, action, taxonomy="abc")
    raw = lf.read_bytes()
    header = raw.split(b"\n---\n", 1)[0]
    assert b"\r\n" not in header and raw.endswith(b"line one\r\nline two\n")
    quoted = tmp_path / "q.md"
    quoted.write_text('---\n"janitor":\n  bucket: junk\n  action: frontmatter\n---\n# Q\n\nbody\n', encoding="utf-8")
    stamp(quoted, vote, action, taxonomy="abc")
    text = quoted.read_text(encoding="utf-8")
    assert text.count("janitor") == 1 and "bucket: reference" in text


def test_preflight_header_counts_only_what_will_be_sent(tmp_path: Path):
    """#12. Two identical notes: one is decided locally, so the header says 1 of 2, as the bill does."""
    (tmp_path / "a.md").write_text("# a\n\nsame body\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("# b\n\nsame body\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, "-X", "utf8", "-m", "janitor.cli", str(tmp_path), "--plan", "--no-config"],
                          capture_output=True, text=True, env={**os.environ, "TYPESAFE_API_KEY": "not-a-real-key"})
    lines = proc.stdout.splitlines()
    header = next(l for l in lines if l.startswith("jev-janitor pre-flight:"))
    bill = next(l for l in lines if "bill (estimate):" in l)
    assert header.startswith("jev-janitor pre-flight: 1 of 2 notes") and "1 notes to send" in bill


def test_records_cli_validates_excerpt_chars_like_the_vault_cli(tmp_path: Path):
    """#13."""
    from janitor.records_cli import main as records_main

    p = tmp_path / "r.jsonl"
    p.write_text(json.dumps({"id": "1", "sent": {"t": "idea"}}) + "\n", encoding="utf-8")
    for bad in ("abc", "50"):
        with pytest.raises(SystemExit) as exc:
            records_main([str(p), "--questions", str(ROOT / "examples" / "triage.yaml"), "--offline", "--excerpt-chars", bad])
        assert "--excerpt-chars must be" in str(exc.value)


def test_state_digest_watches_every_source_that_decides_what_leaves():
    """#14."""
    from janitor.journal import state_sources_digest

    src = (ROOT / "janitor" / "journal.py").read_text(encoding="utf-8")
    for name in ("frontmatter.note_title", "frontmatter.load_note", "frontmatter.parse_frontmatter", "frontmatter.rank_by_overlap",
                 "frontmatter.collect_titles", "index._aliases", "index.VaultIndex.sibling_titles", "plan.plan_vault"):
        assert f"inspect.getsource({name})" in src, name
    assert len(state_sources_digest()) == 16


def test_a_symlinked_note_is_written_through_not_replaced(tmp_path: Path):
    """#15. The link stays a link; its target is stamped."""
    target = tmp_path / "real" / "n.md"
    target.parent.mkdir()
    target.write_text("# N\n\nbody\n", encoding="utf-8")
    vault = tmp_path / "v"
    vault.mkdir()
    link = vault / "n.md"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not permitted for this user on this platform")
    scan_vault(vault, client=FixtureClient(), offline=True, apply=True)
    assert link.is_symlink()
    assert "janitor:" in target.read_text(encoding="utf-8")


# --- 0.5.2: the 0.5.1 audit's findings, each reproduced on the public 0.5.1 before it was fixed ----

def _run_json(capsys, vault: Path, *extra):
    from janitor import cli
    rc = cli.main([str(vault), "--offline", "--yes", "--journal", "vault", "--json", *extra])
    out = capsys.readouterr().out
    return rc, {r["path"]: r for r in json.loads(out)}


def test_a_stamp_keeps_an_undated_notes_cache_key(tmp_path: Path, capsys):
    """A1. Through 0.5.1 an undated note's sent age came from its mtime, which the stamp's own
    write moved to now: after --apply, --resume served the dated note and re-sent the undated one.
    The stamp now records the pre-write mtime's date; the age (and the key) is read from it."""
    import os as _os
    import time as _time
    NL = chr(10)
    body = NL + NL + "a paragraph about the greenhouse vents and the barrel. " * 20 + NL
    (tmp_path / "dated.md").write_text("---" + NL + "created: 2020-01-01" + NL + "---" + NL + "# Dated note" + body, encoding="utf-8")
    (tmp_path / "undated.md").write_text("# Undated note" + body + "a different closing line" + NL, encoding="utf-8")
    old = _time.time() - 100 * 86400
    for name in ("dated.md", "undated.md"):
        _os.utime(tmp_path / name, (old, old))
    rc, rows = _run_json(capsys, tmp_path, "--apply")
    assert rc == 0 and rows["undated.md"]["applied"] == "frontmatter" and rows["dated.md"]["applied"] == "frontmatter"
    assert rows["undated.md"]["graph"]["age_days"] == 90 and rows["undated.md"]["age_source"] == "mtime"
    stamped = (tmp_path / "undated.md").read_text(encoding="utf-8")
    assert "created_from_mtime: " in stamped  # the pre-write mtime's date, recorded once
    assert "created_from_mtime" not in (tmp_path / "dated.md").read_text(encoding="utf-8")  # a dated note needs none
    assert (tmp_path / "undated.md").stat().st_mtime > old + 86400  # the mtime itself is left at the write: sync clients see it
    rc, rows = _run_json(capsys, tmp_path, "--resume")
    assert rc == 0 and rows["dated.md"]["cached"] is True
    assert rows["undated.md"]["cached"] is True  # 0.5.1: False, its band had fallen from 90 to 0
    assert rows["undated.md"]["graph"]["age_days"] == 90 and rows["undated.md"]["age_source"] == "stamp"
    # a second --apply reaches the same conclusion and does not touch the note
    before = (tmp_path / "undated.md").read_bytes()
    rc, rows = _run_json(capsys, tmp_path, "--resume", "--apply")
    assert rows["undated.md"]["cached"] is True and (tmp_path / "undated.md").read_bytes() == before
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "an undated note's age is read from the date the stamp recorded (`janitor.created_from_mtime`" in readme


def test_a_note_stamped_before_the_recorded_date_keeps_its_key_and_gets_the_date_on_its_next_restamp(tmp_path: Path):
    """A1, the upgrade path: a 0.5.1 stamp has no recorded date. Its age is read from the file's
    mtime, as 0.5.1 sent it, so its key holds; the next re-stamp records the date."""
    from janitor.index import age_source, note_age_days
    from datetime import date
    meta_old = {"janitor": {"bucket": "junk", "at": "2026-09-01T00:00:00Z"}}
    day = date(2026, 9, 24)
    mtime = 1_758_000_000.0  # 2025-09-16
    assert age_source(meta_old) == "mtime" and note_age_days(meta_old, mtime, day) == (day - date(2025, 9, 16)).days
    meta_new = {"janitor": {"bucket": "junk", "created_from_mtime": "2024-01-01"}}
    assert age_source(meta_new) == "stamp" and note_age_days(meta_new, mtime, day) == (day - date(2024, 1, 1)).days
    meta_dated = {"created": "2023-05-05", "janitor": {"created_from_mtime": "2024-01-01"}}
    assert age_source(meta_dated) == "frontmatter" and note_age_days(meta_dated, mtime, day) == (day - date(2023, 5, 5)).days


def test_a_failed_stamp_exits_2_with_its_own_line(tmp_path: Path, capsys):
    """A2. README: the exit code is 2 so scripts can tell "finished with failures". Through 0.5.1
    only error rows counted, so a vote whose file could not be written exited 0."""
    from janitor import cli
    NL = chr(10)
    (tmp_path / "ok.md").write_text("# ok" + NL + NL + "body ok" + NL, encoding="utf-8")
    (tmp_path / "yes.md").write_text("---" + NL + "janitor: yes" + NL + "---" + NL + "# yes" + NL + NL + "body yes" + NL, encoding="utf-8")
    rc = cli.main([str(tmp_path), "--offline", "--yes", "--journal", "vault", "--apply", "--json"])
    out, err = capsys.readouterr()
    rows = {r["path"]: r for r in json.loads(out)}
    assert rows["yes.md"]["applied"] == "error: ValueError" and rows["ok.md"]["applied"] == "frontmatter"
    assert rc == cli.EXIT_ERRORS == 2  # 0.5.1: 0
    assert "1 note(s) were judged but could not be written" in err and "Exit 2" in err
    assert not list(tmp_path.glob("*.janitor-tmp"))
    # and a run with no failed write still exits 0
    (tmp_path / "yes.md").write_text("# yes" + NL + NL + "body yes" + NL, encoding="utf-8")
    assert cli.main([str(tmp_path), "--offline", "--yes", "--journal", "vault", "--apply", "--json"]) == 0
    capsys.readouterr()


def test_a_failed_write_is_retried_under_resume_apply_and_a_dry_resume_does_not_count_it(tmp_path: Path, capsys):
    """Review of 0.5.2's first cut. A note whose write failed was served with its old error on
    every `--resume --apply` and never stamped (the served path re-applied only dry-run rows), so
    the advice "fix the file and run --apply again" only worked without --resume, which re-bills.
    And a dry `--resume` after the failure exited 2 for a write it never attempted."""
    from janitor import cli
    NL = chr(10)
    (tmp_path / "a.md").write_text("---" + NL + "janitor: yes" + NL + "tags: [fence]" + NL + "---" + NL + "# A" + NL + NL + "body a about the fence" + NL, encoding="utf-8")
    (tmp_path / "b.md").write_text("# B" + NL + NL + "body b about the gate" + NL, encoding="utf-8")
    rc, rows = _run_json(capsys, tmp_path, "--apply")
    assert rc == 2 and rows["a.md"]["applied"] == "error: ValueError" and rows["b.md"]["applied"] == "frontmatter"
    # a dry --resume attempts no write: the served row still carries the old error, the exit is 0
    rc, rows = _run_json(capsys, tmp_path, "--resume")
    assert rc == 0 and rows["a.md"]["cached"] is True and rows["a.md"]["applied"] == "error: ValueError"
    # the owner deletes the offending line; the key-name set is unchanged (`janitor` is not sent)
    (tmp_path / "a.md").write_text("---" + NL + "tags: [fence]" + NL + "---" + NL + "# A" + NL + NL + "body a about the fence" + NL, encoding="utf-8")
    rc, rows = _run_json(capsys, tmp_path, "--resume", "--apply")
    assert rows["a.md"]["cached"] is True, "the fix must not re-bill the note"
    assert rows["a.md"]["applied"] == "frontmatter" and rc == 0  # 0.5.2 first cut: served with the old error, rc 2, forever
    assert "janitor:" in (tmp_path / "a.md").read_text(encoding="utf-8") and "tags: [fence]" in (tmp_path / "a.md").read_text(encoding="utf-8")


def test_a_quarantined_note_with_an_unreadable_header_is_moved_unstamped_and_the_manifest_says_why(tmp_path: Path):
    """C5. README and SECURITY said the moved note is always stamped first; a header the janitor
    cannot read is moved exactly as it is, and the reason lives in the manifest either way."""
    NL = chr(10)
    broken = "---" + NL + "status: blocked: waiting on review" + NL + "---" + NL + "# Leak" + NL + NL + "token sk-" + "a" * 40 + NL
    (tmp_path / "leak.md").write_text(broken, encoding="utf-8")
    (tmp_path / "ok.md").write_text("---" + NL + "title: fine" + NL + "---" + NL + "# Leak two" + NL + NL + "token sk-" + "b" * 40 + NL, encoding="utf-8")
    rows = {r["path"]: r for r in scan_vault(tmp_path, client=FixtureClient(), offline=True, apply=True)}
    assert rows["leak.md"]["applied"].startswith("quarantine:") and rows["ok.md"]["applied"].startswith("quarantine:")
    moved = (tmp_path / "_janitor" / "quarantine" / "leak.md").read_text(encoding="utf-8")
    assert moved == broken  # unstamped, byte-for-byte
    assert "janitor:" in (tmp_path / "_janitor" / "quarantine" / "ok.md").read_text(encoding="utf-8")  # stamped, then moved
    manifest = [json.loads(line) for line in (tmp_path / "_janitor" / "quarantine" / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {m["reason"] for m in manifest} and all("KEY" in m["reason"] for m in manifest)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "a note whose header does not parse is moved exactly as it is, unstamped" in readme
    assert "a note whose header" in security and "does not parse is moved as it is, unstamped" in security


def test_the_docs_say_what_holds_after_the_051_audit():
    """C1, C2, C3, C4, C6: each overclaim the audit found, replaced by the measured statement."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "second brain of 250 notes, 251 files with the vault's own README" in readme  # C1: 250 notes, 251 scanned
    # C2, counted through report.diagnose on the committed run rather than pinned as a string: the
    # 0.5.4 wording said "every one of them", and by the report's own rule one pile note is Jev
    # abstaining into needs_review, not a two-bucket split.
    from janitor import report as R
    rows = json.loads((ROOT / "examples" / "demo-vault-run" / "run.json").read_text(encoding="utf-8"))
    D = R.diagnose(rows, sensitive_list=list(R.DEFAULT_SENSITIVE))
    two_bucket = sum(1 for r in D["pile"] if len(R.ordered_probs(r)) >= 2 and "needs_review" not in (R.ordered_probs(r)[0][0], R.ordered_probs(r)[1][0]))
    abstaining = D["n_pile"] - two_bucket
    assert (D["n_pile"], two_bucket, abstaining) == (27, 26, 1)
    assert f"{D['n_pile']} notes (12%) went to the review pile, {two_bucket} of them a split between two buckets and one Jev abstaining into `needs_review`, led by `ephemeral` against `log_entry` (7 notes)" in readme
    assert "every one of them a split" not in readme
    assert "the name in each of `jane-doe.md`, `Jane_Doe.md` and a `[[jane-doe]]` link becomes `[NAME]` (`[NAME].md`, `[NAME].md` and `[[[NAME]]]`" in readme  # C3
    assert "a note's first stamp added a key name and changed its cache key" in readme  # C4
    assert "every `--apply` run changed the cache key of every note it stamped" not in readme
    assert "except the tool's own `janitor` key, which is not sent" in security  # C6
    assert "the manifest either way" in security  # C5
    # the "unrelated folder" examples are fictional ones, in both files
    assert "`Recipes/` or `garden/beds/` get no warning" in readme and "(`Recipes/`, `garden/beds/`)" in security
    # 0.5.3: the third age source is stated wherever the other two are
    assert "until its first `--apply` stamp: the stamp records that date once as `janitor.created_from_mtime`" in readme
    assert "`age_source: frontmatter`, `stamp` (the date the janitor recorded at the note's first stamp, which does not reset) or `mtime`" in readme
    assert "the pre-flight and the run's closing lines count the `mtime` ones against all three" in readme
    assert "`age_source: frontmatter` or `mtime`" not in readme
    assert "and a second one when it is used" in readme and "the footer then names that figure as the second not from the rows" in readme


def test_the_filesystem_age_claim_names_the_stamp_everywhere():
    """0.5.4. "no creation date in their frontmatter; their age comes from the filesystem" was false
    for a stamped undated note since 0.5.2: it has no creation date either, and its age comes from
    the stamp. Every line and sentence on that subject now makes the filesystem age the subject and
    names both conditions; the old form appears nowhere in the docs or the package."""
    old_form = "have no creation date in their frontmatter; their age comes from the filesystem"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "whose age comes from the filesystem (no parseable creation date in their frontmatter and no date recorded by a janitor stamp), which resets" in readme
    assert "    age: 25 of 25 readable notes (100%) take their age from the filesystem (no creation date in their frontmatter, none recorded by a stamp); it resets if this vault is moved, cloned, restored or re-synced" in readme
    sources = [readme, (ROOT / "SECURITY.md").read_text(encoding="utf-8")] + [p.read_text(encoding="utf-8") for p in sorted((ROOT / "janitor").glob("*.py"))]
    for text in sources:
        assert old_form not in text
        assert "whose age therefore comes from the filesystem" not in text
    # the program's two lines and the README's sample block say the same thing, byte for byte
    from janitor.bill import Bill, render_bill
    bill = Bill(question_chars=0, max_usd=None)
    bill.age_from_mtime, bill.dated, bill.stamp_dated = 25, 0, 0
    line = next(l for l in render_bill(bill, live=False).splitlines() if l.strip().startswith("age:"))
    assert line in readme
