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
