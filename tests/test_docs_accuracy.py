"""0.5.7: the repo files no audit had covered, pinned against the code.

AGENTS.md's contract, POLICY.md's promises, CONTRIBUTING's rules mirrored by the PR template, the
issue templates' privacy warning, the CI workflow's permissions, the project URLs, the code of
conduct's contact, and the README's full-vault sentence.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from janitor import cli
from janitor.policy import decide
import inspect

ROOT = Path(__file__).resolve().parent.parent
NL = chr(10)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_agents_contract_names_exactly_the_fields_a_real_sent_object_has(tmp_path: Path, capsys):
    """AGENTS.md item 2 said five fields and "Nothing else"; a real `sent` has seven."""
    (tmp_path / "a.md").write_text("---" + NL + "aliases: [x]" + NL + "---" + NL + "# A" + NL + NL + "body a" + NL, encoding="utf-8")
    (tmp_path / "b.md").write_text("# B" + NL + NL + "body b" + NL, encoding="utf-8")
    assert cli.main([str(tmp_path), "--offline", "--json", "--show-payload", "--journal", "off"]) == 0
    sent = next(r["sent"] for r in json.loads(capsys.readouterr().out) if r.get("sent"))
    agents = _read("AGENTS.md")
    item2 = agents.split("2. Send exactly seven fields")[1].split("3. Read")[0]
    documented = re.findall(r"`([a-z_]+)`", item2)
    documented = [d for d in documented if d not in ("janitor", "excerpt-chars", "is_moc", "is_orphan", "sent")]  # words the sentence uses, not fields
    assert set(documented) == set(sent.keys()) == {"title", "path", "aliases", "frontmatter_keys", "excerpt", "other_note_titles", "graph"}
    assert "Nothing else." in item2
    assert all(isinstance(v, (int, bool, type(None))) for v in sent["graph"].values())  # graph is counts and flags only (int | bool; None for unknown)
    assert "counts and flags only" in item2 and "numbers only" not in item2
    # item 3 lists what decide() reads from a vote
    read = set(re.findall(r"vote\.(\w+)", inspect.getsource(decide)))
    item3 = agents.split("3. Read")[1].split("4. Code decides")[0]
    assert set(re.findall(r"`([a-z_]+)`", item3)) >= read


def test_policy_states_what_the_stamp_writes_and_what_leaves():
    policy = _read("POLICY.md")
    # the stamp writes a number, not a word (README's example block shows `persist: 1.25`)
    assert "the stamp writes the" + NL + "number: `persist: <0 to 2>`" in policy
    assert "labels written to frontmatter" not in policy
    readme = _read("README.md")
    assert re.search(r"^  persist: \d+\.\d+$", readme, re.M)
    # quarantine: stamped when the header parses, moved as it is when it does not
    assert "(move, unchanged" not in policy
    assert "A note whose header parses is stamped with its `janitor:` block" in policy and "moves" + NL + "exactly as it is, unstamped" in policy
    # what leaves: the seven fields, the body cut at the cap, so a note under the cap goes whole
    assert "Send a whole vault, or a whole note body" not in policy
    assert "Send anything but the seven redacted fields" in policy and "a note under the cap goes whole" in policy
    rows = json.loads(_read("examples/demo-vault-run/run.json"))
    jev = [r for r in rows if r.get("kind") == "vote" and r.get("judge") == "jev"]
    whole = sum(1 for r in jev if not r.get("truncated"))
    assert (len(jev), whole) == (229, 227) and f"{whole} of the {len(jev)} sent notes did" in policy


def test_readme_full_vault_sentence_matches_the_verified_numbers():
    """Verified from the Sep 23 live journal's header, footer and row kinds: 25,107 rows = 18,882 votes
    (17,140 by Jev, 1,742 local) + 6,216 withheld + 9 errors, $2.51, 4 min 56 s, 16 workers, a 0.4.x release."""
    readme = _read("README.md")
    assert "26 real notes from one production vault" in readme and "and on 26 real notes" not in readme.split("**Does it work.**")[1][:40]
    assert ("on one full real vault of 25,107 notes: 17,140 judged by Jev, 1,742 decided locally, 6,216 withheld and 9 refused by the API, "
            "for $2.51 in 4 min 56 s at 16 workers") in readme
    assert 17_140 + 1_742 + 6_216 + 9 == 25_107


def test_community_files_and_ci_polish():
    conduct = _read("CODE_OF_CONDUCT.md")
    assert "Contributor Covenant" in conduct and "version 2.1" in conduct and "kylehovance@proton.me" in conduct
    bug = _read(".github/ISSUE_TEMPLATE/bug_report.yml")
    assert bug.index("Never paste real note text") < bug.index("- type: input")  # the privacy warning comes first
    for phrase in ("`--show-payload`", "journal", "pip show jev-the-janitor", "there is no `--version` flag", "examples/demo-vault", "fixtures/notes", "--offline"):
        assert phrase in bug, phrase
    assert "name: Feature request" in _read(".github/ISSUE_TEMPLATE/feature_request.yml")
    config = _read(".github/ISSUE_TEMPLATE/config.yml")
    assert "blank_issues_enabled: false" in config and "security/advisories/new" in config
    pr = _read(".github/pull_request_template.md")
    contributing = _read("CONTRIBUTING.md")
    rules = [line for line in contributing.splitlines() if re.match(r"^\d\. ", line)]
    assert len(rules) == 7 and all(f"- [ ] {i}. " in pr for i in range(1, 8))
    ci = _read(".github/workflows/ci.yml")
    assert re.search(r"^permissions:" + NL + r"  contents: read$", ci, re.M)
    pyproject = _read("pyproject.toml")
    assert "[project.urls]" in pyproject and 'Issues = "https://github.com/kylehovance-ai/jev-the-janitor/issues"' in pyproject
    readme = _read("README.md")
    assert "actions/workflows/ci.yml/badge.svg" in readme and readme.count("badge.svg") == 1  # GitHub's own badge, no third-party ones
    security = _read("SECURITY.md")
    assert '"Report a vulnerability"' in security and "Security tab" in security
    assert '"--version"' not in _read("janitor/cli.py")  # there is no --version flag: the bug form says so and points at pip show
