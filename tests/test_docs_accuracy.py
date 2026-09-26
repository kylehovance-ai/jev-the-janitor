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
    graph_text = item2.split("and `graph` (")[1].split("Nothing else")[0]  # up to the closing sentence; "(banded)" sits inside
    graph_keys = set(re.findall(r"`([a-z_]+)`", graph_text))
    documented = [d for d in documented if d not in ("janitor", "excerpt-chars", "sent") and d not in graph_keys]  # words the sentence uses, not fields
    assert set(documented) == set(sent.keys()) == {"title", "path", "aliases", "frontmatter_keys", "excerpt", "other_note_titles", "graph"}
    assert "Nothing else." in item2
    assert all(isinstance(v, (int, bool, type(None))) for v in sent["graph"].values())  # graph is counts and flags only (int | bool; None for unknown)
    assert "counts and flags only" in item2 and "numbers only" not in item2
    # 0.5.8: the nine graph keys, by name, exact equality with a real payload (0.5.7 omitted `embeds`)
    assert graph_keys == set(sent["graph"].keys()) == {"words", "headings", "age_days", "out_links", "in_links", "embeds", "unresolved_links", "is_moc", "is_orphan"}
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
    # 0.5.8 r2: the bill paragraph's parenthetical said "17,140 notes sent"; 17,149 requests went out (9 were refused),
    # so 17,140 is the judged count, and the two sentences must agree
    assert "A live run on a 25,107-note real vault (17,140 notes judged by Jev, " in readme
    assert "17,140 notes sent" not in readme


def test_readme_top_is_privacy_first_and_how_it_works_sits_below_the_contract():
    """0.5.8. A visitor reads the pitch, one privacy line, the affiliation note, then the card; the
    explanatory paragraphs and the flow diagram moved under a How it works heading after the contract."""
    readme = _read("README.md")
    privacy = ("**Privacy first.** Each note is redacted on your machine (best-effort, format by format) before anything is sent; "
               "`--offline --show-payload` prints exactly what would leave, for free; the bill is shown before the first request; "
               "and it never deletes a note.")
    lines = readme.split(NL)
    banner = ("![A brain made of note cards; an amber scan line passes through it, and the notes it has read are filed into three stacks]"
              "(.github/banner.jpg)")
    assert lines[0].startswith("# Jev the Janitor [![ci](") and lines[2] == banner and lines[4].startswith("A janitor for markdown vaults.")  # badge on the title line, banner below
    assert lines[6] == privacy and lines[8].startswith("This project is not affiliated") and lines[10] == "## See a brain scan"
    assert (ROOT / ".github" / "banner.jpg").is_file() and (ROOT / ".github" / "banner.jpg").read_bytes()[:2] == b"\xff\xd8"
    order = ["## See a brain scan", "## Quick start", "## The privacy contract", "## How it works", "**What Jev is.**",
             "**Who this is for.**", "**Does it work.**", "Jev votes. Your code files. You review the low-confidence pile.", "## The run journal"]
    positions = [readme.index(h) for h in order]
    assert positions == sorted(positions), order
    assert readme.count("## How it works") == 1 and readme.count(privacy) == 1
    # each clause of the new line is a claim the README or POLICY already makes
    assert "**Redaction is best-effort.**" in readme and "--offline --show-payload" in readme
    policy_flat = " ".join(_read("POLICY.md").split())  # the sentence wraps across a line break
    assert "before any request, the pre-flight prints" in readme and "the only thing it deletes is nothing" in policy_flat


def test_community_files_and_ci_polish():
    # 0.5.8: no code of conduct, by decision (the repo's focus is privacy and security), and nothing points at one
    assert not (ROOT / "CODE_OF_CONDUCT.md").exists()
    for rel in ("README.md", "CONTRIBUTING.md", "SECURITY.md", ".github/pull_request_template.md",
                ".github/ISSUE_TEMPLATE/bug_report.yml", ".github/ISSUE_TEMPLATE/feature_request.yml", ".github/ISSUE_TEMPLATE/config.yml"):
        assert "code of conduct" not in _read(rel).lower() and "CODE_OF_CONDUCT" not in _read(rel), rel
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
