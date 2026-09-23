from janitor.redact import path_is_sensitive, redact


def test_redacts_openai_style_key():
    result = redact("token sk-abcdefghijklmnopqrstuvwxyz012345 end")
    assert "[KEY]" in result.text
    assert "sk-" not in result.text
    assert "KEY" in result.hits


def test_redacts_email_and_denylist():
    result = redact("Ask ops@example.com or call Ada Lovelace.", denylist=["Ada Lovelace"])
    assert "[EMAIL]" in result.text
    assert "[NAME]" in result.text
    assert "Ada" not in result.text


def test_sensitive_paths():
    assert path_is_sensitive("vault/family/dad.md")
    assert path_is_sensitive("secrets/cards.md")
    assert path_is_sensitive("Personal\\journal.md")
    assert not path_is_sensitive("vault/family/dad.md", parts=("inbox",))
    assert path_is_sensitive("vault/drafts/x.md", parts=("drafts",))
    # Matching is by whole words of the folder name (0.4.1; exact per folder name through 0.4.0,
    # which scanned every one of these decorated inboxes). A longer word is a near-miss the
    # pre-flight names instead.
    assert path_is_sensitive("_Inbox/verdicts.md")
    assert path_is_sensitive("_inbox/verdicts.md")
    assert path_is_sensitive("Inbox_/verdicts.md")
    assert path_is_sensitive("00 Inbox/verdicts.md")
    assert path_is_sensitive("0 - Inbox/verdicts.md")
    assert path_is_sensitive("Private Notes/keys.md")
    assert path_is_sensitive("_private/keys.md")
    assert path_is_sensitive("private-equity/deal.md")  # over-match, on purpose: skipping is the safe way to be wrong
    assert path_is_sensitive("INBOX/x.md")
    assert not path_is_sensitive("inboxes/verdicts.md")
    assert not path_is_sensitive("myinbox/verdicts.md")
    assert not path_is_sensitive("notes/inbox.md")  # the file's own name never counts
    assert not path_is_sensitive("vault/notes/memory.md")
    # A multi-word part matches those words in that order, anywhere in the folder name.
    assert path_is_sensitive("2024 Private Notes/keys.md", parts=("private notes",))
    assert not path_is_sensitive("Notes Private/keys.md", parts=("private notes",))
