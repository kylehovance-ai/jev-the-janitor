<!-- Public page: no real note text, keys, --show-payload output from a real vault, or journals. -->

## What this changes

## CONTRIBUTING checklist

- [ ] 1. The default scan is still a dry run.
- [ ] 2. Every fixture is invented: no real secret, no real person's private fact, no real business data.
- [ ] 3. The suite passes without `TYPESAFE_API_KEY`, on Linux and on Windows.
- [ ] 4. Every file open passes `encoding="utf-8"`.
- [ ] 5. Taxonomy wording changed in `janitor/taxonomies/vault_memory.yaml`, if at all, so Jev sees the new text.
- [ ] 6. Thresholds changed in `janitor/policy.py`, if at all, not in the questions.
- [ ] 7. If anything that leaves the machine changed: a test asserts on the outgoing state dict, `SECURITY.md` has a line, and `STATE_VERSION` moved.
