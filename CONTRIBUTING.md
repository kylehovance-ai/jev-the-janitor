# Contributing

1. Keep the default scan dry-run.
2. Fixtures are invented. Do not add a real secret, a real person's private fact, or real business data.
3. The suite must pass without `TYPESAFE_API_KEY`, on Linux and on Windows.
4. Every file open passes `encoding="utf-8"`.
5. Taxonomy wording belongs in `janitor/taxonomies/vault_memory.yaml`, so Jev sees the new text.
6. Thresholds belong in `janitor/policy.py`, not in the questions.
7. Anything that changes what leaves the machine needs a test asserting on the outgoing state dict, and a line in `SECURITY.md`.

```bash
pip install -e ".[dev,jev]"
pytest -q
```
