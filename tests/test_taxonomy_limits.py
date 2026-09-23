"""The API rejects a Choice with more than 255 options and a Score with more than 10 levels
(measured 2026-09-21). load_taxonomy refuses such a taxonomy before any request is built.
"""

from pathlib import Path

import pytest
import yaml

from janitor.schema import DEFAULT_TAXONOMY, MAX_CHOICE_OPTIONS, MAX_SCORE_LEVELS, load_taxonomy


def _write(tmp_path: Path, *, buckets=None, persist=None) -> Path:
    data = yaml.safe_load(DEFAULT_TAXONOMY.read_text(encoding="utf-8"))
    if buckets is not None:
        data["questions"]["bucket"]["options"] = buckets
    if persist is not None:
        data["questions"]["persist"]["levels"] = persist
    p = tmp_path / "t.yaml"
    p.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return p


def test_limits_match_measured_values():
    assert MAX_CHOICE_OPTIONS == 255 and MAX_SCORE_LEVELS == 10


def test_default_taxonomy_is_within_limits():
    from janitor.schema import buckets, persist_levels

    tax = load_taxonomy()
    assert len(buckets(tax)) <= MAX_CHOICE_OPTIONS and len(persist_levels(tax)) <= MAX_SCORE_LEVELS


def test_too_many_persist_levels_is_refused_locally(tmp_path: Path):
    p = _write(tmp_path, persist=[f"level {i}" for i in range(11)])
    with pytest.raises(ValueError, match="at most 10 levels"):
        load_taxonomy(p)
    assert load_taxonomy(_write(tmp_path, persist=[f"level {i}" for i in range(10)]))


def test_too_many_buckets_is_refused_locally(tmp_path: Path):
    p = _write(tmp_path, buckets={f"b{i}": f"bucket {i}" for i in range(256)})
    with pytest.raises(ValueError, match="at most 255 options"):
        load_taxonomy(p)
    assert load_taxonomy(_write(tmp_path, buckets={f"b{i}": f"bucket {i}" for i in range(255)}))
