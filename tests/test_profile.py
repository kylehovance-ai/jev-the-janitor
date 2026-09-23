"""janitor.toml: a vault profile the tool reads and never writes.

Flag beats profile beats default, the pre-flight names which happened, and an unknown
key is refused rather than ignored.
"""

from pathlib import Path

import pytest

from janitor import cli
from janitor.profile import Profile, find_profile, load_profile


def _vault(tmp_path: Path, profile: str | None = None) -> Path:
    vault = tmp_path / "vault"
    (vault / "notes").mkdir(parents=True)
    (vault / "clients").mkdir()
    (vault / "notes" / "a.md").write_text("# A\n\nAda Lovelace wrote a note.\n", encoding="utf-8")
    (vault / "clients" / "acme.md").write_text("# Acme\n\nclient body\n", encoding="utf-8")
    (vault / "family").mkdir()
    (vault / "family" / "mom.md").write_text("# Mom\n\nfamily body\n", encoding="utf-8")
    if profile is not None:
        (vault / "janitor.toml").write_text(profile, encoding="utf-8")
    return vault


def test_no_profile_means_defaults_and_the_preflight_says_so(tmp_path: Path, capsys):
    vault = _vault(tmp_path)
    assert cli.main([str(vault), "--plan"]) == 0
    out = capsys.readouterr().out
    assert "profile: none (built-in defaults" in out
    assert "family/" in out and "sensitive path part 'family'" in out
    assert "clients/" in out and "1 notes" in out


def test_profile_at_the_vault_root_is_read_and_named(tmp_path: Path, capsys):
    vault = _vault(tmp_path, 'sensitive_paths = ["clients"]\ndenylist = "names.txt"\nworkers = 3\nexcerpt_chars = "full"\n')
    (vault / "names.txt").write_text("Ada Lovelace\n", encoding="utf-8")
    assert cli.main([str(vault), "--plan"]) == 0
    out = capsys.readouterr().out
    assert f"profile: {vault / 'janitor.toml'} (" in out and "sets denylist, excerpt_chars, sensitive_paths, workers" in out
    assert "sensitive path part 'clients'" in out and "sensitive path part 'family'" not in out  # the list replaces the default
    assert "EXCERPT: WHOLE NOTES" in out
    assert cli.main([str(vault), "--offline", "--json"]) == 0
    assert "Lovelace" not in capsys.readouterr().out  # the profile's denylist applied, relative to the profile


def test_a_flag_overrides_the_profile_for_one_run(tmp_path: Path, capsys):
    vault = _vault(tmp_path, 'sensitive_paths = ["clients"]\nworkers = 3\n')
    assert cli.main([str(vault), "--plan", "--sensitive-paths", "family"]) == 0
    out = capsys.readouterr().out
    assert "sensitive path part 'family'" in out and "sensitive path part 'clients'" not in out
    assert cli.main([str(vault), "--offline", "--workers", "2"]) == 0
    assert "workers=2" in capsys.readouterr().out


def test_config_flag_and_no_config(tmp_path: Path, capsys):
    vault = _vault(tmp_path, 'sensitive_paths = ["clients"]\n')
    elsewhere = tmp_path / "other.toml"
    elsewhere.write_text('sensitive_paths = ["notes"]\n', encoding="utf-8")
    assert cli.main([str(vault), "--plan", "--config", str(elsewhere)]) == 0
    out = capsys.readouterr().out
    assert f"profile: {elsewhere}" in out and "sensitive path part 'notes'" in out
    assert cli.main([str(vault), "--plan", "--no-config"]) == 0
    out = capsys.readouterr().out
    assert "profile: none" in out and "sensitive path part 'family'" in out
    with pytest.raises(SystemExit, match="--config: no such file"):
        cli.main([str(vault), "--plan", "--config", str(tmp_path / "missing.toml")])


def test_unknown_key_and_wrong_type_are_refused_not_ignored(tmp_path: Path):
    vault = _vault(tmp_path, 'sensitve_paths = ["clients"]\n')  # misspelled: silently ignoring it would be a privacy hole
    with pytest.raises(SystemExit, match="unknown key"):
        cli.main([str(vault), "--plan"])
    (vault / "janitor.toml").write_text('workers = "eight"\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="workers must be int"):
        cli.main([str(vault), "--plan"])
    (vault / "janitor.toml").write_text('sensitive_paths = [1, 2]\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="list of strings"):
        cli.main([str(vault), "--plan"])
    (vault / "janitor.toml").write_text("not = [toml\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="not a readable TOML profile"):
        cli.main([str(vault), "--plan"])


def test_single_file_target_reads_the_profile_from_its_folder(tmp_path: Path, capsys):
    vault = _vault(tmp_path, 'sensitive_paths = ["notes"]\n')
    assert cli.main([str(vault / "notes" / "a.md"), "--plan"]) == 0
    out = capsys.readouterr().out
    assert "profile:" in out and "notes" in out
    profile = find_profile(vault / "notes" / "a.md")
    assert profile.path is None  # a note's own folder has no janitor.toml; the vault root above it is not searched
    profile = find_profile(vault)
    assert profile.path == vault / "janitor.toml" and profile.get("sensitive_paths") == ["notes"]


def test_ceiling_and_git_threshold_and_include_sensitive_from_profile(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    vault = _vault(tmp_path, "max_usd = 0.0001\ninclude_sensitive = true\ngit_unsafe_below = 0.2\n")
    assert cli.main([str(vault), "--yes"]) == cli.EXIT_REFUSED
    err = capsys.readouterr().err
    assert "ceiling $0.0001: OVER" in err
    assert "family/" in err and "sensitive path part" not in err  # include_sensitive from the profile
    assert cli.main([str(vault), "--plan", "--max-usd", "0"]) == 0  # flag wins: no ceiling line at all
    assert ": OVER" not in capsys.readouterr().out


def test_profile_object_paths_are_resolved_relative_to_the_file(tmp_path: Path):
    p = tmp_path / "cfg" / "janitor.toml"
    p.parent.mkdir()
    p.write_text('denylist = "../names.txt"\ntaxonomy = "tax.yaml"\njournal = "runs"\n', encoding="utf-8")
    prof = load_profile(p)
    assert prof.get("denylist") == (tmp_path / "names.txt").resolve()
    assert prof.get("taxonomy") == (p.parent / "tax.yaml").resolve()
    assert prof.get("journal") == str((p.parent / "runs").resolve())
    assert len(prof.fingerprint) == 12 and Profile().fingerprint is None


def test_dry_run_with_a_profile_writes_nothing_into_the_vault(tmp_path: Path):
    vault = _vault(tmp_path, 'workers = 2\n')
    before = sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*"))
    assert cli.main([str(vault), "--offline"]) == 0
    assert sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*")) == before
