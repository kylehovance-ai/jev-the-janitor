"""A vault profile: janitor.toml at the vault root, so a scheduled scan is repeatable.

An orchestrator runs this against one vault on a schedule, not by retyping flags. The
profile holds what would otherwise be flags; a flag given on the command line overrides
the profile for that invocation; a missing profile means today's defaults, and the
pre-flight says which of the three happened. The tool reads the profile and never writes
it: a dry run still changes nothing on disk.

Unknown keys are refused rather than ignored, because a misspelled ``sensitive_paths``
that silently did nothing would be a privacy hole with a config file's confidence.
"""

from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROFILE_NAME = "janitor.toml"

# key -> (accepted python types, one-line meaning). Paths are relative to the profile's folder.
KNOWN_KEYS: dict[str, tuple[tuple[type, ...], str]] = {
    "sensitive_paths": ((list,), "folder names treated as sensitive; replaces the default list"),
    "denylist": ((str,), "path to a newline-separated denylist, relative to this file"),
    "taxonomy": ((str,), "path to a taxonomy YAML, relative to this file"),
    "excerpt_chars": ((int, str), "characters of each note sent after redaction; 'full' or 0 for whole notes"),
    "workers": ((int,), "concurrent requests"),
    "journal": ((str,), "'default' (user cache dir), 'vault', 'off', or a directory"),
    "model": ((str,), "model id to request"),
    "max_usd": ((int, float), "ceiling for one live run's pessimistic cost estimate in dollars; 0 for none"),
    "git_unsafe_below": ((int, float), "quarantine when safe_to_leave_in_git is at or below this; unset = off"),
    "include_sensitive": ((bool,), "scan notes on sensitive paths (their titles are still never sibling context)"),
}


@dataclass
class Profile:
    path: Path | None = None  # None: no profile, built-in defaults
    values: dict[str, Any] = field(default_factory=dict)
    fingerprint: str | None = None

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def describe(self) -> str:
        if self.path is None:
            return "profile: none (built-in defaults; put a janitor.toml at the vault root to make a scan repeatable)"
        keys = ", ".join(sorted(self.values)) or "no keys"
        return f"profile: {self.path} ({self.fingerprint}; sets {keys})"


def profile_root(target: Path) -> Path:
    """Where a profile is looked for: the directory named, or a single file's folder."""
    target = target.resolve()
    return target if target.is_dir() else target.parent


def load_profile(path: Path) -> Profile:
    raw = path.read_bytes()
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"{path}: not a readable TOML profile: {exc}") from None
    unknown = sorted(k for k in data if k not in KNOWN_KEYS)
    if unknown:
        raise SystemExit(f"{path}: unknown key(s) {unknown}. Known keys: {', '.join(sorted(KNOWN_KEYS))}")
    for key, value in data.items():
        types, meaning = KNOWN_KEYS[key]
        if not isinstance(value, types) or (isinstance(value, bool) and bool not in types):
            raise SystemExit(f"{path}: {key} must be {' or '.join(t.__name__ for t in types)} ({meaning}); got {value!r}")
        if key == "sensitive_paths" and not all(isinstance(v, str) for v in value):
            raise SystemExit(f"{path}: sensitive_paths must be a list of strings")
    values = dict(data)
    for key in ("denylist", "taxonomy"):
        if key in values:
            values[key] = (path.parent / values[key]).resolve()
    if "excerpt_chars" in values:
        values["excerpt_chars"] = str(values["excerpt_chars"])
    if "journal" in values and values["journal"] not in ("default", "vault", "off"):
        values["journal"] = str((path.parent / values["journal"]).resolve())
    return Profile(path=path, values=values, fingerprint=hashlib.sha256(raw).hexdigest()[:12])


def find_profile(target: Path, *, explicit: Path | None = None, disabled: bool = False) -> Profile:
    """``--config PATH`` wins; ``--no-config`` reads none; otherwise <root>/janitor.toml if present."""
    if disabled:
        return Profile()
    if explicit is not None:
        if not explicit.exists():
            raise SystemExit(f"--config: no such file: {explicit}")
        return load_profile(explicit.resolve())
    candidate = profile_root(target) / PROFILE_NAME
    return load_profile(candidate) if candidate.is_file() else Profile()
