"""Decide what is read, before anything is read. No note is opened here.

``plan_vault`` is the single place that decides which files a run will touch; the pre-flight
prints it, the index reads exactly it, and the CLI refuses on it. Keeping it free of any
file read is what lets the privacy claims be argued from one function.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from janitor.redact import DEFAULT_SENSITIVE_PATH_PARTS, matching_part, segment_matches


@dataclass
class PlanEntry:
    rel: str  # vault-relative posix path
    status: str  # scan | skip_sensitive | skip_hidden | skip_janitor
    rule: str  # human-readable reason for a skip, empty for scan
    sensitive: bool = False  # on a sensitive path: scanned only under --include-sensitive, never a sibling title

    @property
    def folder(self) -> str:
        return rel_folder(self.rel)


def rel_folder(rel: str) -> str:
    return rel.rsplit("/", 1)[0] + "/" if "/" in rel else "./"


def plan_vault(
    vault: Path,
    *,
    include_sensitive: bool = False,
    sensitive_parts: tuple[str, ...] | None = None,
) -> tuple[Path, list[PlanEntry]]:
    """Classify every note before anything runs. Returns (vault_root, entries).

    This is the single place that decides what is read. ``scan_vault`` and the pre-flight
    summary both consume it, so what the operator is shown is what will happen.
    """
    vault = vault.resolve()
    parts = tuple(sensitive_parts if sensitive_parts is not None else DEFAULT_SENSITIVE_PATH_PARTS)
    if vault.is_file():
        candidates = [vault]
        vault = vault.parent
    else:
        candidates = sorted(vault.rglob("*.md"))
    # The path the operator names is tested by the same rules as a vault-relative path,
    # against its own absolute folder names. Relative segments alone left two doors open,
    # because whatever is named becomes the root and the root's own name is never a
    # segment: `vault/family/mom.md` scanned in 0.1.0, `vault/family` scanned through
    # 0.2.0. This is a local comparison; the absolute path never leaves the machine.
    # Matching is by whole words of the folder name (redact.segment_matches): `_Inbox`,
    # `00 Inbox` and `Private Notes` are sensitive, `inboxes` is a near-miss the pre-flight warns about.
    root_hit = [p for p in vault.parts if matching_part(p, parts) is not None]
    root_in_janitor = "_janitor" in vault.parts

    entries: list[PlanEntry] = []
    for path in candidates:
        rel_parts = path.relative_to(vault).parts
        rel = "/".join(rel_parts)
        hidden = [part for part in rel_parts if part.startswith(".")]
        if hidden:
            entries.append(PlanEntry(rel, "skip_hidden", f"hidden folder or file '{hidden[0]}' (starts with '.')"))
            continue
        if root_in_janitor or "_janitor" in rel_parts:
            entries.append(PlanEntry(rel, "skip_janitor", "janitor working folder '_janitor'"))
            continue
        matched = root_hit + [part for part in rel_parts[:-1] if matching_part(part, parts) is not None]
        if matched and not include_sensitive:
            entries.append(PlanEntry(rel, "skip_sensitive", f"sensitive path part '{matched[0]}'", sensitive=True))
            continue
        entries.append(PlanEntry(rel, "scan", "", sensitive=bool(matched)))
    return vault, entries


VAULT_MARKERS = (".obsidian",)


def vault_root(target: Path) -> Path | None:
    """The nearest directory at or above ``target`` that holds a vault marker (``.obsidian/``), or None."""
    target = target.resolve()
    start = target if target.is_dir() else target.parent
    for candidate in (start, *start.parents):
        if any((candidate / marker).is_dir() for marker in VAULT_MARKERS):
            return candidate
    return None


def root_refusal(target: Path, sensitive_parts: tuple[str, ...] | None = None, *, include_sensitive: bool = False) -> str | None:
    """Why a directory target ABOVE which a sensitive folder name sits should not run at all.

    Same string, opposite meaning: a folder called ``personal`` inside the vault is the
    note-taker's own statement about the notes in it, and is skipped quietly like any other
    sensitive path. A folder called ``personal`` above the vault root is an accident of
    where the vault was mounted and says nothing about any note inside. Planning every
    note as skipped and exiting 0 would be a run that judged nothing and reported success,
    which on a schedule is silent forever. So that case refuses, with the remedy named.
    The target's own name is not an ancestor; ``jev-janitor ./vault/family`` still skips.
    A single file keeps the strict, quiet rule: a false skip costs one note.
    """
    target = target.resolve()
    if target.is_file() or include_sensitive:
        return None
    parts = tuple(p for p in (sensitive_parts if sensitive_parts is not None else DEFAULT_SENSITIVE_PATH_PARTS) if p.strip())
    # Where does the vault start? An Obsidian vault carries .obsidian/ at its root: segments at
    # or below that root are the note-taker's taxonomy (skipped quietly), segments above it are
    # where the vault happened to be mounted (refused). Without the marker, position alone
    # cannot tell the two apart, so everything above the folder named counts as "above".
    root = vault_root(target)
    above = target.parent.parts if root is None else root.parent.parts
    hit = [p for p in above if matching_part(p, parts) is not None]
    if not hit:
        return None
    hit_parts = {matching_part(h, parts) for h in hit}
    remaining = ",".join(p for p in parts if p not in hit_parts) or '""'
    return (
        f"REFUSED: the folder you named lives under '{hit[0]}', which is on the sensitive list, so nothing would be scanned. "
        f"A sensitive folder name above the vault says nothing about the notes inside it; one inside the vault does. "
        f"To scan: --include-sensitive, or --sensitive-paths {remaining} to drop '{hit[0]}' from the list."
    )


def near_misses(entries: list[PlanEntry], sensitive_parts: tuple[str, ...] | None = None) -> list[tuple[str, str]]:
    """Folders that will be scanned but contain a sensitive name inside a longer word.

    ``inboxes`` and ``myinbox`` do not match ``inbox``: the match is on whole words of the
    folder name, and a substring rule would have its own surprises. So the pre-flight names
    the near-miss instead of guessing. (``_Inbox`` and ``00 Inbox`` DO match since 0.4.1;
    they are listed among the skipped folders, not here.)
    """
    parts = tuple(p for p in (sensitive_parts if sensitive_parts is not None else DEFAULT_SENSITIVE_PATH_PARTS) if p.strip())
    seen: dict[str, str] = {}
    for entry in entries:
        if entry.status != "scan":
            continue
        for segment in entry.rel.split("/")[:-1]:
            low = segment.lower()
            for part in parts:
                if part.lower() in low and not segment_matches(segment, part) and segment not in seen:
                    seen[segment] = part
    return sorted(seen.items())
