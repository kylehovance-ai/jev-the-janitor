"""One pass over the vault, before any request. Everything local hangs off it.

The index is built once and reused for duplicate detection, local triage, sibling titles,
graph facts and payload sizing. Until 0.2.1 each of those was its own walk: the sibling
list re-globbed the folder per note, duplicates were hashed in a side dict, and nothing
counted links at all, so a flat folder was slow before the first request and the graph
was invisible.

What the index reads is exactly what the plan says is scanned. A note on a sensitive or
hidden path, or under ``_janitor/``, is stat'ed for its size and never opened; its
in-degree is still counted from links in scanned notes, with the target name kept local.
Nothing here leaves the machine; ``scan.build_state`` chooses what does.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from janitor.frontmatter import Note, load_note, rank_by_overlap
from janitor.plan import PlanEntry, plan_vault, rel_folder
from janitor.policy import HIGH_PRECISION_SECRETS
from janitor.redact import redact

# [[target]], [[target|alias]], [[target#heading]], ![[embed]]. Group 1 is the ! for embeds.
WIKILINK = re.compile(r"(!?)\[\[([^\]|#]+)(?:#[^\]|]*)?(?:\|[^\]]*)?\]\]")
# [text](path.md) and [text](path.md#heading); external URLs are not links between notes.
MDLINK = re.compile(r"(!?)\[[^\]]*\]\(([^)\s]+?\.md)(?:#[^)]*)?\)")
HEADING = re.compile(r"^#{1,6}\s+\S", re.M)
WORD = re.compile(r"\S+")
TOKEN = re.compile(r"[a-z0-9]+")
MAX_TITLE_CHARS = 80  # a sibling title is context, not content; 80 characters is a title, 800 is a paragraph


def _tokens(text: str) -> set[str]:
    return {t for t in TOKEN.findall(text.lower()) if len(t) > 1}

MOC_MIN_LINKS = 8  # a map of content links a lot and says little else
MOC_WORDS_PER_LINK = 20
ORPHAN_MIN_AGE_DAYS = 30  # a note nobody links to is only an orphan once it has had time to be linked
# The facts are part of the hashed state, so they must not move under edits Jev cannot see
# or under the calendar. Words are sent to two significant figures (1,506 -> 1,500), so an
# edit below the excerpt cap keeps the cache key; age is sent as the largest band it has
# reached, so a key does not change at midnight.
AGE_BANDS = (0, 1, 7, 30, 90, 365, 1000)
SPARSE_GRAPH_SHARE = 0.05  # below this share of notes linking out, in-degree and is_orphan are noise, not findings


def banded_words(n: int) -> int:
    if n < 100:
        return n
    magnitude = 10 ** (len(str(n)) - 2)
    return (n // magnitude) * magnitude


def banded_age(days: int | None) -> int | None:
    if days is None:
        return None
    return max(b for b in AGE_BANDS if b <= days)


@dataclass
class IndexedNote:
    rel: str
    path: Path
    entry: PlanEntry
    note: Note | None = None  # loaded only when the plan says scan
    error: BaseException | None = None  # a read failure (permissions, I/O); an error row, retried on --resume
    undecodable: str | None = None  # not valid UTF-8: a finding about the vault, never sent, never retried
    size: int = 0  # bytes on disk, from stat, for every entry
    mtime: float = 0.0
    digest: str = ""  # body digest, scanned notes only
    words: int = 0
    headings: int = 0
    empty: bool = False  # body is empty or is only headings
    links_out: list[str] = field(default_factory=list)  # resolved vault-relative targets, duplicates kept
    unresolved: int = 0  # link targets that match no note in the plan
    embeds: int = 0
    in_links: int = 0
    aliases: list[str] = field(default_factory=list)  # raw frontmatter aliases; redacted before any use
    locked: bool = False  # janitor.locked: true in frontmatter
    title_credential: bool = False  # the title itself holds a credential format: never a sibling title
    age_days: int | None = None  # creation age: frontmatter created/date if parseable, else mtime
    age_source: str | None = None  # "frontmatter" | "mtime" | None. mtime-derived age resets on clone, restore or sync

    @property
    def folder(self) -> str:
        return rel_folder(self.rel)


@dataclass
class VaultIndex:
    root: Path
    plan: list[PlanEntry]
    notes: dict[str, IndexedNote]  # every plan entry, in plan order
    by_digest: dict[str, list[str]] = field(default_factory=dict)  # scanned notes only; first rel is canonical
    by_folder: dict[str, list[str]] = field(default_factory=dict)  # sibling pool: scanned, not sensitive, title holds no credential
    single_file: bool = False  # the target was one note; in-degree is unknown, not zero

    def exact_duplicate_of(self, rel: str) -> str | None:
        item = self.notes[rel]
        if not item.digest:
            return None
        first = self.by_digest[item.digest][0]
        return None if first == rel else first

    def sibling_titles(self, rel: str, cap: int, own_title: str | None = None) -> list[str]:
        """Titles of the other scanned, non-sensitive notes in ``rel``'s folder, the closest first.

        Sibling titles are the quadratic term of the bill and the duplicate question's only
        context. Until 0.3.1 the first ``cap`` in plan order (alphabetical) were sent, so in a
        folder of 2,000 notes a near-duplicate of "Zoning appeal" was never listed. Now the
        candidates are ranked by token overlap with the note's own title (ties keep plan
        order) and the ``cap`` closest are returned, whole: build_state redacts each and
        only then cuts it to MAX_TITLE_CHARS. (Through 0.4.6 the cut happened here, before
        redaction, so a name or key straddling character 80 left as a fragment.)
        """
        candidates = []
        for other in self.by_folder.get(rel_folder(rel), []):
            if other == rel:
                continue
            note = self.notes[other].note
            if note is not None:
                candidates.append(note.title)
        return rank_by_overlap(own_title, candidates, cap)

    @property
    def linking_share(self) -> float:
        """The share of scanned notes with at least one outgoing link. Near zero means the vault does not use links."""
        scanned = [n for n in self.notes.values() if n.note is not None]
        if not scanned:
            return 0.0
        return sum(1 for n in scanned if n.links_out or n.unresolved) / len(scanned)

    @property
    def graph_sparse(self) -> bool:
        """True when so few notes link out that in-degree says nothing.

        The first live run scanned 31 real notes that reference each other by path, not by
        [[wikilink]]: 30 had no outgoing link, so nothing linked to anything and 17 came back
        is_orphan: true. Arithmetically correct, and it said nothing. Below this share the
        orphan fact is reported as unknown rather than as a number that looks like a finding.
        A subfolder scan makes it worse, since inbound links from the rest of the vault are
        invisible by construction, and that is stated too.
        """
        return self.linking_share < SPARSE_GRAPH_SHARE

    def facts(self, rel: str) -> dict[str, Any]:
        """Graph facts as numbers. Counts leave the machine; names of link targets do not."""
        item = self.notes[rel]
        out_links = len(item.links_out) + item.unresolved
        in_links: int | None = None if self.single_file else item.in_links
        is_moc = out_links >= MOC_MIN_LINKS and item.words <= out_links * MOC_WORDS_PER_LINK
        is_orphan: bool | None
        if in_links is None or self.graph_sparse:
            is_orphan = None
        else:
            is_orphan = in_links == 0 and (item.age_days is None or item.age_days >= ORPHAN_MIN_AGE_DAYS)
        return {
            "words": banded_words(item.words),
            "headings": item.headings,
            "age_days": banded_age(item.age_days),
            "out_links": out_links,
            "in_links": in_links,
            "embeds": item.embeds,
            "unresolved_links": item.unresolved,
            "is_moc": is_moc,
            "is_orphan": is_orphan,
        }


def body_digest(body: str) -> str:
    """Hash of the body content, ignoring a leading H1 heading, line-ending style and outer whitespace.

    The heading is the title, which is compared separately. Two notes that say the same
    thing under different dated headings are exact duplicates of content.
    """
    import hashlib

    text = body.replace("\r\n", "\n").strip()
    if text.startswith("# "):
        text = text.split("\n", 1)[1] if "\n" in text else ""
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:16]


def is_empty_body(body: str) -> bool:
    """Nothing, or nothing but headings."""
    for line in body.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            return False
    return True


def parse_links(body: str) -> tuple[list[str], int]:
    """Return (link targets as written, embed count). Targets keep their path but lose .md and anchors."""
    targets: list[str] = []
    embeds = 0
    for pat in (WIKILINK, MDLINK):
        for m in pat.finditer(body):
            if m.group(1):
                embeds += 1
            t = m.group(2).strip().replace("\\", "/")
            if t.lower().endswith(".md"):
                t = t[:-3]
            elif "." in t.rsplit("/", 1)[-1]:
                continue  # an image, PDF or other asset: an embed, not a link between notes
            if t:
                targets.append(t)
    return targets, embeds


CREATION_KEYS = ("created", "date", "created_at", "creation_date")
# The date the janitor's own stamp records for a note whose frontmatter has no creation date:
# the file's mtime as it was before the first stamp. A stamp is a write, so it moves the mtime
# to now; without this record an undated note's sent age fell from its real band to 0 on the
# scan after an --apply, its cache key changed, and --resume re-sent it (through 0.5.1).
STAMP_DATE_KEY = "created_from_mtime"


def creation_date(meta: dict) -> date | None:
    """The earliest parseable creation date in the frontmatter's own keys, or None."""
    stamps = [d for d in (_as_date(meta.get(key)) for key in CREATION_KEYS) if d is not None]
    return min(stamps) if stamps else None


def stamp_date(meta: dict) -> date | None:
    """The date the janitor block recorded from the file's mtime at its first stamp, or None."""
    janitor = meta.get("janitor")
    return _as_date(janitor.get(STAMP_DATE_KEY)) if isinstance(janitor, dict) else None


def age_source(meta: dict) -> str:
    """Where the age comes from: "frontmatter" when a creation key parses, "stamp" when only the
    janitor block's recorded mtime date does, else "mtime" (which resets when the vault is copied)."""
    if creation_date(meta) is not None:
        return "frontmatter"
    return "stamp" if stamp_date(meta) is not None else "mtime"


def note_age_days(meta: dict, mtime: float, today: date | None = None) -> int | None:
    """CREATION age: days since the earliest parseable ``created``/``date`` in the frontmatter,
    falling back to the file's mtime only when neither parses.

    Age and staleness are different questions. Through 0.3.0 this took the newest of
    created, date, modified, updated AND mtime, which measures when a note was last
    touched: a note written in 2023 and edited yesterday came back as age 0, and because
    mtime always joined the list, every note in a freshly cloned, restored or synced vault
    read 0 and ``is_orphan`` could never fire there. ORPHAN_MIN_AGE_DAYS is a statement
    about how long a note has existed, so this is the age it needs. ``modified`` and
    ``updated`` no longer feed it.
    """
    today = today or datetime.now(timezone.utc).date()
    start = creation_date(meta)
    if start is None:
        start = stamp_date(meta)  # the mtime the janitor recorded before its own write moved it
    if start is None:
        try:
            start = datetime.fromtimestamp(mtime, tz=timezone.utc).date()
        except (OverflowError, OSError, ValueError):
            return None
    return max(0, (today - start).days)


def _as_date(val: Any) -> date | None:
    if isinstance(val, datetime):
        return val.date()
    if isinstance(val, date):
        return val
    if isinstance(val, str) and len(val) >= 10:
        try:
            return date.fromisoformat(val[:10])
        except ValueError:
            return None
    return None


def _aliases(meta: dict) -> list[str]:
    raw = meta.get("aliases", meta.get("alias"))
    if isinstance(raw, str):
        return [raw.strip()] if raw.strip() else []
    if isinstance(raw, list):
        return [str(a).strip() for a in raw if str(a).strip()]
    return []


def build_index(
    vault: Path,
    *,
    include_sensitive: bool = False,
    sensitive_parts: tuple[str, ...] | None = None,
    today: date | None = None,
) -> VaultIndex:
    """Plan, then read each scanned note exactly once."""
    target = vault.resolve()
    root, plan = plan_vault(vault, include_sensitive=include_sensitive, sensitive_parts=sensitive_parts)
    index = VaultIndex(root=root, plan=plan, notes={}, single_file=target.is_file())
    stems: dict[str, list[str]] = {}
    for entry in plan:
        path = root / entry.rel
        item = IndexedNote(rel=entry.rel, path=path, entry=entry)
        try:
            st = path.stat()
            item.size, item.mtime = st.st_size, st.st_mtime
        except OSError:
            pass
        index.notes[entry.rel] = item
        stem = entry.rel[:-3] if entry.rel.lower().endswith(".md") else entry.rel
        stems.setdefault(stem.rsplit("/", 1)[-1].lower(), []).append(stem)
        if entry.status != "scan":
            continue
        try:
            note = load_note(path)
        except UnicodeDecodeError as exc:
            item.undecodable = f"not valid UTF-8 at byte {exc.start}: {exc.reason}"
            continue
        except Exception as exc:  # noqa: BLE001 - recorded, never sent
            item.error = exc
            continue
        item.note = note
        item.digest = body_digest(note.body)
        index.by_digest.setdefault(item.digest, []).append(entry.rel)
        # A note whose own title carries a credential format is quarantined on its own hit and
        # is never listed as a sibling, the way a sensitive note is not: its title would go out
        # as `[KEY]` in every neighbour's list, which is a token, but there is nothing to gain
        # from listing it and a boundary miss would leak it n times.
        item.title_credential = any(h in HIGH_PRECISION_SECRETS for h in redact(note.title).hits)
        if not entry.sensitive and not item.title_credential:
            index.by_folder.setdefault(item.folder, []).append(entry.rel)
        body = note.body
        item.words = len(WORD.findall(body))
        item.headings = len(HEADING.findall(body))
        item.empty = is_empty_body(body)
        item.aliases = _aliases(note.existing)
        janitor_meta = note.existing.get("janitor")
        item.locked = bool(isinstance(janitor_meta, dict) and janitor_meta.get("locked") is True)
        item.age_days = note_age_days(note.existing, item.mtime, today)
        item.age_source = age_source(note.existing) if item.age_days is not None else None
        raw_targets, item.embeds = parse_links(body)
        item.links_out = raw_targets  # resolved below, once every stem is known

    in_degree: Counter[str] = Counter()
    for item in index.notes.values():
        if item.note is None:
            continue
        resolved: list[str] = []
        for raw in item.links_out:
            rel = _resolve(raw, stems)
            if rel is None:
                item.unresolved += 1
            else:
                resolved.append(rel)
                if rel != item.rel:
                    in_degree[rel] += 1
        item.links_out = resolved
    for rel, n in in_degree.items():
        index.notes[rel].in_links = n
    return index


def _resolve(raw: str, stems: dict[str, list[str]]) -> str | None:
    """Obsidian resolution: by basename, and a path-like target must match the tail of the rel."""
    raw = raw.strip("/")
    base = raw.rsplit("/", 1)[-1].lower()
    candidates = stems.get(base)
    if not candidates:
        return None
    if "/" in raw:
        tail = raw.lower()
        for c in candidates:
            if c.lower() == tail or c.lower().endswith("/" + tail):
                return c + ".md"
        return None
    return candidates[0] + ".md"
