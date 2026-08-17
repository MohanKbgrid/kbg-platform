"""D2 — append-only. A value changes by SUPERSEDING, never by updating in place.

Applies to anything financial or evidentiary: a mapping, a price, a threshold that decides a
write-off, a credential. The reason is not tidiness — it is that "what was the rule when this
document was posted" must stay answerable. An `UPDATE` makes an audit trail into a table of
current values, which is not an audit trail.

The shape is always the same, so it lives here once:

    unchanged   the new value equals the current one -> no write at all
    created     nothing was active -> version 1
    superseded  the current row is closed (is_active=false, superseded_at/by) and a new row is
                inserted at version+1, pointing back via supersedes_id

Persistence is injected. This class owns the DECISION and the version arithmetic; your store owns
the SQL.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol


@dataclass(frozen=True)
class VersionedRecord:
    key: tuple
    value: Any
    version: int
    id: Any = None


@dataclass(frozen=True)
class WriteResult:
    action: str                     # unchanged | created | superseded
    version: int
    value: Any
    superseded: Optional[VersionedRecord] = None
    id: Any = None

    @property
    def wrote(self) -> bool:
        return self.action != "unchanged"


class VersionedStore(Protocol):
    def get_active(self, key: tuple) -> Optional[VersionedRecord]: ...
    def close(self, record: VersionedRecord, actor: str) -> None: ...
    def insert(self, key: tuple, value: Any, version: int,
               supersedes: Optional[VersionedRecord], actor: str,
               **extra: Any) -> Any: ...


class VersionedWriter:
    def __init__(self, store: VersionedStore) -> None:
        self.store = store

    def set(self, key: tuple, value: Any, *, actor: str,
            equals=None, **extra: Any) -> WriteResult:
        """Set `key` to `value`, superseding whatever is active.

        `equals` compares the current value to the new one. It is a parameter because equality is
        domain-specific — two prices equal at 2 decimal places, two configs equal ignoring a
        comment — and getting it wrong in either direction is costly: too strict writes a new
        version on every save and buries the real changes; too loose silently drops a real change.
        """
        if not actor:
            raise ValueError("actor is required: an unattributed change to a versioned value "
                             "defeats the point of versioning it")

        current = self.store.get_active(key)
        same = (equals or (lambda a, b: a == b))
        if current is not None and same(current.value, value):
            return WriteResult("unchanged", current.version, current.value, None, current.id)

        if current is None:
            new_id = self.store.insert(key, value, 1, None, actor, **extra)
            return WriteResult("created", 1, value, None, new_id)

        self.store.close(current, actor)
        version = current.version + 1
        new_id = self.store.insert(key, value, version, current, actor, **extra)
        return WriteResult("superseded", version, value, current, new_id)
