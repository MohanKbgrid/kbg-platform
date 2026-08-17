"""kbg-platform-core — the domain-free primitives that enforce the KBG Platform Surfaces canon.

Read `docs/canon/README.md` first. This package does not replace the specs; it makes six of their
doctrines hard to violate by accident. Everything else is yours to build against the contract.
"""
from .authority import Authority, Decision, PermissionDenied
from .idem import capture_id, is_client_minted
from .outbox import Mode, Outbox, OutboxRow, OutboxStore, State
from .result import Gap, GapError, Outcome, Resolved, all_resolved, gaps
from .versioned import VersionedRecord, VersionedStore, VersionedWriter, WriteResult

__version__ = "0.1.0"
__all__ = [
    "Authority", "Decision", "PermissionDenied",
    "Gap", "GapError", "Outcome", "Resolved", "all_resolved", "gaps",
    "Mode", "Outbox", "OutboxRow", "OutboxStore", "State",
    "VersionedRecord", "VersionedStore", "VersionedWriter", "WriteResult",
    "capture_id", "is_client_minted",
]
