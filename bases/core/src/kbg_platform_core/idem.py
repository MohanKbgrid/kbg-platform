"""D3 — idempotency by SOURCE id, not by server id.

The client (a device, an external system) mints the id and it BECOMES the primary key. A re-sent
capture then collides instead of duplicating: double-insert is impossible by construction rather
than by a de-dup pass someone has to remember to run.

This matters most where the network is worst. A field app that flushes its queue three times on a
bad connection must produce one row, and it must do so without the server keeping a seen-set.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional


def capture_id(client_supplied: Optional[Any] = None) -> uuid.UUID:
    """The id a capture will be stored under.

    Prefers the client's. Mints one only when there genuinely is no client (a server-side job),
    and NEVER silently replaces a malformed client id — a client sending something unparseable is
    a bug to surface, not to paper over, because the retry that follows will duplicate.
    """
    if client_supplied is None:
        return uuid.uuid4()
    if isinstance(client_supplied, uuid.UUID):
        return client_supplied
    try:
        return uuid.UUID(str(client_supplied))
    except (ValueError, AttributeError, TypeError) as e:
        raise ValueError(
            f"client-supplied capture id {client_supplied!r} is not a uuid. Refusing to mint a "
            f"replacement: the client will retry with the same bad id and create a duplicate. "
            f"Fix the client."
        ) from e


def is_client_minted(client_supplied: Optional[Any]) -> bool:
    return client_supplied is not None
