# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""RS256 signatures (RSASSA-PKCS1-v1_5 with SHA-256) checked with the standard library only. Used for single
sign-on ID tokens and for licences."""
from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any

_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def rs256_verify(jwk: dict[str, Any], signing_input: bytes, sig: bytes) -> bool:
    """True when ``sig`` is a valid RS256 signature of ``signing_input`` by this RSA public key (2048 bits+)."""
    try:
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    except (KeyError, ValueError, TypeError):
        return False
    size = (n.bit_length() + 7) // 8
    if len(sig) != size or size < 256:
        return False
    digest = hashlib.sha256(signing_input).digest()
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(size, "big")
    expected = b"\x00\x01" + b"\xff" * (size - 3 - 19 - 32) + b"\x00" + _SHA256_PREFIX + digest
    return secrets.compare_digest(em, expected)
