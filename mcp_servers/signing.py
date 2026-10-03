"""HMAC signing of tool responses (P1-L2 response integrity, H6).

Every tool stub signs the response it returns; the host's P1-L2 layer
verifies the signature before the response reaches an agent.  A response
altered anywhere between the tool and the host (a forged response, a
compromised transport) fails verification.  The key is the project's
shared secret (``MMA_SHARED_SECRET`` or ``configs/hmac_key.txt``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Optional

from config import BASE_DIR

SIGNED_FIELDS = ("status", "tool_id", "result", "payload_hash", "error")


def shared_key() -> str:
    key = os.environ.get("MMA_SHARED_SECRET", "")
    if not key:
        path = BASE_DIR / "configs" / "hmac_key.txt"
        if path.exists():
            key = path.read_text().strip()
    return key


def canonical(response: dict) -> bytes:
    body = {k: response.get(k) for k in SIGNED_FIELDS if k in response}
    return json.dumps(body, sort_keys=True, default=str, separators=(",", ":")).encode()


def sign(response: dict, key: Optional[str] = None) -> Optional[str]:
    key = shared_key() if key is None else key
    if not key:
        return None
    return hmac.new(key.encode(), canonical(response), hashlib.sha256).hexdigest()


def verify(response: Any, key: Optional[str] = None) -> tuple[bool, str]:
    """``(ok, reason)``.  Unsigned responses are accepted only when no key
    is configured (then nothing could have been signed)."""
    key = shared_key() if key is None else key
    if not key:
        return True, "P1_no_signing_key"
    if not isinstance(response, dict):
        return False, "P1_response_unsigned"
    sig = response.get("signature")
    if not sig:
        return False, "P1_response_unsigned"
    expected = sign(response, key)
    if not hmac.compare_digest(str(sig), str(expected)):
        return False, "P1_response_signature_invalid"
    return True, "P1_response_signature_ok"
