"""RFC 6238 TOTP (time-based one-time passwords) with zero extra dependencies.

Secrets are stored encrypted at rest (Fernet, keyed off the server JWT secret)
via `cptr.utils.crypto`. This module deals only with plaintext secrets; the
callers in `cptr.routers.auth` handle encrypt/decrypt at the DB boundary.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
PERIOD = 30
# Accept the previous / next window to tolerate clock drift between the
# server and the authenticator app (±30 s).
DRIFT_WINDOWS = 1

ISSUER = "cptr"


def generate_secret() -> str:
    """Generate a fresh base32 TOTP secret (160 bits, as recommended by RFC 4226)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    """Compute the HOTP value for a counter (RFC 4226)."""
    padding = "=" * (-len(secret) % 8)
    try:
        key = base64.b32decode(secret.upper() + padding, casefold=True)
    except Exception as exc:  # malformed secret in DB
        raise ValueError("invalid TOTP secret") from exc
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**DIGITS)).zfill(DIGITS)


def now_code(secret: str, at: float | None = None) -> str:
    """Current TOTP code. Exposed for `cptr recovery` / tests."""
    return _hotp(secret, int((at if at is not None else time.time()) // PERIOD))


def verify(secret: str, code: str, at: float | None = None) -> bool:
    """Constant-time verification of a 6-digit code across the drift window."""
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "").replace("-", "")
    if len(code) != DIGITS or not code.isdigit():
        return False
    counter = int((at if at is not None else time.time()) // PERIOD)
    ok = False
    for skew in range(-DRIFT_WINDOWS, DRIFT_WINDOWS + 1):
        # No early break: compare every window so timing does not leak which
        # one matched.
        ok |= hmac.compare_digest(_hotp(secret, counter + skew), code)
    return ok


def provisioning_uri(secret: str, username: str, issuer: str = ISSUER) -> str:
    """otpauth:// URI for QR codes and manual entry."""
    label = quote(f"{issuer}:{username}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )
