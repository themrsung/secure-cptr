"""TOTP enrolment and verification at the auth boundary.

`cptr.utils.totp` is pure RFC 6238 arithmetic over a plaintext secret. This
module is the layer that knows about the database: it encrypts secrets at
rest (Fernet, keyed by the server JWT secret, same scheme as stored API keys)
and enforces the single-use rule that stops a code being replayed inside its
own 30-second step.
"""

from __future__ import annotations

import time

from cptr.models import Auth
from cptr.utils import totp
from cptr.utils.config import _get_jwt_secret
from cptr.utils.crypto import decrypt_key, encrypt_key

ISSUER = "cptr"


def _encrypt(secret: str) -> str:
    return encrypt_key(secret, _get_jwt_secret())


def _decrypt(stored: str) -> str:
    return decrypt_key(stored, _get_jwt_secret())


async def begin_enrollment(user_id: str, username: str) -> dict:
    """Mint a fresh secret and return everything the client needs to enrol.

    The secret is stored unconfirmed: `totp_enabled` stays false until the
    user proves possession with a code, so a failed enrolment can never lock
    an account out of its own second factor.
    """
    secret = totp.generate_secret()
    await Auth.set_totp_secret(user_id, _encrypt(secret))
    uri = totp.provisioning_uri(secret, username, issuer=ISSUER)
    from cptr.utils.qr import svg

    return {
        "secret": secret,
        "uri": uri,
        "qr_svg": svg(uri),
    }


async def check_code(auth: Auth, code: str, *, confirming: bool = False) -> tuple[bool, str | None]:
    """Verify a code for an existing enrolment.

    Returns `(ok, error)`. Codes are single-use: the accepted step is recorded
    so the same digits presented twice inside one window are refused.
    """
    if not auth.totp_secret:
        return False, "two-factor authentication is not set up"

    try:
        secret = _decrypt(auth.totp_secret)
    except Exception:
        return False, "stored two-factor secret could not be read"

    now = time.time()
    if not totp.verify(secret, code, at=now):
        return False, "invalid code"

    step = int(now) // totp.PERIOD
    last = auth.totp_last_used_at or 0
    if not confirming and last and int(last) // totp.PERIOD >= step:
        return False, "that code was already used; wait for the next one"

    if confirming:
        await Auth.confirm_totp(auth.user_id, int(now))
    else:
        await Auth.record_totp_use(auth.user_id, int(now))
    return True, None


def needs_enrollment(auth: Auth) -> bool:
    """True when the next login must (re-)enrol a second factor."""
    return bool(auth.totp_reset_required) or not auth.totp_enabled or not auth.totp_secret
