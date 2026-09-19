"""Short-lived TOTP elevation grants guarding host terminal access.

Holding the `terminal` capability is necessary but not sufficient: reaching a
PTY also requires a live elevation grant, obtained by re-entering a TOTP code.
A grant is per user account (not per session), so every terminal tab that
account has open shares one window.

The window is idle-based and refreshed by *any* traffic in either direction —
a long-running build that keeps printing output keeps the grant alive. Thirty
idle minutes expires it; attached sockets are then closed and the user must
re-enter a code. PTY processes are deliberately left running so an expiry
never destroys in-flight work.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# Idle window before a grant lapses.
ELEVATION_TTL = 30 * 60

# WebSocket close code the frontend maps to "prompt for a fresh TOTP code".
WS_ELEVATION_REQUIRED = 4003


@dataclass
class _Grant:
    user_id: str
    granted_at: float
    last_activity: float
    listeners: set = field(default_factory=set)


_grants: dict[str, _Grant] = {}


def grant(user_id: str) -> float:
    """Start (or restart) an elevation window. Returns the expiry timestamp."""
    now = time.time()
    existing = _grants.get(user_id)
    if existing is not None:
        existing.granted_at = now
        existing.last_activity = now
    else:
        _grants[user_id] = _Grant(user_id=user_id, granted_at=now, last_activity=now)
    return now + ELEVATION_TTL


def _live(user_id: str) -> _Grant | None:
    g = _grants.get(user_id)
    if g is None:
        return None
    if time.time() - g.last_activity >= ELEVATION_TTL:
        _grants.pop(user_id, None)
        return None
    return g


def is_elevated(user_id: str | None) -> bool:
    return bool(user_id) and _live(user_id) is not None


def expires_at(user_id: str | None) -> float | None:
    if not user_id:
        return None
    g = _live(user_id)
    return None if g is None else g.last_activity + ELEVATION_TTL


def touch(user_id: str | None) -> bool:
    """Record activity. Returns False when the grant has already lapsed."""
    if not user_id:
        return False
    g = _live(user_id)
    if g is None:
        return False
    g.last_activity = time.time()
    return True


def revoke(user_id: str | None) -> None:
    """Drop a grant — used on logout and on an explicit session kill."""
    if user_id:
        _grants.pop(user_id, None)


def register_listener(user_id: str, socket) -> None:
    g = _live(user_id)
    if g is not None:
        g.listeners.add(socket)


def unregister_listener(user_id: str, socket) -> None:
    g = _grants.get(user_id)
    if g is not None:
        g.listeners.discard(socket)


def expired_listeners() -> list[tuple[str, object]]:
    """Sockets belonging to grants that have just lapsed, so a sweeper can
    close them. Clearing the grant is left to the caller draining this list."""
    now = time.time()
    stale: list[tuple[str, object]] = []
    for user_id, g in list(_grants.items()):
        if now - g.last_activity >= ELEVATION_TTL:
            for socket in list(g.listeners):
                stale.append((user_id, socket))
            _grants.pop(user_id, None)
    return stale
