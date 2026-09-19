"""Role and capability model for cptr.

Two orthogonal axes:

* **Tier** (`users.role`) — `superadmin` > `admin` > `user` > `pending`.
  Only the tier controls who may administer *other* accounts.
* **Capabilities** (boolean columns on `users`) — independent grants that say
  what a non-admin account may reach. Admins and superadmins hold every
  capability implicitly; they are never stored as explicit grants.

Capabilities are resolved from the database on every request (behind a short
TTL cache) rather than being baked into the JWT, so a revocation takes effect
within seconds instead of waiting out a 30-day session.
"""

from __future__ import annotations

import time

# ── Tiers ─────────────────────────────────────────────────────────

ROLE_SUPERADMIN = "superadmin"
ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLE_PENDING = "pending"

ASSIGNABLE_ROLES = (ROLE_SUPERADMIN, ROLE_ADMIN, ROLE_USER, ROLE_PENDING)
ADMIN_ROLES = (ROLE_ADMIN, ROLE_SUPERADMIN)


def is_admin(role: str | None) -> bool:
    """True for admins and superadmins."""
    return role in ADMIN_ROLES


def is_superadmin(role: str | None) -> bool:
    return role == ROLE_SUPERADMIN


# ── Capabilities ──────────────────────────────────────────────────

CAP_TERMINAL = "terminal"
"""Interactive PTY sessions on the host shell."""

CAP_MACHINE = "machine"
"""Local machine reach: workspaces, files, git, browser control, shell tools."""

CAP_EXTERNAL = "external"
"""Remote MCP / external tool-server connectors."""

ALL_CAPABILITIES = (CAP_TERMINAL, CAP_MACHINE, CAP_EXTERNAL)

# Capability -> users table column
CAPABILITY_COLUMNS = {
    CAP_TERMINAL: "can_terminal",
    CAP_MACHINE: "can_machine",
    CAP_EXTERNAL: "can_external",
}


# ── HTTP surface gating ───────────────────────────────────────────

# Longest-prefix wins, so a more specific path can override its parent.
PATH_CAPABILITIES: tuple[tuple[str, str], ...] = (
    ("/api/terminal", CAP_TERMINAL),
    # Command sessions are `run_command` output streams owned by the agent,
    # not interactive host shells — machine reach is the right bar, and they
    # must not demand terminal elevation. Longest prefix wins, so this
    # deliberately overrides the line above.
    ("/api/terminal/sessions", CAP_MACHINE),
    ("/api/workspace", CAP_MACHINE),
    ("/api/git", CAP_MACHINE),
    ("/api/browser", CAP_MACHINE),
    ("/api/memory", CAP_MACHINE),
    ("/api/automations", CAP_MACHINE),
)
# Note: `/v1` (the OpenAI-compatible gateway) is absent on purpose. It bypasses
# the auth middleware and carries its own API keys, and it is a chat surface —
# which every approved account may use. What a gateway chat can *do* is decided
# where it matters, by filtering the tool list against the key owner's
# capabilities, so a barebones account driving `/v1` gets a chat and nothing
# that touches the machine. The key check only rejects unapproved accounts.
#
# `/api/files` is also absent: an upload is content the user already holds, and
# it lands in cptr's own storage rather than the host filesystem. Reading files
# *off* the machine goes through `/api/workspace`, which is gated.


def capability_for_path(path: str) -> str | None:
    """Capability required to reach `path`, or None if it is unrestricted."""
    best: str | None = None
    best_len = -1
    for prefix, cap in PATH_CAPABILITIES:
        if (path == prefix or path.startswith(prefix + "/")) and len(prefix) > best_len:
            best, best_len = cap, len(prefix)
    return best


# ── Tool surface gating ───────────────────────────────────────────

# Built-in tools that reach the local machine. `run_command` lives here rather
# than under CAP_TERMINAL: it is agent-driven execution inside a workspace,
# whereas CAP_TERMINAL guards the interactive host shell.
TOOL_CAPABILITIES: dict[str, str] = {
    # files
    "read_file": CAP_MACHINE,
    "list_directory": CAP_MACHINE,
    "search_files": CAP_MACHINE,
    "create_file": CAP_MACHINE,
    "display_file": CAP_MACHINE,
    "edit_file": CAP_MACHINE,
    "multi_edit_file": CAP_MACHINE,
    "write_file": CAP_MACHINE,
    # shell execution
    "run_command": CAP_MACHINE,
    "send_input": CAP_MACHINE,
    "check_task": CAP_MACHINE,
    "kill_task": CAP_MACHINE,
    # browser control
    "browser_navigate": CAP_MACHINE,
    "browser_snapshot": CAP_MACHINE,
    "browser_click": CAP_MACHINE,
    "browser_type": CAP_MACHINE,
    "browser_screenshot": CAP_MACHINE,
    "browser_evaluate": CAP_MACHINE,
    # persistent local state
    "update_memory": CAP_MACHINE,
    "manage_skill": CAP_MACHINE,
    "create_automation": CAP_MACHINE,
    "update_automation": CAP_MACHINE,
    "toggle_automation": CAP_MACHINE,
    "delete_automation": CAP_MACHINE,
}


def tool_allowed(name: str, caps: frozenset[str]) -> bool:
    """Whether a built-in tool is reachable with `caps`."""
    required = TOOL_CAPABILITIES.get(name)
    return required is None or required in caps


# ── Resolution ────────────────────────────────────────────────────

_CACHE_TTL = 5.0
_cache: dict[str, tuple[float, str, frozenset[str]]] = {}

ADMIN_CAPS = frozenset(ALL_CAPABILITIES)
NO_CAPS: frozenset[str] = frozenset()


def invalidate(user_id: str | None = None) -> None:
    """Drop cached grants so a permission change applies immediately."""
    if user_id is None:
        _cache.clear()
    else:
        _cache.pop(user_id, None)


async def resolve(user_id: str | None) -> tuple[str, frozenset[str]]:
    """Return `(role, capabilities)` for a user id.

    Unknown or pending accounts resolve to no capabilities. Failures are
    treated as "no capabilities" so that a database problem cannot
    accidentally widen access.
    """
    if not user_id:
        return ROLE_PENDING, NO_CAPS

    hit = _cache.get(user_id)
    now = time.monotonic()
    if hit and now - hit[0] < _CACHE_TTL:
        return hit[1], hit[2]

    try:
        from cptr.models import User

        user = await User.get_by_id(user_id)
    except Exception:
        return ROLE_PENDING, NO_CAPS

    if user is None:
        return ROLE_PENDING, NO_CAPS

    role = user.role or ROLE_USER
    if is_admin(role):
        caps = ADMIN_CAPS
    elif role == ROLE_PENDING:
        caps = NO_CAPS
    else:
        caps = frozenset(
            cap for cap, column in CAPABILITY_COLUMNS.items() if bool(getattr(user, column, False))
        )

    _cache[user_id] = (now, role, caps)
    return role, caps


async def has_capability(user_id: str | None, capability: str) -> bool:
    _, caps = await resolve(user_id)
    return capability in caps
