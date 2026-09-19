"""Security regression tests for TOTP, capabilities, roles and elevation.

Stdlib only, and runnable two ways so the absence of a test runner in this
repo is not an excuse to skip them:

    python3 tests/test_security.py     # standalone
    pytest tests/test_security.py      # if pytest happens to be installed
"""

from __future__ import annotations

import base64
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Point the app at a scratch data dir before anything reads cptr.env.
_TMP = tempfile.mkdtemp(prefix="cptr_tests_")
os.environ["CPTR_DATA_DIR"] = _TMP

from cptr.utils import qr, totp  # noqa: E402
from cptr.utils.elevation import (  # noqa: E402
    ELEVATION_TTL,
    _grants,
    expires_at,
    grant,
    is_elevated,
    revoke,
    touch,
)
from cptr.utils.permissions import (  # noqa: E402
    ADMIN_CAPS,
    CAP_MACHINE,
    CAP_TERMINAL,
    ROLE_ADMIN,
    ROLE_PENDING,
    ROLE_SUPERADMIN,
    ROLE_USER,
    capability_for_path,
    is_admin,
    is_superadmin,
    tool_allowed,
)


class TotpVectors(unittest.TestCase):
    """RFC 4226 / 6238 published test vectors."""

    SECRET = base64.b32encode(b"12345678901234567890").decode()

    def test_hotp_rfc4226(self):
        expected = [
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        ]  # fmt: skip
        self.assertEqual([totp._hotp(self.SECRET, c) for c in range(10)], expected)

    def test_totp_rfc6238(self):
        for t, code in {
            59: "287082",
            1111111109: "081804",
            1111111111: "050471",
            1234567890: "005924",
            2000000000: "279037",
            20000000000: "353130",
        }.items():
            self.assertEqual(totp.now_code(self.SECRET, at=t), code, f"T={t}")

    def test_drift_window_accepts_one_step_either_side(self):
        now = 1_700_000_000
        for offset in (-30, 0, 30):
            self.assertTrue(totp.verify(self.SECRET, totp.now_code(self.SECRET, at=now + offset), at=now))

    def test_drift_window_rejects_two_steps_out(self):
        now = 1_700_000_000
        for offset in (-90, 90):
            self.assertFalse(
                totp.verify(self.SECRET, totp.now_code(self.SECRET, at=now + offset), at=now)
            )

    def test_malformed_codes_are_rejected(self):
        for bad in ("", "12345", "1234567", "abcdef", None, "  "):
            self.assertFalse(totp.verify(self.SECRET, bad))  # type: ignore[arg-type]

    def test_secret_is_160_bits_of_base32(self):
        secret = totp.generate_secret()
        self.assertEqual(len(secret), 32)
        base64.b32decode(secret + "=" * (-len(secret) % 8))

    def test_provisioning_uri_escapes_the_label(self):
        uri = totp.provisioning_uri("ABC", "user name/with:chars")
        self.assertIn("otpauth://totp/", uri)
        self.assertNotIn(" ", uri)
        self.assertIn("secret=ABC", uri)


class QrEncoder(unittest.TestCase):
    """Golden matrices, captured when the encoder was verified module-for-module
    against the reference `qrcode` library (181/181 inputs matched exactly)."""

    GOLDEN = [
        ("hi", 21, "69f439bee9c38226"),
        (
            "otpauth://totp/cptr%3Aalice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
            "&issuer=cptr&algorithm=SHA1&digits=6&period=30",
            45,
            "88576b34d04fa272",
        ),
        ("a" * 106, 41, "d3b1a20558fa8324"),
        ("a" * 213, 57, "c463831103cf2588"),
    ]

    def _digest(self, grid):
        import hashlib

        flat = "".join("".join(map(str, row)) for row in grid)
        return hashlib.sha256(flat.encode()).hexdigest()[:16]

    def test_golden_matrices(self):
        for data, size, digest in self.GOLDEN:
            grid = qr.encode(data)
            self.assertEqual(len(grid), size, data[:24])
            self.assertEqual(self._digest(grid), digest, data[:24])

    def test_structure_finder_patterns_and_quiet_zone(self):
        grid = qr.encode("structure check")
        size = len(grid)
        # Finder patterns: dark ring, light ring, dark 3x3 core.
        for top, left in ((0, 0), (0, size - 7), (size - 7, 0)):
            self.assertEqual(grid[top][left], 1)
            self.assertEqual(grid[top + 1][left + 1], 0)
            self.assertEqual(grid[top + 3][left + 3], 1)
        # Dark module is fixed by the spec.
        self.assertEqual(grid[size - 8][8], 1)

    def test_version_grows_with_payload(self):
        self.assertLess(len(qr.encode("short")), len(qr.encode("x" * 200)))

    def test_rejects_oversized_payload(self):
        with self.assertRaises(ValueError):
            qr.encode("x" * 400)

    def test_svg_is_wellformed_and_theme_aware(self):
        svg = qr.svg("otpauth://totp/x?secret=AAAA")
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.rstrip().endswith("</svg>"))
        # Dark modules inherit text colour; the plate stays white for scanners.
        self.assertIn("currentColor", svg)
        self.assertIn('fill="#fff"', svg)


class PathGating(unittest.TestCase):
    def test_terminal_paths_require_terminal(self):
        for path in ("/api/terminal", "/api/terminal/abc", "/api/terminal/abc/ws"):
            self.assertEqual(capability_for_path(path), CAP_TERMINAL, path)

    def test_command_sessions_override_to_machine(self):
        # Longest prefix wins: agent output streams are not host shells.
        for path in ("/api/terminal/sessions", "/api/terminal/sessions/x/ws"):
            self.assertEqual(capability_for_path(path), CAP_MACHINE, path)

    def test_machine_paths(self):
        for path in (
            "/api/workspace/files",
            "/api/git/status",
            "/api/browser/sessions",
            "/api/memory",
            "/api/automations/7",
        ):
            self.assertEqual(capability_for_path(path), CAP_MACHINE, path)

    def test_chat_surface_is_ungated(self):
        for path in ("/api/chats", "/api/auth", "/api/files/abc", "/v1/chat/completions"):
            self.assertIsNone(capability_for_path(path), path)

    def test_prefix_match_is_not_substring_match(self):
        # /api/gitlab must not inherit /api/git's gate by accident.
        self.assertIsNone(capability_for_path("/api/gitlab"))
        self.assertIsNone(capability_for_path("/api/terminals"))


class ToolGating(unittest.TestCase):
    def test_barebones_account_gets_chat_tools_only(self):
        none: frozenset[str] = frozenset()
        for allowed in ("web_search", "read_url", "search_chats", "update_tasks", "notify"):
            self.assertTrue(tool_allowed(allowed, none), allowed)
        for denied in (
            "run_command", "read_file", "write_file", "edit_file",
            "browser_navigate", "update_memory", "create_automation",
        ):  # fmt: skip
            self.assertFalse(tool_allowed(denied, none), denied)

    def test_machine_capability_unlocks_shell_and_files(self):
        caps = frozenset({CAP_MACHINE})
        for name in ("run_command", "read_file", "browser_navigate", "update_memory"):
            self.assertTrue(tool_allowed(name, caps), name)

    def test_terminal_capability_does_not_imply_machine_tools(self):
        # CAP_TERMINAL guards the interactive PTY, not agent-driven execution.
        caps = frozenset({CAP_TERMINAL})
        self.assertFalse(tool_allowed("run_command", caps))
        self.assertFalse(tool_allowed("read_file", caps))

    def test_admins_hold_everything(self):
        for name in ("run_command", "read_file", "browser_evaluate", "delete_automation"):
            self.assertTrue(tool_allowed(name, ADMIN_CAPS), name)


class RoleHelpers(unittest.TestCase):
    def test_superadmin_is_an_admin(self):
        self.assertTrue(is_admin(ROLE_SUPERADMIN))
        self.assertTrue(is_admin(ROLE_ADMIN))
        self.assertTrue(is_superadmin(ROLE_SUPERADMIN))
        self.assertFalse(is_superadmin(ROLE_ADMIN))

    def test_plain_and_pending_are_not_admins(self):
        for role in (ROLE_USER, ROLE_PENDING, None, "", "Admin", "ADMIN"):
            self.assertFalse(is_admin(role), repr(role))


class Elevation(unittest.TestCase):
    def setUp(self):
        _grants.clear()

    def test_not_elevated_by_default(self):
        self.assertFalse(is_elevated("u1"))
        self.assertFalse(is_elevated(None))

    def test_grant_then_elevated(self):
        grant("u1")
        self.assertTrue(is_elevated("u1"))
        self.assertFalse(is_elevated("u2"))

    def test_grant_is_per_account_not_per_session(self):
        grant("u1")
        self.assertTrue(is_elevated("u1"))
        # A second tab for the same account shares the one window.
        self.assertAlmostEqual(expires_at("u1") or 0, time.time() + ELEVATION_TTL, delta=2)

    def test_idle_expiry(self):
        grant("u1")
        _grants["u1"].last_activity = time.time() - ELEVATION_TTL - 1
        self.assertFalse(is_elevated("u1"))
        self.assertFalse(touch("u1"))

    def test_activity_refreshes_the_window(self):
        grant("u1")
        _grants["u1"].last_activity = time.time() - ELEVATION_TTL + 5
        self.assertTrue(touch("u1"))
        self.assertAlmostEqual(expires_at("u1") or 0, time.time() + ELEVATION_TTL, delta=2)

    def test_touch_after_expiry_does_not_resurrect(self):
        grant("u1")
        _grants["u1"].last_activity = time.time() - ELEVATION_TTL - 1
        self.assertFalse(touch("u1"))
        self.assertFalse(is_elevated("u1"))

    def test_revoke_is_immediate(self):
        grant("u1")
        revoke("u1")
        self.assertFalse(is_elevated("u1"))


class Tickets(unittest.TestCase):
    """A half-finished login must never be usable as a session."""

    def test_ticket_is_not_accepted_as_a_session(self):
        from cptr.utils.config import create_ticket, verify_token

        ticket = create_ticket("u1", "alice", "totp-login")
        self.assertIsNone(verify_token(ticket))

    def test_session_token_verifies(self):
        from cptr.utils.config import create_token, verify_token

        result = verify_token(create_token("u1", "alice", role=ROLE_ADMIN))
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.user_id, "u1")
        self.assertEqual(result.role, ROLE_ADMIN)

    def test_ticket_purpose_is_not_interchangeable(self):
        from cptr.utils.config import create_ticket, verify_ticket

        ticket = create_ticket("u1", "alice", "totp-enroll")
        self.assertIsNone(verify_ticket(ticket, "totp-login"))
        self.assertIsNotNone(verify_ticket(ticket, "totp-enroll"))

    def test_garbage_tickets_are_rejected(self):
        from cptr.utils.config import verify_ticket

        for bad in (None, "", "not.a.jwt", "a.b.c"):
            self.assertIsNone(verify_ticket(bad, "totp-login"))

    def test_legacy_tokens_without_typ_still_work(self):
        # Adding `typ` must not log out everyone holding an older cookie.
        import jwt as pyjwt

        from cptr.utils.config import _get_jwt_secret, verify_token

        legacy = pyjwt.encode(
            {"sub": "u1", "username": "alice", "role": "user", "exp": time.time() + 600},
            _get_jwt_secret(),
            algorithm="HS256",
        )
        self.assertIsNotNone(verify_token(legacy))


if __name__ == "__main__":
    unittest.main(verbosity=2)
