"""Regression tests for the credential-exfiltration audit.

Each test pins a specific finding so it cannot silently come back.

    python3 tests/test_exfiltration.py    # standalone
    pytest tests/test_exfiltration.py     # if pytest is installed
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_TMP = tempfile.mkdtemp(prefix="cptr_exfil_tests_")
os.environ["CPTR_DATA_DIR"] = _TMP


class TestAuditRedaction(unittest.TestCase):
    """Finding 1: the audit log wrote credentials in clear text.

    Redaction matched key names exactly, so `password` was covered but
    `current_password`, `new_password`, `ticket` and `totp_secret` were not.
    """

    def _decode(self, payload: str) -> str:
        from cptr.utils.audit import _decode_body

        return _decode_body(bytearray(payload.encode())) or ""

    def test_password_change_body_is_redacted(self):
        body = json.dumps(
            {"current_password": "Summer2024!", "new_password": "Tr0ub4dor&3"}
        )
        out = self._decode(body)
        self.assertNotIn("Summer2024!", out)
        self.assertNotIn("Tr0ub4dor&3", out)

    def test_auth_ticket_and_totp_secret_are_redacted(self):
        out = self._decode(json.dumps({"ticket": "eyJhbGciOi.AAA.BBB", "totp_secret": "JBSWY3DP"}))
        self.assertNotIn("eyJhbGciOi.AAA.BBB", out)
        self.assertNotIn("JBSWY3DP", out)

    def test_provider_keys_are_redacted(self):
        out = self._decode(json.dumps({"config": {"web.tavily_api_key": "tvly-REAL-KEY"}}))
        self.assertNotIn("tvly-REAL-KEY", out)

    def test_truncated_json_still_redacted(self):
        # Bodies are cut at max_body_size, so JSON parsing fails and the
        # regex fallback has to hold.
        out = self._decode('{"password":"hunter2-unterminated')
        self.assertNotIn("hunter2", out)

    def test_form_encoded_body_is_redacted(self):
        out = self._decode("current_password=hunter2&new_password=swordfish")
        self.assertNotIn("hunter2", out)
        self.assertNotIn("swordfish", out)

    def test_non_sensitive_fields_survive(self):
        # Redaction must not gut the log's usefulness.
        out = self._decode(json.dumps({"display_name": "Alice", "path": "/tmp/x"}))
        self.assertIn("Alice", out)
        self.assertIn("/tmp/x", out)


class TestDataDirPermissions(unittest.TestCase):
    """Finding 2: config.toml held the JWT secret at mode 0644.

    That secret is also the key every Fernet value is derived from, so a
    readable config.toml makes encryption-at-rest decorative.
    """

    def test_config_written_owner_only(self):
        from cptr.env import CONFIG_FILE
        from cptr.utils.config import save_config

        save_config({"server": {"secret": "s3cret-value"}})
        mode = stat.S_IMODE(os.stat(CONFIG_FILE).st_mode)
        self.assertEqual(mode & 0o077, 0, f"config.toml is group/world accessible: {oct(mode)}")

    def test_data_dir_owner_only(self):
        from cptr.env import DATA_DIR
        from cptr.utils.config import harden_data_dir

        harden_data_dir()
        mode = stat.S_IMODE(os.stat(DATA_DIR).st_mode)
        self.assertEqual(mode & 0o077, 0, f"data dir is group/world accessible: {oct(mode)}")


class TestTrustedHeaderFailsClosed(unittest.TestCase):
    """Finding 3: trusted-header mode trusted Remote-User with no allowlist.

    An empty `trusted_sources` meant "skip the IP check", so anyone who could
    reach the port could assert any identity via a header.
    """

    def test_remote_user_rejected_without_allowlist(self):
        from cptr.env import CONFIG_FILE
        from cptr.utils import config as cfg

        CONFIG_FILE.write_text('[auth]\nmode = "trusted_header"\n')
        cfg.invalidate_config_cache()
        try:
            result = cfg.check_access(
                client_host="203.0.113.9",
                jwt_token=None,
                remote_user_header="admin",
            )
            self.assertIsNone(result, "header identity accepted with no trusted_sources")
        finally:
            CONFIG_FILE.write_text("")
            cfg.invalidate_config_cache()

    def test_remote_user_rejected_from_untrusted_source(self):
        from cptr.env import CONFIG_FILE
        from cptr.utils import config as cfg

        CONFIG_FILE.write_text(
            '[auth]\nmode = "trusted_header"\ntrusted_sources = ["10.0.0.1"]\n'
        )
        cfg.invalidate_config_cache()
        try:
            self.assertIsNone(
                cfg.check_access("203.0.113.9", None, "admin"),
                "header identity accepted from a non-allowlisted source",
            )
        finally:
            CONFIG_FILE.write_text("")
            cfg.invalidate_config_cache()


class TestUploadCannotExecuteOnOrigin(unittest.TestCase):
    """Finding 4: /api/files/{id} is unauthenticated and echoed a caller-chosen
    content type inline, turning an upload into stored XSS on the app origin."""

    def test_active_types_are_forced_to_download(self):
        from cptr.routers.files import _safe_disposition

        for ctype in (
            "text/html",
            "image/svg+xml",
            "application/xhtml+xml",
            "text/javascript",
            "TEXT/HTML; charset=utf-8",
        ):
            resolved, disposition = _safe_disposition(ctype)
            self.assertEqual(disposition, "attachment", f"{ctype} served inline")
            self.assertEqual(resolved, "application/octet-stream", f"{ctype} kept renderable type")

    def test_benign_types_still_render_inline(self):
        from cptr.routers.files import _safe_disposition

        for ctype in ("image/png", "application/pdf", "text/plain"):
            resolved, disposition = _safe_disposition(ctype)
            self.assertEqual(disposition, "inline")
            self.assertEqual(resolved, ctype)

    def test_filename_cannot_inject_headers(self):
        from cptr.routers.files import _safe_filename

        out = _safe_filename('evil"; x=1\r\nSet-Cookie: a=b')
        for bad in ('"', "\r", "\n"):
            self.assertNotIn(bad, out)


class TestSecretConfigKeysAreEncrypted(unittest.TestCase):
    """Finding 5: only four audio/image keys were encrypted before storage, so
    web-search and browser provider keys were persisted in clear text."""

    def test_provider_keys_are_recognized_as_secret(self):
        from cptr.routers.admin import _is_secret_config_key

        for key in (
            "web.tavily_api_key",
            "web.brave_api_key",
            "web.exa_api_key",
            "web.perplexity_api_key",
            "browser.firecrawl_api_key",
            "browser.browser_use_api_key",
            "audio.stt_api_key",
            "images.generation_api_key",
        ):
            self.assertTrue(_is_secret_config_key(key), f"{key} not treated as secret")

    def test_non_secret_keys_untouched(self):
        from cptr.routers.admin import _is_secret_config_key

        for key in ("web.enabled", "web.search_provider", "browser.cdp_url", "chat.default_model"):
            self.assertFalse(_is_secret_config_key(key), f"{key} wrongly treated as secret")

    def test_values_round_trip_through_encryption(self):
        from cptr.routers.admin import _prepare_config_updates

        prepared = _prepare_config_updates({"web.tavily_api_key": "tvly-REAL", "web.enabled": True})
        self.assertTrue(prepared["web.tavily_api_key"].startswith("encrypted:"))
        self.assertNotIn("tvly-REAL", prepared["web.tavily_api_key"])
        self.assertIs(prepared["web.enabled"], True)

    def test_already_encrypted_values_not_double_wrapped(self):
        from cptr.routers.admin import _prepare_config_updates

        once = _prepare_config_updates({"web.brave_api_key": "BSA-REAL"})
        twice = _prepare_config_updates(once)
        self.assertEqual(once["web.brave_api_key"], twice["web.brave_api_key"])


class TestCorsDoesNotPairWildcardWithCredentials(unittest.TestCase):
    """Finding 6: allow_origins=* with allow_credentials=True makes Starlette
    echo the caller's Origin, so any site could read authenticated responses."""

    def test_wildcard_disables_credentials(self):
        from starlette.middleware.cors import CORSMiddleware

        import cptr.app as app_module

        cors = [
            m
            for m in app_module.app.user_middleware
            if m.cls is CORSMiddleware
        ]
        self.assertTrue(cors, "CORS middleware not installed")
        kwargs = cors[0].kwargs
        if "*" in kwargs.get("allow_origins", []):
            self.assertFalse(
                kwargs.get("allow_credentials"),
                "wildcard origin paired with credentialed CORS",
            )


class TestUploadBodiesAreNotAudited(unittest.TestCase):
    """Finding 7: the harness recovered an uploaded file's contents verbatim
    from /data/logs/audit.jsonl.

    Uploading a secrets file made a second copy of it inside the audit log,
    and redaction cannot help - the bytes are opaque.
    """

    def _request(self, content_type: str):
        from starlette.requests import Request

        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/files",
                "headers": [(b"content-type", content_type.encode())],
            }
        )

    def test_multipart_uploads_are_not_captured(self):
        from cptr.utils.audit import AuditLoggingMiddleware

        for ctype in (
            "multipart/form-data; boundary=----x",
            "MULTIPART/FORM-DATA; boundary=y",
            "multipart/mixed",
        ):
            self.assertTrue(
                AuditLoggingMiddleware._is_multipart(self._request(ctype)),
                f"{ctype} body would be copied into the audit log",
            )

    def test_normal_bodies_are_still_captured(self):
        from cptr.utils.audit import AuditLoggingMiddleware

        for ctype in (
            "application/json",
            "application/x-www-form-urlencoded",
            "text/plain",
            "",
        ):
            self.assertFalse(
                AuditLoggingMiddleware._is_multipart(self._request(ctype)),
                f"{ctype} wrongly excluded from auditing",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
