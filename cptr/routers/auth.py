"""Authentication router for cptr."""

from __future__ import annotations

from fastapi import APIRouter, Request, UploadFile, File as FastAPIFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

from cptr.utils.config import (
    SESSION_MAX_AGE,
    AuthMode,
    check_access,
    check_rate_limit,
    create_ticket,
    create_token,
    get_auth_mode,
    get_or_create_user,
    has_any_user,
    hash_password,
    load_config,
    now_ms,
    pam_authenticate,
    record_attempt,
    verify_password,
    verify_ticket,
)
from cptr.env import TLS_ENABLED
from cptr.models import User, Auth, Config
from cptr.utils.elevation import expires_at, grant, revoke
from cptr.utils.permissions import (
    CAP_TERMINAL,
    ROLE_SUPERADMIN,
    has_capability,
    is_admin,
    resolve,
)
from cptr.utils.twofactor import begin_enrollment, check_code, needs_enrollment

router = APIRouter(prefix="/api/auth", tags=["auth"])

COOKIE_NAME = "cptr_session"

# Ticket purposes bridging the password step to the TOTP step.
TICKET_ENROLL = "totp-enroll"
TICKET_LOGIN = "totp-login"


class ElevateRequest(BaseModel):
    code: str


def _ok_with_cookie(jwt_token: str, data: dict | None = None) -> JSONResponse:
    """Return a JSONResponse with the session cookie set."""
    resp = JSONResponse(data or {"ok": True})
    resp.set_cookie(
        key=COOKIE_NAME,
        value=jwt_token,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=SESSION_MAX_AGE,
        # Under TLS the cookie must never be sent over a plain-HTTP fallback.
        # Left off when serving HTTP so that `--no-tls` on loopback still works.
        secure=TLS_ENABLED,
    )
    return resp


@router.get("")
async def get_auth(request: Request):
    """Session check. Returns user info or {authenticated: false}.

    Implements sliding sessions: if the token is past its halfway point,
    a fresh token is issued so active users never get logged out.
    """
    import time

    client_host = request.client.host if request.client else "127.0.0.1"
    token = request.cookies.get(COOKIE_NAME)
    remote_user = None
    if get_auth_mode() == AuthMode.TRUSTED_HEADER:
        header_name = load_config().get("auth", {}).get("header", "Remote-User")
        remote_user = request.headers.get(header_name)
    auth = check_access(client_host=client_host, jwt_token=token, remote_user_header=remote_user)

    if auth is not None and auth.username and not auth.user_id:
        auth.user_id = await get_or_create_user(auth.username)

    if auth is not None and auth.user_id:
        if not auth.exp:
            auth.exp = time.time() + SESSION_MAX_AGE
        user = await User.get_by_id(auth.user_id)
        if user is None:
            from starlette.responses import JSONResponse as StarletteJSONResponse

            response = StarletteJSONResponse({"authenticated": False})
            response.delete_cookie(COOKIE_NAME, path="/")
            return response

        _, caps = await resolve(auth.user_id)
        elevation_expiry = expires_at(auth.user_id)
        data = {
            "authenticated": True,
            "user_id": auth.user_id,
            "username": auth.username,
            "display_name": user.display_name,
            "role": user.role,
            "profile_image_url": user.profile_image_url,
            "exp": int(auth.exp * 1000),
            # Drives what the UI offers. The server re-checks every one of
            # these on the request itself; this is presentation only.
            "capabilities": sorted(caps),
            "elevated": elevation_expiry is not None,
            "elevation_expires_at": int(elevation_expiry * 1000) if elevation_expiry else None,
        }

        # Sliding session: refresh token if past halfway to expiry
        remaining = auth.exp - time.time()
        if remote_user or remaining < SESSION_MAX_AGE / 2:
            new_token = create_token(auth.user_id, auth.username, user.role)
            return _ok_with_cookie(new_token, data)

        return data

    return {"authenticated": False}


@router.post("/setup")
async def setup(request: Request, body: SetupRequest):
    """First-time admin setup. Requires valid startup token."""
    if await has_any_user():
        return JSONResponse({"error": "already set up"}, 400)
    import secrets as _secrets

    expected = getattr(request.app.state, "startup_token", None)
    if not body.token or not expected or not _secrets.compare_digest(body.token, expected):
        return JSONResponse({"error": "invalid startup token"}, 403)
    if not body.username or not body.username.strip():
        return JSONResponse({"error": "username required"}, 400)
    if len(body.password.strip()) < 6:
        return JSONResponse({"error": "min 6 characters"}, 400)

    # Whoever sets the box up owns it outright.
    user_id = await User.create(
        username=body.username.strip(),
        password_hash=hash_password(body.password.strip()),
        role=ROLE_SUPERADMIN,
        display_name=body.display_name,
        created_at=now_ms(),
    )

    # No session yet: the very first sign-in enrols a second factor like any
    # other, so there is never an account without one.
    return await _second_factor_challenge(user_id, body.username.strip())


@router.post("/login")
async def login(request: Request, body: LoginRequest):
    """Login with password or PAM."""
    ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(ip):
        return JSONResponse({"error": "too many attempts"}, 429)
    record_attempt(ip)

    mode = get_auth_mode()

    if mode == AuthMode.PASSWORD:
        if not body.username:
            return JSONResponse({"error": "username required"}, 400)
        result = await Auth.get_with_user(body.username)
        if not result or not verify_password(body.password, result[0].password):
            return JSONResponse({"error": "incorrect credentials"}, 401)
        auth, user = result
        if user.role == "pending":
            return JSONResponse({"error": "account pending approval"}, 403)
        return await _second_factor_challenge(auth.user_id, auth.username)

    if mode == AuthMode.PAM:
        if not body.username:
            return JSONResponse({"error": "username required"}, 400)
        if not pam_authenticate(body.username, body.password):
            return JSONResponse({"error": "incorrect credentials"}, 401)
        user_id = await get_or_create_user(body.username)
        user = await User.get_by_id(user_id)
        if user and user.role == "pending":
            role = _bootstrap_role(await User.list_all())
            await User.update_role(user_id, role)
            user.role = role
        return await _second_factor_challenge(user_id, body.username)

    return JSONResponse({"error": "auth not configured"}, 400)


def _bootstrap_role(existing: list[dict]) -> str:
    """Role for the first PAM user to arrive: the very first one owns the box."""
    if any(is_admin(u["role"]) for u in existing):
        return "user"
    return ROLE_SUPERADMIN


async def _second_factor_challenge(user_id: str, username: str) -> JSONResponse:
    """Password step passed — hand back a TOTP challenge, never a session.

    Two shapes come back, both carrying a 5-minute ticket rather than a
    cookie:

    * `totp_enrollment` — first sign-in (or after `cptr recovery reset`).
      The secret, `otpauth://` URI and a QR code are shown once, here, and
      never again.
    * `totp_required` — steady state; the client just collects six digits.
    """
    auth = await Auth.get_by_user_id(user_id)
    if auth is None:
        return JSONResponse({"error": "incorrect credentials"}, 401)

    if needs_enrollment(auth):
        enrollment = await begin_enrollment(user_id, username)
        return JSONResponse(
            {
                "totp_enrollment": True,
                "ticket": create_ticket(user_id, username, TICKET_ENROLL),
                "secret": enrollment["secret"],
                "uri": enrollment["uri"],
                "qr_svg": enrollment["qr_svg"],
            }
        )

    return JSONResponse(
        {
            "totp_required": True,
            "ticket": create_ticket(user_id, username, TICKET_LOGIN),
        }
    )


class TotpRequest(BaseModel):
    ticket: str
    code: str


@router.post("/login/totp")
async def login_totp(request: Request, body: TotpRequest):
    """Second step of login: exchange a ticket plus a valid code for a session.

    Confirming an enrolment and satisfying a routine challenge land here alike;
    the ticket's purpose says which, so an enrolment ticket cannot be replayed
    to skip a challenge on an already-enrolled account.
    """
    ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(ip):
        return JSONResponse({"error": "too many attempts"}, 429)
    record_attempt(ip)

    claims = verify_ticket(body.ticket, TICKET_ENROLL) or verify_ticket(body.ticket, TICKET_LOGIN)
    if claims is None:
        return JSONResponse({"error": "login expired, start again"}, 401)
    confirming = claims.get("typ") == TICKET_ENROLL

    auth = await Auth.get_by_user_id(claims["sub"])
    user = await User.get_by_id(claims["sub"])
    if auth is None or user is None:
        return JSONResponse({"error": "incorrect credentials"}, 401)
    if user.role == "pending":
        return JSONResponse({"error": "account pending approval"}, 403)
    # An enrolment ticket must not satisfy an account that is already enrolled.
    if confirming != needs_enrollment(auth):
        return JSONResponse({"error": "login expired, start again"}, 401)

    ok, error = await check_code(auth, body.code, confirming=confirming)
    if not ok:
        return JSONResponse({"error": error or "invalid code"}, 401)

    return _ok_with_cookie(
        create_token(auth.user_id, auth.username, role=user.role),
        {"ok": True, "username": auth.username, "enrolled": confirming},
    )


@router.post("/elevate")
async def elevate(request: Request, body: ElevateRequest):
    """Open a terminal elevation window by re-entering a TOTP code.

    Holding the `terminal` capability is not enough to reach a PTY — see
    `cptr.utils.elevation` for the idle window this opens.
    """
    ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(ip):
        return JSONResponse({"error": "too many attempts"}, 429)
    record_attempt(ip)

    token = request.cookies.get(COOKIE_NAME)
    auth_info = check_access(
        client_host=request.client.host if request.client else "127.0.0.1",
        jwt_token=token,
    )
    if auth_info is None or not auth_info.user_id:
        return JSONResponse({"error": "not authenticated"}, 401)

    if not await has_capability(auth_info.user_id, CAP_TERMINAL):
        return JSONResponse({"error": "terminal access not granted"}, 403)

    auth = await Auth.get_by_user_id(auth_info.user_id)
    if auth is None or needs_enrollment(auth):
        return JSONResponse({"error": "two-factor authentication is not set up"}, 403)

    ok, error = await check_code(auth, body.code)
    if not ok:
        return JSONResponse({"error": error or "invalid code"}, 401)

    expires = grant(auth_info.user_id)
    return JSONResponse({"ok": True, "expires_at": int(expires * 1000)})


@router.get("/elevation")
async def elevation_status(request: Request):
    """Whether the caller currently holds a terminal elevation window."""
    token = request.cookies.get(COOKIE_NAME)
    auth_info = check_access(
        client_host=request.client.host if request.client else "127.0.0.1",
        jwt_token=token,
    )
    if auth_info is None or not auth_info.user_id:
        return JSONResponse({"error": "not authenticated"}, 401)

    _, caps = await resolve(auth_info.user_id)
    expiry = expires_at(auth_info.user_id)
    return {
        "elevated": expiry is not None,
        "expires_at": int(expiry * 1000) if expiry else None,
        "capabilities": sorted(caps),
    }


@router.post("/logout")
async def logout(request: Request):
    """Logout = delete cookie, and drop any terminal elevation window."""
    token = request.cookies.get(COOKIE_NAME)
    auth_info = check_access(
        client_host=request.client.host if request.client else "127.0.0.1",
        jwt_token=token,
    )
    if auth_info is not None and auth_info.user_id:
        revoke(auth_info.user_id)

    resp = JSONResponse({"ok": True})
    resp.delete_cookie(key=COOKIE_NAME, path="/")
    return resp


@router.post("/password")
async def update_password(request: Request, body: UpdatePasswordRequest):
    """Update password for the authenticated user."""
    token = request.cookies.get(COOKIE_NAME)
    auth_info = check_access(
        client_host=request.client.host if request.client else "127.0.0.1",
        jwt_token=token,
    )
    if auth_info is None:
        return JSONResponse({"error": "not authenticated"}, 401)

    if len(body.new_password.strip()) < 6:
        return JSONResponse({"error": "min 6 characters"}, 400)

    # Verify current password
    result = await Auth.get_with_user(auth_info.username)
    if not result:
        return JSONResponse({"error": "user not found"}, 404)
    auth, _ = result
    if auth.password and not verify_password(body.current_password, auth.password):
        return JSONResponse({"error": "incorrect current password"}, 401)

    await Auth.update_password(auth_info.user_id, hash_password(body.new_password.strip()))
    return {"ok": True}


@router.post("/signup")
async def signup(request: Request, body: SignupRequest):
    """Self-registration. Only works if auth.signup_enabled is true."""
    signup_enabled = await Config.get("auth.signup_enabled")
    if not signup_enabled:
        return JSONResponse({"error": "sign up disabled"}, 403)

    if not body.username or not body.username.strip():
        return JSONResponse({"error": "username required"}, 400)
    if len(body.password.strip()) < 6:
        return JSONResponse({"error": "min 6 characters"}, 400)

    username = body.username.strip()
    if await Auth.username_exists(username):
        return JSONResponse({"error": "username taken"}, 409)

    await User.create(
        username=username,
        password_hash=hash_password(body.password.strip()),
        role="pending",
        created_at=now_ms(),
    )
    return {"ok": True, "pending": True}


# ── Request Models ───────────────────────────────────────────


class LoginRequest(BaseModel):
    username: Optional[str] = None
    password: str


class SetupRequest(BaseModel):
    username: str
    password: str
    token: str
    display_name: Optional[str] = None


class SignupRequest(BaseModel):
    username: str
    password: str


class UpdatePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class UpdateProfileRequest(BaseModel):
    display_name: Optional[str] = None


@router.put("/profile")
async def update_profile(request: Request, body: UpdateProfileRequest):
    """Update display name."""
    token = request.cookies.get(COOKIE_NAME)
    auth_info = check_access(
        client_host=request.client.host if request.client else "127.0.0.1",
        jwt_token=token,
    )
    if auth_info is None:
        return JSONResponse({"error": "not authenticated"}, 401)

    await User.update_display_name(auth_info.user_id, body.display_name)
    return {"ok": True, "display_name": body.display_name}


# ── Avatar ───────────────────────────────────────────────────


@router.put("/avatar")
async def upload_avatar(request: Request, file: UploadFile = FastAPIFile(...)):
    """Upload a profile image. Resizing is done client-side."""
    from cptr.models.files import File as FileModel
    from cptr.utils.storage import get_storage

    token = request.cookies.get(COOKIE_NAME)
    auth_info = check_access(
        client_host=request.client.host if request.client else "127.0.0.1",
        jwt_token=token,
    )
    if auth_info is None:
        return JSONResponse({"error": "not authenticated"}, 401)

    data = await file.read()
    if len(data) > 5 * 1024 * 1024:
        return JSONResponse({"error": "file too large (max 5 MB)"}, 413)

    # Delete old avatar if exists
    user = await User.get_by_id(auth_info.user_id)
    if user and user.profile_image_url:
        old_id = user.profile_image_url.rsplit("/", 1)[-1]
        await get_storage().delete(old_id)
        await FileModel.delete_by_id(old_id)

    record = await FileModel.create(
        user_id=auth_info.user_id,
        filename=file.filename or "avatar",
        meta={"content_type": file.content_type or "image/png", "size": len(data)},
        created_at=now_ms(),
    )
    await get_storage().put(record.id, data)

    url = f"/api/files/{record.id}"
    await User.update_profile_image(auth_info.user_id, url)

    return {"ok": True, "profile_image_url": url}


@router.delete("/avatar")
async def delete_avatar(request: Request):
    """Delete profile image."""
    from cptr.models.files import File as FileModel
    from cptr.utils.storage import get_storage

    token = request.cookies.get(COOKIE_NAME)
    auth_info = check_access(
        client_host=request.client.host if request.client else "127.0.0.1",
        jwt_token=token,
    )
    if auth_info is None:
        return JSONResponse({"error": "not authenticated"}, 401)

    user = await User.get_by_id(auth_info.user_id)
    if user and user.profile_image_url:
        old_id = user.profile_image_url.rsplit("/", 1)[-1]
        await get_storage().delete(old_id)
        await FileModel.delete_by_id(old_id)

    await User.update_profile_image(auth_info.user_id, None)
    return {"ok": True}
