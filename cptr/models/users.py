"""User, Auth, and UserStates models with data-access class methods."""

from __future__ import annotations

import uuid

from sqlalchemy import BigInteger, Boolean, Column, ForeignKey, Text, select, update, delete
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship

from cptr.models.base import Base
from cptr.utils.db import get_db


def _uuid() -> str:
    return str(uuid.uuid4())


def _invalidate_permissions(user_id: str) -> None:
    """Drop the cached capability set so a change takes effect at once."""
    try:
        from cptr.utils.permissions import invalidate

        invalidate(user_id)
    except Exception:
        pass


class User(Base):
    """Profile only. No credentials, no login identity."""

    __tablename__ = "users"

    id = Column(Text, primary_key=True, default=_uuid)
    display_name = Column(Text, nullable=True)
    profile_image_url = Column(Text, nullable=True)
    # "superadmin" | "admin" | "user" | "pending"
    role = Column(Text, nullable=False, default="pending")
    settings = Column(JSON, nullable=False, default=dict)
    created_at = Column(BigInteger, nullable=False)
    updated_at = Column(BigInteger, nullable=True)
    last_seen_at = Column(BigInteger, nullable=True)

    # Independent capability grants. Admins hold all of these implicitly, so
    # these columns are only consulted for plain users — see
    # cptr.utils.permissions. New accounts start with none: chat only.
    can_terminal = Column(Boolean, nullable=False, default=False)
    can_machine = Column(Boolean, nullable=False, default=False)
    can_external = Column(Boolean, nullable=False, default=False)

    auth = relationship("Auth", back_populates="user", uselist=False)
    states = relationship("UserStates", back_populates="user", uselist=False)

    # ── Class methods ────────────────────────────────────────

    @staticmethod
    async def get_by_id(user_id: str) -> User | None:
        async with await get_db() as db:
            result = await db.execute(select(User).where(User.id == user_id))
            return result.scalar_one_or_none()

    @staticmethod
    async def list_all() -> list[dict]:
        """List all users joined with their auth username."""
        async with await get_db() as db:
            result = await db.execute(
                select(
                    User.id,
                    User.display_name,
                    User.profile_image_url,
                    User.role,
                    User.created_at,
                    User.can_terminal,
                    User.can_machine,
                    User.can_external,
                    Auth.username,
                    Auth.totp_enabled,
                    Auth.totp_reset_required,
                )
                .join(Auth, User.id == Auth.user_id)
                .order_by(User.created_at)
            )
            return [
                {
                    "user_id": row.id,
                    "username": row.username,
                    "display_name": row.display_name,
                    "profile_image_url": row.profile_image_url,
                    "role": row.role,
                    "created_at": row.created_at,
                    "capabilities": {
                        "terminal": bool(row.can_terminal),
                        "machine": bool(row.can_machine),
                        "external": bool(row.can_external),
                    },
                    "totp_enabled": bool(row.totp_enabled),
                    "totp_reset_required": bool(row.totp_reset_required),
                }
                for row in result.all()
            ]

    @staticmethod
    async def create(
        username: str,
        password_hash: str,
        role: str = "user",
        display_name: str | None = None,
        created_at: int = 0,
    ) -> str:
        """Create a User + Auth row. Returns the new user_id."""
        async with await get_db() as db:
            user = User(created_at=created_at, display_name=display_name, role=role)
            db.add(user)
            await db.flush()
            db.add(Auth(user_id=user.id, username=username, password=password_hash))
            await db.commit()
            return user.id

    @staticmethod
    async def update_role(user_id: str, role: str) -> bool:
        """Update a user's role. Returns True if user existed."""
        async with await get_db() as db:
            result = await db.execute(update(User).where(User.id == user_id).values(role=role))
            await db.commit()
        _invalidate_permissions(user_id)
        return result.rowcount > 0

    @staticmethod
    async def update_capabilities(user_id: str, capabilities: dict[str, bool]) -> bool:
        """Grant or revoke capability flags. Returns True if user existed."""
        from cptr.utils.permissions import CAPABILITY_COLUMNS

        values = {
            CAPABILITY_COLUMNS[cap]: bool(value)
            for cap, value in capabilities.items()
            if cap in CAPABILITY_COLUMNS
        }
        if not values:
            return await User.get_by_id(user_id) is not None
        async with await get_db() as db:
            result = await db.execute(update(User).where(User.id == user_id).values(**values))
            await db.commit()
        _invalidate_permissions(user_id)
        return result.rowcount > 0

    @staticmethod
    async def list_by_role(role: str) -> list[User]:
        async with await get_db() as db:
            result = await db.execute(select(User).where(User.role == role))
            return list(result.scalars().all())

    @staticmethod
    async def delete_user(user_id: str) -> None:
        """Delete user and all related rows."""
        async with await get_db() as db:
            await db.execute(delete(UserStates).where(UserStates.user_id == user_id))
            await db.execute(delete(Auth).where(Auth.user_id == user_id))
            await db.execute(delete(User).where(User.id == user_id))
            await db.commit()

    @staticmethod
    async def update_profile_image(user_id: str, url: str | None) -> bool:
        """Set or clear profile image URL. Returns True if user existed."""
        async with await get_db() as db:
            result = await db.execute(
                update(User).where(User.id == user_id).values(profile_image_url=url)
            )
            await db.commit()
            return result.rowcount > 0

    @staticmethod
    async def update_display_name(user_id: str, display_name: str | None) -> bool:
        """Set or clear display name. Returns True if user existed."""
        async with await get_db() as db:
            result = await db.execute(
                update(User).where(User.id == user_id).values(display_name=display_name or None)
            )
            await db.commit()
            return result.rowcount > 0


class Auth(Base):
    """Login identity + credentials. 1:1 with User."""

    __tablename__ = "auths"

    user_id = Column(Text, ForeignKey("users.id"), primary_key=True)
    username = Column(Text, unique=True, nullable=False)
    password = Column(Text, nullable=True)  # bcrypt hash, NULL for PAM

    # TOTP second factor. The secret is stored Fernet-encrypted (keyed by the
    # server JWT secret) and only ever decrypted at the auth boundary.
    # `totp_enabled` flips true once the user proves enrolment with a code.
    totp_secret = Column(Text, nullable=True)
    totp_enabled = Column(Boolean, nullable=False, default=False)
    # Set by `cptr recovery reset`: clears the factor so the next successful
    # password login re-enrols from scratch.
    totp_reset_required = Column(Boolean, nullable=False, default=False)
    # Unix seconds of the last accepted code, so a code cannot be replayed
    # inside its own 30-second step.
    totp_last_used_at = Column(BigInteger, nullable=True)

    user = relationship("User", back_populates="auth")

    # ── Class methods ────────────────────────────────────────

    @staticmethod
    async def get_by_username(username: str) -> Auth | None:
        async with await get_db() as db:
            result = await db.execute(
                select(Auth).where(Auth.username == username, Auth.password.isnot(None))
            )
            return result.scalar_one_or_none()

    @staticmethod
    async def get_by_user_id(user_id: str) -> Auth | None:
        async with await get_db() as db:
            result = await db.execute(select(Auth).where(Auth.user_id == user_id))
            return result.scalar_one_or_none()

    @staticmethod
    async def username_exists(username: str) -> bool:
        async with await get_db() as db:
            result = await db.execute(select(Auth).where(Auth.username == username))
            return result.scalar_one_or_none() is not None

    @staticmethod
    async def update_password(user_id: str, new_hash: str) -> bool:
        """Update password hash. Returns True if auth row existed."""
        async with await get_db() as db:
            result = await db.execute(select(Auth).where(Auth.user_id == user_id))
            auth = result.scalar_one_or_none()
            if not auth:
                return False
            await db.execute(update(Auth).where(Auth.user_id == user_id).values(password=new_hash))
            await db.commit()
            return True

    @staticmethod
    async def update_username(user_id: str, new_username: str) -> bool:
        """Update username. Returns True if auth row existed."""
        async with await get_db() as db:
            result = await db.execute(select(Auth).where(Auth.user_id == user_id))
            auth = result.scalar_one_or_none()
            if not auth:
                return False
            # Check uniqueness
            existing = await db.execute(
                select(Auth).where(Auth.username == new_username, Auth.user_id != user_id)
            )
            if existing.scalar_one_or_none():
                return False
            await db.execute(
                update(Auth).where(Auth.user_id == user_id).values(username=new_username)
            )
            await db.commit()
            return True

    # ── TOTP second factor ───────────────────────────────────

    @staticmethod
    async def set_totp_secret(user_id: str, encrypted_secret: str) -> bool:
        """Stage an unconfirmed secret. Enrolment is not complete until the
        user proves possession via `confirm_totp`."""
        async with await get_db() as db:
            result = await db.execute(
                update(Auth)
                .where(Auth.user_id == user_id)
                .values(
                    totp_secret=encrypted_secret,
                    totp_enabled=False,
                    totp_reset_required=False,
                    totp_last_used_at=None,
                )
            )
            await db.commit()
            return result.rowcount > 0

    @staticmethod
    async def confirm_totp(user_id: str, used_at: int) -> bool:
        """Mark enrolment complete after a first valid code."""
        async with await get_db() as db:
            result = await db.execute(
                update(Auth)
                .where(Auth.user_id == user_id)
                .values(totp_enabled=True, totp_reset_required=False, totp_last_used_at=used_at)
            )
            await db.commit()
            return result.rowcount > 0

    @staticmethod
    async def record_totp_use(user_id: str, used_at: int) -> None:
        """Burn a code so the same one cannot be replayed within its step."""
        async with await get_db() as db:
            await db.execute(
                update(Auth).where(Auth.user_id == user_id).values(totp_last_used_at=used_at)
            )
            await db.commit()

    @staticmethod
    async def reset_totp(user_id: str) -> bool:
        """Clear the factor and require re-enrolment at the next login."""
        async with await get_db() as db:
            result = await db.execute(
                update(Auth)
                .where(Auth.user_id == user_id)
                .values(
                    totp_secret=None,
                    totp_enabled=False,
                    totp_reset_required=True,
                    totp_last_used_at=None,
                )
            )
            await db.commit()
            return result.rowcount > 0

    @staticmethod
    async def get_with_user(username: str) -> tuple[Auth, User] | None:
        """Get auth + user in one query for login."""
        async with await get_db() as db:
            result = await db.execute(
                select(Auth).where(Auth.username == username, Auth.password.isnot(None))
            )
            auth = result.scalar_one_or_none()
            if not auth:
                return None
            user_result = await db.execute(select(User).where(User.id == auth.user_id))
            user = user_result.scalar_one()
            return auth, user


class UserStates(Base):
    """Workspace layout state. 1:1 with User."""

    __tablename__ = "user_states"

    user_id = Column(Text, ForeignKey("users.id"), primary_key=True)
    data = Column(JSON, nullable=False, default=dict)
    updated_at = Column(BigInteger, nullable=True)

    user = relationship("User", back_populates="states")

    # ── Class methods ────────────────────────────────────────

    @staticmethod
    async def get_data(user_id: str) -> dict:
        """Get user state data. Returns empty dict if not set."""
        async with await get_db() as db:
            result = await db.execute(select(UserStates).where(UserStates.user_id == user_id))
            row = result.scalar_one_or_none()
            return row.data if row else {}

    @staticmethod
    async def save_data(user_id: str, data: dict) -> None:
        """Upsert user state data."""
        async with await get_db() as db:
            result = await db.execute(select(UserStates).where(UserStates.user_id == user_id))
            row = result.scalar_one_or_none()
            if row:
                row.data = data
            else:
                db.add(UserStates(user_id=user_id, data=data))
            await db.commit()
