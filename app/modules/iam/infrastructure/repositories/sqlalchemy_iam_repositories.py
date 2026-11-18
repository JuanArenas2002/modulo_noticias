from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.shared.exceptions import InvalidDataError

from app.modules.iam.domain.entities.audit import AuditLog
from app.modules.iam.domain.entities.identity import (AccountType, AuthSession, IdentityProvider, LoginAttempt, User,
                                                      UserIdentity, UserStatus, UserToken)


class SqlAlchemyUserRepository:
    def __init__(self, s: Session):
        self.s = s

    def get(self, user_id: int) -> User | None:
        user = self.s.get(User, user_id)
        return user if user and user.deleted_at is None else None

    def by_email(self, email: str) -> User | None:
        return self.s.scalar(select(User).where(User.email == email.lower(), User.deleted_at.is_(None)))

    def by_identity(self, provider_code: str, tenant_id: str, subject: str) -> UserIdentity | None:
        return self.s.scalar(select(UserIdentity).join(UserIdentity.provider).where(
            IdentityProvider.code == provider_code, UserIdentity.tenant_id == tenant_id,
            UserIdentity.subject == subject))

    def add(self, user: User) -> None:
        self.s.add(user)
        self.s.flush()

    def status(self, code: str) -> UserStatus:
        return self.s.scalars(select(UserStatus).where(UserStatus.code == code)).one()

    def account_type(self, code: str) -> AccountType:
        if (t := self.s.scalar(select(AccountType).where(AccountType.code == code))) is None:
            raise InvalidDataError(f"account_type '{code}' no existe")
        return t

    def provider(self, code: str) -> IdentityProvider:
        return self.s.scalars(select(IdentityProvider).where(IdentityProvider.code == code)).one()


class SqlAlchemySessionRepository:
    def __init__(self, s: Session):
        self.s = s

    def add(self, session: AuthSession) -> None:
        self.s.add(session)
        self.s.flush()

    def by_token_hash(self, token_hash: str) -> AuthSession | None:
        return self.s.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash))

    def by_previous_hash(self, token_hash: str) -> AuthSession | None:
        return self.s.scalar(select(AuthSession).where(AuthSession.previous_token_hash == token_hash))

    def active_for_user(self, user_id: int, at: datetime) -> list[AuthSession]:
        return list(self.s.scalars(select(AuthSession).where(
            AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None), AuthSession.expires_at > at)
            .order_by(AuthSession.id.desc())).unique())

    def revoke_all(self, user_id: int, at: datetime, reason: str, except_id: int | None = None) -> int:
        sessions = [s for s in self.active_for_user(user_id, at) if s.id != except_id]
        for s in sessions:
            s.revoked_at, s.revoked_reason = at, reason
        return len(sessions)


class SqlAlchemyTokenRepository:
    def __init__(self, s: Session):
        self.s = s

    def add(self, token: UserToken) -> None:
        self.s.add(token)

    def by_hash(self, token_hash: str) -> UserToken | None:
        return self.s.scalar(select(UserToken).where(UserToken.token_hash == token_hash))

    def invalidate(self, user_id: int, purpose: str, at: datetime) -> None:
        for t in self.s.scalars(select(UserToken).where(UserToken.user_id == user_id, UserToken.purpose == purpose,
                                                        UserToken.used_at.is_(None))):
            t.used_at = at


class SqlAlchemyLoginAttemptRepository:
    def __init__(self, s: Session):
        self.s = s

    def add(self, attempt: LoginAttempt) -> None:
        self.s.add(attempt)

    def count_ip(self, ip: str, since: datetime) -> int:
        return self.s.scalar(select(func.count()).where(LoginAttempt.ip == ip, LoginAttempt.at >= since,
                                                        LoginAttempt.success.is_(False)))


class SqlAlchemyAuditRepository:
    def __init__(self, s: Session):
        self.s = s

    def add(self, entry: AuditLog) -> None:
        self.s.add(entry)

    def count_recent(self, event_type: str, ip: str, since: datetime) -> int:
        return self.s.scalar(select(func.count()).where(AuditLog.event_type == event_type, AuditLog.ip == ip,
                                                        AuditLog.at >= since))


class SqlAlchemyIamUnitOfWork:
    """Todos los repositorios comparten la sesión: un commit = una transacción."""

    def __init__(self, s: Session):
        self.s = s
        self.users = SqlAlchemyUserRepository(s)
        self.sessions = SqlAlchemySessionRepository(s)
        self.tokens = SqlAlchemyTokenRepository(s)
        self.attempts = SqlAlchemyLoginAttemptRepository(s)
        self.audit = SqlAlchemyAuditRepository(s)

    def flush(self) -> None:
        self.s.flush()

    def commit(self) -> None:
        self.s.commit()
