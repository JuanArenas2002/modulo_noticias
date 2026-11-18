"""Persistencia de privacidad y el control central `allows(subject, categoría)`, que consulta la analítica."""
import time
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.modules.privacy.domain.rules import VALIDITY, needs_decision, normalize
from app.modules.privacy.infrastructure.tables import privacy_consents as C
from app.modules.privacy.infrastructure.tables import privacy_cookie_categories as K
from app.modules.privacy.infrastructure.tables import privacy_policies as P
from app.shared.clock import as_utc

# ponytail: caché por proceso de la versión que exige reconsentimiento (cambia solo al publicar una política).
# Se invalida al publicar desde este proceso; en otros workers tarda hasta 30 s.
_reconsent: tuple[float, int] | None = None
CACHE_SECONDS = 30


def forget_cache() -> None:
    global _reconsent
    _reconsent = None


class PrivacyRepository:
    def __init__(self, db: Session):
        self.db = db

    # ---------- políticas ----------
    def current_policies(self, at: datetime) -> list[dict]:
        """La versión vigente de cada tipo + la lista de versiones publicadas (trazabilidad)."""
        rows = [r._asdict() for r in self.db.execute(
            select(P).where(P.c.effective_at <= at).order_by(P.c.kind, P.c.version.desc()))]
        out: dict[str, dict] = {}
        for r in rows:
            entry = out.setdefault(r["kind"], r | {"versions": []})
            entry["versions"].append({"version": r["version"], "effective_at": r["effective_at"], "title": r["title"]})
        return list(out.values())

    def policy(self, kind: str, version: int, at: datetime) -> dict | None:
        r = self.db.execute(select(P).where(P.c.kind == kind, P.c.version == version, P.c.effective_at <= at)).first()
        return r._asdict() if r else None

    def all_policies(self) -> list[dict]:
        return [r._asdict() for r in self.db.execute(select(P).order_by(P.c.kind, P.c.version.desc()))]

    def policy_by_id(self, policy_id: int) -> dict | None:
        r = self.db.execute(select(P).where(P.c.id == policy_id)).first()
        return r._asdict() if r else None

    def add_policy(self, row: dict) -> dict:
        version = (self.db.scalar(select(func.max(P.c.version)).where(P.c.kind == row["kind"])) or 0) + 1
        new_id = self.db.execute(P.insert().values(**row, version=version)).inserted_primary_key[0]
        forget_cache()
        return self.policy_by_id(new_id)

    def update_policy(self, policy_id: int, values: dict) -> dict:
        self.db.execute(update(P).where(P.c.id == policy_id).values(**values))
        forget_cache()
        return self.policy_by_id(policy_id)

    def cookie_policy_version(self, at: datetime) -> int:
        return self.db.scalar(select(func.max(P.c.version)).where(
            P.c.kind == "cookie_policy", P.c.effective_at <= at)) or 0

    def reconsent_version(self, at: datetime) -> int:
        """Última versión vigente de la política de cookies que exige volver a decidir."""
        global _reconsent
        if _reconsent and _reconsent[0] > time.monotonic():
            return _reconsent[1]
        v = self.db.scalar(select(func.max(P.c.version)).where(
            P.c.kind == "cookie_policy", P.c.requires_reconsent.is_(True), P.c.effective_at <= at)) or 0
        _reconsent = (time.monotonic() + CACHE_SECONDS, v)
        return v

    # ---------- categorías ----------
    def categories(self) -> list[dict]:
        return [r._asdict() for r in self.db.execute(select(K).order_by(K.c.sort))]

    def update_category(self, code: str, values: dict) -> dict | None:
        self.db.execute(update(K).where(K.c.code == code).values(**values))
        r = self.db.execute(select(K).where(K.c.code == code)).first()
        return r._asdict() if r else None

    # ---------- consentimientos ----------
    def active(self, subject_id: str | None) -> dict | None:
        if not subject_id:
            return None
        r = self.db.execute(select(C).where(C.c.subject_id == subject_id, C.c.status == "active")
                            .order_by(C.c.id.desc()).limit(1)).first()
        return r._asdict() if r else None

    def state(self, subject_id: str | None, at: datetime) -> dict:
        """Lo que el navegador necesita saber: su decisión vigente y si hay que preguntar (otra vez)."""
        c = self.active(subject_id)
        pending = needs_decision(c and c["policy_version"], c and as_utc(c["expires_at"]),
                                 self.reconsent_version(at), at)
        return {
            "needs_decision": pending,
            "cookie_policy_version": self.cookie_policy_version(at),
            "categories": normalize({} if pending or not c else c["categories"]),  # vigente: si hay que preguntar, todo apagado
            "consent": None if not c else {k: c[k] for k in ("policy_version", "categories", "method", "decided_at",
                                                             "expires_at")},
        }

    def allows(self, subject_id: str | None, category: str, at: datetime) -> bool:
        """Control central: ¿esta categoría está autorizada para este navegador AHORA?"""
        return bool(self.state(subject_id, at)["categories"].get(category))

    def decide(self, subject_id: str, user_id: int | None, categories: dict[str, bool], method: str,
               at: datetime) -> None:
        """Nueva decisión: la anterior queda como `superseded` (prueba conservada, no se edita)."""
        self.db.execute(update(C).where(C.c.subject_id == subject_id, C.c.status == "active")
                        .values(status="superseded"))
        self.db.execute(C.insert().values(subject_id=subject_id, user_id=user_id, categories=normalize(categories),
                                          policy_version=self.cookie_policy_version(at), method=method,
                                          status="active", decided_at=at, expires_at=at + VALIDITY))
        self.db.commit()

    def summary(self, since: datetime) -> dict:
        """Agregados para la administración (nunca decisiones individuales)."""
        rows = self.db.execute(select(C.c.method, func.count()).where(C.c.decided_at >= since)
                               .group_by(C.c.method)).all()
        active = [r[0] for r in self.db.execute(select(C.c.categories).where(C.c.status == "active"))]
        return {"decisions_by_method": dict(rows), "active_subjects": len(active),
                "analytics_allowed": sum(bool(c.get("analytics")) for c in active),
                "functional_allowed": sum(bool(c.get("functional")) for c in active)}
