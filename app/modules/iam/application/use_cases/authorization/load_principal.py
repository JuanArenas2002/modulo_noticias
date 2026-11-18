"""Caso de uso: permisos efectivos de un usuario (roles activos x permisos activos x alcance + herencia)."""
from app.modules.iam.domain.repositories.iam_repositories import AuthorizationRepository
from app.modules.iam.domain.services.authorization_service import Principal, build_principal


class LoadPrincipalUseCase:
    def __init__(self, repo: AuthorizationRepository):
        self.repo = repo

    def execute(self, user_id: int, session_id: int | None = None) -> Principal:
        # ponytail: se recalcula en cada request (revocación inmediata). Cachear por sesión si el costo se nota.
        return build_principal(user_id, session_id, self.repo.grants(user_id), self.repo.institutional_types(),
                               self.repo.children)
