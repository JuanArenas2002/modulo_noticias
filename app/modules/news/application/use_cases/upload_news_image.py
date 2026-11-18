"""Caso de uso: subir la imagen principal de una noticia.

Mismo permiso que editar el campo image_url (news.update sobre todas sus dependencias mientras es editable).
El tipo se decide por la firma de bytes, no por lo que diga el cliente.
"""
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.news.domain.entities.news import News, NewsHistory
from app.modules.news.domain.repositories.media_storage import MediaStorage
from app.modules.news.domain.repositories.news_repository import NewsRepository
from app.shared.clock import now
from app.shared.exceptions import InvalidDataError, NotFoundError

SIGNATURES = (  # (prefijo, extensión)
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
)


def image_extension(content: bytes) -> str | None:
    if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return "webp"
    return next((ext for sig, ext in SIGNATURES if content.startswith(sig)), None)


class UploadNewsImageUseCase:
    def __init__(self, news: NewsRepository, storage: MediaStorage, max_bytes: int):
        self.news, self.storage, self.max_bytes = news, storage, max_bytes

    def _store(self, news_id: int, content: bytes, user: Principal, field: str) -> tuple[News, str]:
        if (n := self.news.get(news_id)) is None:
            raise NotFoundError("Noticia no encontrada")
        user.ensure_all(n.edit_permission({field}), n.scope_keys)
        if not content or len(content) > self.max_bytes:
            raise InvalidDataError(f"La imagen debe pesar como máximo {self.max_bytes // (1024 * 1024)} MB")
        if (ext := image_extension(content)) is None:
            raise InvalidDataError("Formato no admitido: usa JPG, PNG o WebP")
        return n, self.storage.save(n.id, content, ext)

    def inline(self, news_id: int, content: bytes, user: Principal) -> str:
        """Imagen dentro del contenido: solo se guarda; el editor inserta la URL en el HTML."""
        return self._store(news_id, content, user, "content")[1]

    def execute(self, news_id: int, content: bytes, user: Principal) -> News:
        n, url = self._store(news_id, content, user, "image_url")
        n.image_url = url
        n.updated_at = now()
        self.news.add_history(NewsHistory(news_id=n.id, actor_id=user.user_id, action="update",
                                          from_status=n.status, to_status=n.status))
        self.news.commit()
        return n
