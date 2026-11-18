from typing import Protocol


class MediaStorage(Protocol):
    """Almacén de imágenes de noticias. Devuelve la ruta pública relativa (p.ej. /media/news/7-ab12.webp)."""
    def save(self, news_id: int, content: bytes, extension: str) -> str: ...
