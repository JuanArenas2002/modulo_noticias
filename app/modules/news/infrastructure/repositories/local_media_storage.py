"""Imágenes en disco local (MEDIA_DIR). Nombre = id + hash del contenido: inmutable y cacheable."""
import hashlib
import re
import uuid
from pathlib import Path

PUBLIC_PREFIX = "/media/news/"
NAME = re.compile(r"^\d+-[0-9a-f]{16}\.(jpg|png|webp)$")
# Anchos servibles (?w=): pocos y fijos para que la caché en disco no crezca sin control.
WIDTHS = (320, 640, 960, 1280, 1920)


class LocalMediaStorage:
    def __init__(self, root: str):
        self.dir = Path(root) / "news"

    def save(self, news_id: int, content: bytes, extension: str) -> str:
        self.dir.mkdir(parents=True, exist_ok=True)
        name = f"{news_id}-{hashlib.sha256(content).hexdigest()[:16]}.{extension}"
        (self.dir / name).write_bytes(content)
        # ponytail: la imagen anterior queda en disco; limpiar huérfanas si el espacio importa.
        return PUBLIC_PREFIX + name

    def variant(self, name: str, width: int) -> Path | None:
        """Versión WebP de `width` px de ancho (nunca más grande que el original), creada una vez y guardada.

        Las fotos se suben tal cual (hasta 8000 px y varios MB); una tarjeta de 300 px no debe descargarlas.
        El nombre incluye el hash del contenido: cada variante es inmutable y cacheable.
        """
        if width not in WIDTHS or (src := self.path(name)) is None:
            return None
        out = self.dir / "_w" / str(width) / f"{Path(name).stem}.webp"
        if not out.is_file():
            from PIL import Image, ImageOps  # import diferido: solo quien sirve imágenes lo necesita

            out.parent.mkdir(parents=True, exist_ok=True)
            with Image.open(src) as original:
                img = ImageOps.exif_transpose(original)  # fotos de celular: respeta la orientación
                if img.width > width:
                    img.thumbnail((width, img.height * width // img.width + 1), Image.Resampling.LANCZOS)
                img = img.convert("RGBA" if img.mode in ("RGBA", "LA", "P") else "RGB")
                tmp = out.with_suffix(f".{uuid.uuid4().hex}.tmp")  # escritura atómica: peticiones simultáneas
                img.save(tmp, "WEBP", quality=80, method=4)
                tmp.replace(out)
        return out

    def path(self, name: str) -> Path | None:
        """Solo nombres generados por save(): sin rutas, sin ../ (evita leer archivos arbitrarios)."""
        if not NAME.fullmatch(name):
            return None
        file = self.dir / name
        return file if file.is_file() else None
