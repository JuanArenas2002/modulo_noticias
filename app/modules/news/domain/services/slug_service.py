import re
import unicodedata
from collections.abc import Callable


def slugify(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:250] or "noticia"


def unique_slug(text: str, exists: Callable[[str], bool]) -> str:
    base = slug = slugify(text)
    n = 1
    while exists(slug):
        n += 1
        slug = f"{base}-{n}"
    return slug
