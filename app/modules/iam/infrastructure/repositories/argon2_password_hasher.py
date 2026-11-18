"""Argon2id (argon2-cffi). Parámetros por defecto de la librería = RFC 9106 perfil de baja memoria."""
from argon2 import PasswordHasher as _Argon2
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.shared.security import new_token


class Argon2PasswordHasher:
    def __init__(self):
        self._h = _Argon2()  # type = Argon2id
        self._dummy = self._h.hash(new_token())

    def hash(self, password: str) -> str:
        return self._h.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._h.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        return self._h.check_needs_rehash(password_hash)

    def burn(self, password: str) -> None:
        self.verify(self._dummy, password)


hasher = Argon2PasswordHasher()  # el hash ficticio cuesta ~50 ms: una vez por proceso
