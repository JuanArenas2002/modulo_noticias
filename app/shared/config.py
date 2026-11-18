"""Configuración por variables de entorno. Ningún secreto en código.

ENVIRONMENT = development | staging | production. En staging/production se exigen valores seguros
y la app no arranca si faltan (fallar temprano es mejor que arrancar insegura).
"""
import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: str) -> None:
    """Lee KEY=VALUE de un archivo .env. Nunca pisa variables ya definidas en el entorno (estas mandan)."""
    file = Path(path)
    if not path or not file.is_file():
        return
    for line in file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(os.getenv("DOTENV_PATH", ".env"))  # las pruebas lo desactivan con DOTENV_PATH=""


def _str(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    return value if value not in (None, "") else default


def _int(name: str, default: int) -> int:
    return int(_str(name, str(default)))


def _bool(name: str, default: bool) -> bool:
    return _str(name, str(default)).lower() in ("1", "true", "yes", "on")


def _list(name: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in (_str(name, "") or "").split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    environment: str
    secret_key: str
    frontend_url: str
    frontend_login_path: str  # pantalla de login del frontend (destino de los errores de Microsoft)
    cors_origins: tuple[str, ...]
    media_dir: str          # imágenes subidas (debe persistir entre despliegues)
    max_image_mb: int
    # Cookies / sesión
    session_cookie_name: str
    csrf_cookie_name: str
    cookie_secure: bool
    cookie_domain: str | None
    cookie_samesite: str
    session_idle_minutes: int
    session_absolute_hours: int
    # Contraseñas y fuerza bruta
    password_min_length: int
    password_max_length: int
    login_max_failures: int
    login_lock_minutes: int
    rate_limit_window_minutes: int
    rate_limit_per_ip: int
    # Tokens de un solo uso
    reset_token_minutes: int
    invitation_token_hours: int
    verify_token_hours: int
    # Correo
    mail_backend: str  # console | smtp
    smtp_host: str | None
    smtp_port: int
    smtp_user: str | None
    smtp_password: str | None
    smtp_from: str | None
    smtp_starttls: bool
    # Microsoft Entra ID
    microsoft_client_id: str | None
    microsoft_client_secret: str | None
    microsoft_tenant_id: str | None
    microsoft_authority: str | None
    microsoft_redirect_uri: str | None
    microsoft_post_logout_redirect_uri: str | None
    microsoft_allowed_tenants: tuple[str, ...]  # vacío = solo microsoft_tenant_id
    microsoft_auto_provision: bool              # crear usuario básico al primer login institucional

    @property
    def is_production_like(self) -> bool:
        return self.environment in ("staging", "production")

    @property
    def microsoft_enabled(self) -> bool:
        return bool(self.microsoft_client_id and self.microsoft_client_secret and self.microsoft_tenant_id
                    and self.microsoft_redirect_uri)

    @property
    def tenants(self) -> tuple[str, ...]:
        return self.microsoft_allowed_tenants or ((self.microsoft_tenant_id,) if self.microsoft_tenant_id else ())


def load_settings() -> Settings:
    env = _str("ENVIRONMENT", "development")
    prod = env in ("staging", "production")
    tenant = _str("MICROSOFT_TENANT_ID")
    s = Settings(
        environment=env,
        # Dev sin SECRET_KEY: clave aleatoria por proceso (las cookies de estado no sobreviven un reinicio).
        secret_key=_str("SECRET_KEY") or ("" if prod else secrets.token_urlsafe(48)),
        frontend_url=_str("FRONTEND_URL", "http://localhost:5173").rstrip("/"),
        frontend_login_path="/" + _str("FRONTEND_LOGIN_PATH", "/login").strip("/"),
        cors_origins=_list("CORS_ORIGINS"),
        media_dir=_str("MEDIA_DIR", "data/media"),
        max_image_mb=_int("MAX_IMAGE_MB", 5),
        # __Host- obliga a Secure + Path=/ + sin Domain: la cookie no se puede pisar desde subdominios.
        session_cookie_name=_str("SESSION_COOKIE_NAME", "__Host-session" if prod else "session"),
        csrf_cookie_name=_str("CSRF_COOKIE_NAME", "__Host-csrf" if prod else "csrf_token"),
        cookie_secure=_bool("COOKIE_SECURE", prod),
        cookie_domain=_str("COOKIE_DOMAIN"),
        cookie_samesite=_str("COOKIE_SAMESITE", "lax"),
        session_idle_minutes=_int("SESSION_IDLE_MINUTES", 60),
        session_absolute_hours=_int("SESSION_ABSOLUTE_HOURS", 12),
        password_min_length=_int("PASSWORD_MIN_LENGTH", 12),
        password_max_length=_int("PASSWORD_MAX_LENGTH", 128),
        login_max_failures=_int("LOGIN_MAX_FAILURES", 5),
        login_lock_minutes=_int("LOGIN_LOCK_MINUTES", 15),
        rate_limit_window_minutes=_int("RATE_LIMIT_WINDOW_MINUTES", 15),
        rate_limit_per_ip=_int("RATE_LIMIT_PER_IP", 30),
        reset_token_minutes=_int("RESET_TOKEN_MINUTES", 30),
        invitation_token_hours=_int("INVITATION_TOKEN_HOURS", 72),
        verify_token_hours=_int("VERIFY_TOKEN_HOURS", 24),
        mail_backend=_str("MAIL_BACKEND", "smtp" if prod else "console"),
        smtp_host=_str("SMTP_HOST"),
        smtp_port=_int("SMTP_PORT", 587),
        smtp_user=_str("SMTP_USER"),
        smtp_password=_str("SMTP_PASSWORD"),
        smtp_from=_str("SMTP_FROM"),
        smtp_starttls=_bool("SMTP_STARTTLS", True),
        microsoft_client_id=_str("MICROSOFT_CLIENT_ID"),
        microsoft_client_secret=_str("MICROSOFT_CLIENT_SECRET"),
        microsoft_tenant_id=tenant,
        microsoft_authority=_str("MICROSOFT_AUTHORITY",
                                 f"https://login.microsoftonline.com/{tenant}" if tenant else None),
        microsoft_redirect_uri=_str("MICROSOFT_REDIRECT_URI"),
        microsoft_post_logout_redirect_uri=_str("MICROSOFT_POST_LOGOUT_REDIRECT_URI"),
        microsoft_allowed_tenants=_list("MICROSOFT_ALLOWED_TENANTS"),
        microsoft_auto_provision=_bool("MICROSOFT_AUTO_PROVISION", False),
    )
    if s.is_production_like:
        problems = [msg for bad, msg in (
            (len(s.secret_key) < 32, "SECRET_KEY debe tener al menos 32 caracteres"),
            (not s.cookie_secure, "COOKIE_SECURE debe ser true"),
            (s.mail_backend != "smtp" or not s.smtp_host, "MAIL_BACKEND=smtp y SMTP_HOST son obligatorios"),
            (not s.frontend_url.startswith("https://"), "FRONTEND_URL debe ser https"),
        ) if bad]
        if problems:
            raise RuntimeError("Configuración insegura para " + env + ": " + "; ".join(problems))
    return s


settings = load_settings()
