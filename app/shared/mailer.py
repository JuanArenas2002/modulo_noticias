"""Envío de correo con smtplib (sin dependencias). En desarrollo, a consola."""
import logging
import smtplib
from email.message import EmailMessage
from typing import Protocol

from app.shared.config import Settings, settings

log = logging.getLogger("mailer")


class Mailer(Protocol):
    def send(self, to: str, subject: str, body: str) -> None: ...


class ConsoleMailer:
    """Solo desarrollo (la configuración lo impide en staging/production): imprime el correo."""

    def send(self, to: str, subject: str, body: str) -> None:
        log.warning("[correo de desarrollo] para=%s asunto=%s\n%s", to, subject, body)


class SmtpMailer:
    def __init__(self, cfg: Settings):
        self.cfg = cfg

    def send(self, to: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.cfg.smtp_from or self.cfg.smtp_user, to, subject
        msg.set_content(body)
        with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port, timeout=15) as smtp:
            if self.cfg.smtp_starttls:
                smtp.starttls()
            if self.cfg.smtp_user:
                smtp.login(self.cfg.smtp_user, self.cfg.smtp_password or "")
            smtp.send_message(msg)


def get_mailer() -> Mailer:  # dependencia FastAPI; se sobreescribe en pruebas
    return SmtpMailer(settings) if settings.mail_backend == "smtp" else ConsoleMailer()
