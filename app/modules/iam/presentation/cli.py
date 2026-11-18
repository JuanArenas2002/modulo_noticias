"""Comandos de administración. Crear el administrador inicial (una sola vez):

    python -m app.modules.iam.presentation.cli create-admin --email admin@unisimon.edu.co --first Ana --last Pérez

La contraseña se pide por consola (o ADMIN_PASSWORD, p.ej. en un pipeline). Se niega si ya hay un super_admin
activo: después, los administradores se gestionan desde la API.
"""
import argparse
import getpass
import os
import sys

from sqlalchemy import select

import app.main  # noqa: F401  (inicia los mapeos)
from app.modules.iam.application.use_cases.authentication.common import check_password
from app.modules.iam.domain.entities.access import Role, RoleAssignment
from app.modules.iam.domain.entities.identity import PasswordCredential, User
from app.modules.iam.domain.services.audit_service import RequestMeta, event
from app.modules.iam.infrastructure.repositories.argon2_password_hasher import hasher
from app.modules.iam.infrastructure.repositories.sqlalchemy_iam_repositories import SqlAlchemyIamUnitOfWork
from app.shared.clock import now
from app.shared.config import settings
from app.shared.database import SessionLocal
from app.shared.exceptions import DomainError


def create_admin(email: str, first: str, last: str, password: str) -> int:
    with SessionLocal() as s:
        uow = SqlAlchemyIamUnitOfWork(s)
        role = s.scalars(select(Role).where(Role.code == "super_admin")).one()
        if s.scalar(select(RoleAssignment).where(RoleAssignment.role_id == role.id, RoleAssignment.revoked_at.is_(None))):
            raise DomainError("Ya existe un super_admin activo; usa la API para crear más administradores")
        if uow.users.by_email(email):
            raise DomainError("Ya existe un usuario con ese correo")
        at = now()
        user = User(first_name=first, last_name=last, email=email.strip().lower(), status=uow.users.status("active"),
                    account_type=uow.users.account_type("institutional"), email_verified_at=at,
                    created_at=at, updated_at=at)
        check_password(settings, password, user)
        user.password = PasswordCredential(password_hash=hasher.hash(password), password_changed_at=at)
        uow.users.add(user)
        s.add(RoleAssignment(user_id=user.id, role=role))  # alcance institucional
        uow.audit.add(event("iam.bootstrap.admin", "success", RequestMeta(ip="cli"), None, "user", user.id))
        uow.commit()
        return user.id


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="iam")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("create-admin", help="Crea el super_admin inicial")
    p.add_argument("--email", required=True)
    p.add_argument("--first", required=True)
    p.add_argument("--last", required=True)
    args = parser.parse_args(argv)
    password = os.getenv("ADMIN_PASSWORD") or getpass.getpass("Contraseña: ")
    try:
        user_id = create_admin(args.email, args.first, args.last, password)
    except DomainError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    print(f"super_admin creado (id={user_id})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
