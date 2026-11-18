"""Retención de la analítica: borra lecturas y compartidos más viejos que N días (por defecto 25 meses,
así siempre se puede comparar un mes con el mismo mes del año anterior). Programar a diario (cron / Programador
de tareas):

    python -m app.modules.analytics.presentation.cli purge            # ANALYTICS_RETENTION_DAYS o 760
    python -m app.modules.analytics.presentation.cli purge --days 400
"""
import argparse
import os
from datetime import timedelta

import app.main  # noqa: F401  (inicia los mapeos)
from app.modules.analytics.domain.rules import local_day
from app.modules.analytics.infrastructure.repository import AnalyticsRepository
from app.shared.clock import now
from app.shared.database import SessionLocal


def purge(days: int) -> tuple[int, int]:
    if days < 30:
        raise SystemExit("La retención mínima es de 30 días")
    with SessionLocal() as s:
        return AnalyticsRepository(s).purge(local_day(now()) - timedelta(days=days))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("purge").add_argument("--days", type=int, default=int(os.getenv("ANALYTICS_RETENTION_DAYS", 760)))
    args = parser.parse_args()
    views, shares = purge(args.days)
    print(f"Eliminadas {views} lecturas y {shares} compartidos anteriores a {args.days} días")
