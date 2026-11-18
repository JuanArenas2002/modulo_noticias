"""Cliente de solo lectura de la API de Metri-K (stdlib, sin dependencias)."""
import json
import os
from datetime import date, datetime
from urllib.request import Request, urlopen

from app.modules.organization.domain.entities.organization import AcademicProgram, Faculty, ResearchCenter

METRIK_API_URL = os.getenv("METRIK_API_URL", "https://metrik.unisimon.edu.co/back/api")
TIMEOUT_SECONDS = 20


def _date(value: str | None) -> date | None:
    return datetime.fromisoformat(value).date() if value else None


class MetrikOrganizationSource:
    def __init__(self, base_url: str = METRIK_API_URL):
        self.base_url = base_url.rstrip("/")

    def _get(self, path: str) -> list[dict]:
        req = Request(f"{self.base_url}/{path}", headers={"Accept": "application/json"})
        with urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return json.load(resp)["data"]

    def faculties(self) -> list[Faculty]:
        return [Faculty(id=f["id"], name=f["name"].strip()) for f in self._get("faculty")]

    def centers(self) -> list[ResearchCenter]:
        return [
            ResearchCenter(id=c["id"], code=c.get("code"), name=c["name"].strip(), acronym=c.get("acronym"),
                           is_active=bool(c.get("state")), date_created=_date(c.get("date_created")),
                           date_closed=_date(c.get("date_closed")))
            for c in self._get("center")
            if c["id"] > 0  # Metri-K trae un registro comodín id=0 "N/A"
        ]

    def programs(self, faculty_id: int) -> list[AcademicProgram]:
        return [
            AcademicProgram(id=p["id"], name=p["name"].strip(), faculty_id=p["facultyId"],
                            code_snies=p.get("code_snies"), level_academic=p.get("level_academic"),
                            level_education=p.get("level_education"), modality=p.get("modality"),
                            is_active=bool(p.get("state")))
            for p in self._get(f"program/faculty/{faculty_id}")
        ]
