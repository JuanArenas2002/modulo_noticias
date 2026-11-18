from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.modules.organization.domain.entities.organization import AcademicProgram, Faculty, ResearchCenter


class SqlAlchemyOrganizationRepository:
    def __init__(self, session: Session):
        self.s = session

    def upsert(self, items: list) -> None:
        for item in items:
            self.s.merge(item)
        self.s.flush()  # en orden: facultades antes que programas (FK)

    def deactivate_missing(self, model: type, keep_ids: set[int]) -> int:
        stmt = update(model).where(model.id.not_in(keep_ids), model.is_active.is_(True)).values(is_active=False)
        return self.s.execute(stmt, execution_options={"synchronize_session": False}).rowcount

    def _list(self, model, only_active: bool, *where):
        stmt = select(model).where(*where).order_by(model.name)
        if only_active:
            stmt = stmt.where(model.is_active.is_(True))
        return list(self.s.scalars(stmt))

    def faculties(self, only_active: bool) -> list[Faculty]:
        return self._list(Faculty, only_active)

    def centers(self, only_active: bool) -> list[ResearchCenter]:
        return self._list(ResearchCenter, only_active)

    def programs(self, faculty_id: int | None, only_active: bool) -> list[AcademicProgram]:
        where = [AcademicProgram.faculty_id == faculty_id] if faculty_id else []
        return self._list(AcademicProgram, only_active, *where)

    def commit(self) -> None:
        self.s.commit()
