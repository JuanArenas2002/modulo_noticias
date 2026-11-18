import re

from sqlalchemy import exists, select, text
from sqlalchemy.orm import Session

from app.modules.news.domain.entities.catalogs import Category, NewsStatus, StatusTransition


class SqlAlchemyCatalogRepository:
    def __init__(self, session: Session):
        self.s = session

    def by_code(self, model, code: str):
        return self.s.scalar(select(model).where(model.code == code))

    def all(self, model) -> list:
        return list(self.s.scalars(select(model).order_by(model.id)).unique())

    def initial_status(self) -> NewsStatus:
        return self.s.scalars(select(NewsStatus).where(NewsStatus.is_initial.is_(True))).one()

    def transitions(self, action: str) -> list[StatusTransition]:
        return list(self.s.scalars(select(StatusTransition).where(StatusTransition.action == action)).unique())

    def category_exists(self, category_id: int) -> bool:
        return bool(self.s.scalar(select(exists().where(Category.id == category_id))))

    def add_category(self, category: Category) -> None:
        self.s.add(category)

    def reference_exists(self, table: str, ref_id: int) -> bool:
        # source_table viene del catálogo (BD), no del request; igual se valida el identificador.
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", table):
            raise ValueError(f"source_table inválido: {table}")
        return bool(self.s.scalar(text(f"SELECT 1 FROM {table} WHERE id = :id"), {"id": ref_id}))

    def commit(self) -> None:
        self.s.commit()
