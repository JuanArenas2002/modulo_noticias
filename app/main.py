from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.modules.analytics.presentation import routes as analytics_routes
from app.modules.privacy.presentation import routes as privacy_routes

from app.modules.iam.infrastructure.persistence.mapping import start_mappers as start_iam_mappers
from app.modules.iam.presentation.routes import admin_routes, auth_routes
from app.modules.news.infrastructure.persistence.mapping import start_mappers
from app.modules.news.presentation.routes import catalog_routes, news_routes
from app.modules.organization.infrastructure.persistence.mapping import start_mappers as start_org_mappers
from app.modules.organization.presentation.routes import organization_routes
from app.shared.config import settings
from app.shared.exceptions import register_exception_handlers

# Esquema y catálogos: `alembic upgrade head` (paso de despliegue explícito; la app no migra sola).
start_mappers()
start_org_mappers()
start_iam_mappers()

app = FastAPI(title="Noticias institucionales")
register_exception_handlers(app)
if settings.cors_origins:  # sin lista explícita no se habilita CORS (mismo origen en producción)
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_credentials=True,
                       allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                       allow_headers=["Content-Type", "X-CSRF-Token"])
app.include_router(auth_routes.router)
app.include_router(admin_routes.router)
app.include_router(analytics_routes.router)  # antes que news: /analytics/... no debe caer en /{ref}
app.include_router(catalog_routes.router)  # antes que news: /catalogs no debe caer en /{ref}
app.include_router(news_routes.router)
app.include_router(news_routes.media_router)
app.include_router(organization_routes.router)
app.include_router(privacy_routes.router)
