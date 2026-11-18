"""privacidad: políticas versionadas, categorías de cookies, consentimientos y permiso privacy.manage.

Las categorías describen las tecnologías que el portal usa HOY (auditadas en el código). Los textos de las
políticas v1 son una base técnica: deben ser revisados por el responsable de protección de datos de la
Universidad antes de considerarse definitivos (se publican nuevas versiones con POST /api/admin/privacy/policies).

Revision ID: 0008
Revises: 0007
"""
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

Ts = sa.DateTime(timezone=True)
BigId = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
CODE = "privacy.manage"
ROLES = ("super_admin", "admin")
PENDING = ("<p><em>Versión inicial preparada por el equipo técnico del portal. Pendiente de revisión por el "
           "responsable de protección de datos personales de la Universidad.</em></p>")


def tech(name, type_, duration, provider, purpose):
    return {"name": name, "type": type_, "duration": duration, "provider": provider, "purpose": purpose}


OWN = "Universidad Simón Bolívar (propia)"
CATEGORIES = [
    ("necessary", "Necesarias",
     "Imprescindibles para que el portal funcione y para recordar tu decisión sobre cookies. No se pueden desactivar.",
     "Funcionamiento, seguridad e inicio de sesión del personal autorizado; guardar tu elección de privacidad.",
     [tech("cris_consent", "cookie", "12 meses", OWN, "Recordar tu decisión de privacidad (solo un identificador "
                                                      "aleatorio; no te identifica)."),
      tech("__Host-session / session", "cookie", "Hasta 12 horas", OWN,
           "Sesión del panel de administración (solo personal autorizado)."),
      tech("__Host-csrf / csrf_token", "cookie", "Hasta 12 horas", OWN,
           "Protección contra solicitudes falsificadas en el panel de administración."),
      tech("Estado del inicio de sesión con Microsoft", "cookie", "Minutos", OWN,
           "Completar de forma segura el inicio de sesión institucional."),
      tech("Tipografía del portal", "third_party", "Según el proveedor", "Google Fonts",
           "Mostrar la tipografía del portal. Al descargarla, Google recibe la dirección IP del navegador.")],
     "Mientras dure la sesión o la decisión (máximo 12 meses).", True, True, 1),
    ("functional", "Funcionales",
     "Recuerdan preferencias que eliges para no tener que repetirlas en cada visita.",
     "Recordar el idioma del portal (español, inglés o portugués).",
     [tech("cris-lang", "localStorage", "Hasta que la borres o revoques el permiso", OWN,
           "Recordar el idioma elegido.")],
     "Hasta que revoques el permiso o borres los datos del navegador.", False, True, 2),
    ("analytics", "Analíticas y estadísticas",
     "Miden de forma anónima cómo se leen las noticias para mejorar la calidad y relevancia de los contenidos "
     "institucionales. No se usan para publicidad ni para identificarte.",
     "Contar visualizaciones de noticias, estimar visitantes únicos, medir el tiempo de lectura activa, registrar "
     "interacciones y compartidos por canal, y conocer de forma general la procedencia del tráfico y el tipo de "
     "dispositivo, navegador y sistema operativo.",
     [tech("cris-news-session", "sessionStorage", "Hasta cerrar la pestaña", OWN,
           "Contar una sola lectura por pestaña y medir su tiempo activo."),
      tech("Seudónimo diario de visitante", "server", "Cambia cada día", OWN,
           "Estimar visitantes únicos sin guardar la dirección IP ni el navegador."),
      tech("Eventos de lectura", "server", "25 meses", OWN,
           "Visualizaciones, tiempo activo, compartidos, sitio de procedencia (solo el dominio) y tipo general de "
           "dispositivo, navegador y sistema operativo.")],
     "Los registros estadísticos se conservan 25 meses y luego se eliminan.", False, True, 3),
    ("advertising", "Publicidad y seguimiento",
     "El portal NO usa publicidad ni seguimiento entre sitios. Si algún día se usara, se te preguntaría antes.",
     "No aplica.", [], "No aplica.", False, False, 4),
]

POLICIES = {
    "cookie_policy": (
        "Política de cookies",
        "Qué cookies y tecnologías similares usa el portal, para qué, cuánto duran y cómo cambiar tu decisión.",
        "<h2>¿Qué son?</h2><p>Las cookies y tecnologías similares (almacenamiento del navegador) son pequeños datos "
        "que un sitio guarda en tu navegador. El portal también procesa en su servidor eventos estadísticos de "
        "lectura de noticias.</p>"
        "<h2>Categorías</h2><ul><li><strong>Necesarias:</strong> funcionamiento, seguridad y recordar tu decisión. "
        "Siempre activas.</li><li><strong>Funcionales:</strong> recordar el idioma. Solo con tu permiso.</li>"
        "<li><strong>Analíticas:</strong> estadísticas anónimas de lectura de noticias (visualizaciones, visitantes "
        "únicos estimados, tiempo de lectura activa, interacciones y compartidos). Solo con tu permiso.</li>"
        "<li><strong>Publicidad y seguimiento:</strong> no se usan.</li></ul>"
        "<p>El detalle de cada tecnología, su proveedor y su duración está en «Configuración de cookies y "
        "privacidad», al pie de todas las páginas, donde puedes aceptar, rechazar o cambiar tu decisión en "
        "cualquier momento. Tu decisión dura 12 meses; si cambian de forma sustancial las finalidades o "
        "tecnologías, te la pediremos de nuevo.</p>" + PENDING),
    "privacy_notice": (
        "Aviso de privacidad",
        "Quién es responsable del tratamiento, para qué se usan los datos, tus derechos y dónde consultar la política.",
        "<h2>Responsable del tratamiento</h2><p>Universidad Simón Bolívar, Barranquilla (Colombia). Los canales "
        "para consultas y reclamos son los indicados en su Política de Tratamiento de Datos Personales e "
        "Información.</p>"
        "<h2>Tratamiento y finalidad</h2><p>Con tu autorización, el portal registra estadísticas de lectura de "
        "noticias para analizar y mejorar los contenidos y servicios institucionales. No se guardan tu nombre, tu "
        "correo ni tu dirección IP en estas estadísticas.</p>"
        "<h2>Tus derechos (Ley 1581 de 2012, art. 8)</h2><p>Conocer, actualizar y rectificar tus datos; solicitar "
        "prueba de la autorización; ser informado sobre su uso; presentar quejas ante la Superintendencia de "
        "Industria y Comercio; revocar la autorización y solicitar la supresión; y acceder gratuitamente a tus "
        "datos.</p>"
        "<h2>Política de tratamiento</h2><p>Puedes consultarla en la sección de privacidad de este portal y en "
        "los canales oficiales de la Universidad.</p>" + PENDING),
    "privacy_policy": (
        "Política de privacidad del portal",
        "Cómo trata este portal la información de quienes lo visitan.",
        "<p>Este portal de investigación de la Universidad Simón Bolívar se rige por la Política de Tratamiento "
        "de Datos Personales e Información de la Universidad, adoptada conforme a la Ley 1581 de 2012 y sus "
        "decretos reglamentarios (compilados en el Decreto 1074 de 2015).</p>"
        "<h2>Qué información trata el portal</h2><ul><li>Para visitantes: estadísticas de lectura de noticias, "
        "solo si las autorizas (ver la Política de cookies).</li><li>Para el personal autorizado del panel: datos de "
        "su cuenta institucional y registros de auditoría de seguridad.</li></ul>"
        "<h2>Conservación</h2><p>Estadísticas de lectura: 25 meses. Decisiones de consentimiento: se conservan como "
        "prueba de la autorización.</p>"
        "<h2>Tu decisión</h2><p>Puedes cambiarla o revocarla cuando quieras desde «Configuración de cookies y "
        "privacidad», al pie de todas las páginas.</p>" + PENDING),
}


def upgrade() -> None:
    op.create_table(
        "privacy_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("effective_at", Ts, nullable=False),
        sa.Column("requires_reconsent", sa.Boolean(), nullable=False),
        sa.Column("created_at", Ts, nullable=False),
        sa.Column("created_by", sa.BigInteger(), sa.ForeignKey("users.id", name="fk_privacy_policy_creator")),
        sa.Column("updated_at", Ts, nullable=False),
        sa.UniqueConstraint("kind", "version", name="uq_privacy_policies_kind_version"),
        sa.CheckConstraint("kind IN ('privacy_policy', 'cookie_policy', 'privacy_notice')",
                           name="ck_privacy_policies_kind"),
    )
    categories = op.create_table(
        "privacy_cookie_categories",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(20), nullable=False, unique=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("technologies", sa.JSON(), nullable=False),
        sa.Column("retention", sa.Text(), nullable=False),
        sa.Column("is_required", sa.Boolean(), nullable=False),
        sa.Column("is_available", sa.Boolean(), nullable=False),
        sa.Column("sort", sa.Integer(), nullable=False),
        sa.Column("updated_at", Ts, nullable=False),
    )
    op.create_table(
        "privacy_consents",
        sa.Column("id", BigId, primary_key=True),
        sa.Column("subject_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.BigInteger(), sa.ForeignKey("users.id", name="fk_privacy_consent_user")),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("categories", sa.JSON(), nullable=False),
        sa.Column("method", sa.String(20), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("decided_at", Ts, nullable=False),
        sa.Column("expires_at", Ts, nullable=False),
        sa.CheckConstraint("method IN ('accept_all', 'reject_optional', 'custom', 'revoke')",
                           name="ck_privacy_consents_method"),
        sa.CheckConstraint("status IN ('active', 'superseded')", name="ck_privacy_consents_status"),
    )
    op.create_index("ix_privacy_consents_subject_status", "privacy_consents", ["subject_id", "status"])
    op.create_index("ix_privacy_consents_decided_at", "privacy_consents", ["decided_at"])

    at = datetime.now(UTC)
    op.bulk_insert(categories, [
        {"code": c, "name": n, "description": d, "purpose": p, "technologies": t, "retention": r,
         "is_required": req, "is_available": av, "sort": s, "updated_at": at}
        for c, n, d, p, t, r, req, av, s in CATEGORIES])
    policies = sa.table("privacy_policies", *(sa.column(c) for c in (
        "kind", "version", "title", "summary", "content", "effective_at", "requires_reconsent", "created_at",
        "updated_at")))
    op.bulk_insert(policies, [
        {"kind": k, "version": 1, "title": t, "summary": s, "content": c, "effective_at": at,
         "requires_reconsent": k == "cookie_policy", "created_at": at, "updated_at": at}
        for k, (t, s, c) in POLICIES.items()])

    bind = op.get_bind()
    bind.execute(sa.text("INSERT INTO permissions (code, name, module, resource, action, is_active) "
                         "VALUES (:c, 'Administrar políticas de privacidad y cookies', 'privacy', 'policies', "
                         "'manage', :a)"), {"c": CODE, "a": True})
    bind.execute(sa.text("INSERT INTO role_permissions (role_id, permission_id) "
                         "SELECT r.id, p.id FROM roles r, permissions p WHERE p.code = :c AND r.code IN :rs")
                 .bindparams(sa.bindparam("rs", expanding=True)), {"c": CODE, "rs": list(ROLES)})


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("DELETE FROM role_permissions WHERE permission_id = "
                         "(SELECT id FROM permissions WHERE code = :c)"), {"c": CODE})
    bind.execute(sa.text("DELETE FROM permissions WHERE code = :c"), {"c": CODE})
    op.drop_table("privacy_consents")
    op.drop_table("privacy_cookie_categories")
    op.drop_table("privacy_policies")
