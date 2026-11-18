# Casos de uso por rol y permiso

Fuente: los permisos que el backend realmente exige en `app/modules/*/application/use_cases`, más los roles
iniciales de las migraciones `0003` y `0006`. Los roles se pueden reconfigurar por API: si cambian sus permisos,
la matriz cambia, pero cada caso de uso sigue exigiendo el mismo **permiso**.

## Diagramas (PlantUML)

| Archivo | Actor |
|---|---|
| [01_visitante.puml](01_visitante.puml) | Visitante (sin sesión) |
| [02_usuario.puml](02_usuario.puml) | Usuario autenticado (rol `user`, sin permisos) |
| [03_consulta.puml](03_consulta.puml) | Consulta (`viewer`) |
| [04_editor.puml](04_editor.puml) | Editor (`editor`) |
| [05_centro_investigacion.puml](05_centro_investigacion.puml) | Centro de investigación (`research_center`, con alcance) |
| [06_revisor.puml](06_revisor.puml) | Revisor (`reviewer`) |
| [07_publicador.puml](07_publicador.puml) | Publicador (`publisher`) |
| [08_administrador.puml](08_administrador.puml) | Administrador (`admin`) |
| [09_super_administrador.puml](09_super_administrador.puml) | Super administrador (`super_admin`) |
| [10_flujo_editorial.puml](10_flujo_editorial.puml) | Estados de una noticia y el permiso de cada transición |

Para generar las imágenes, usa la extensión **PlantUML** de VS Code (Alt+D para previsualizar, o
"Export Current Diagram"), o ejecuta `java -jar plantuml.jar -tpng uses_case/*.puml`. Todos incluyen
`_estilo.iuml`, que debe quedar en la misma carpeta.

## Catálogo

| CU | Caso de uso | Permiso exigido | Alcance |
|---|---|---|---|
| CU-01 | Consultar noticias publicadas (listado, destacadas, detalle) | — | público |
| CU-02 | Consultar catálogos y estructura organizacional | — | público |
| CU-03 | Iniciar sesión con correo y contraseña | — | público |
| CU-04 | Iniciar sesión con Microsoft | — | público |
| CU-05 | Recuperar contraseña por correo | — | público (depende del correo) |
| CU-07 | Cambiar contraseña temporal (obligatorio en el primer ingreso) | sesión | propio |
| CU-08 | Cambiar mi contraseña | sesión | propio |
| CU-09 | Ver mi perfil y mis permisos efectivos | sesión | propio |
| CU-10 | Ver y cerrar mis sesiones | sesión | propio |
| CU-11 | Renovar / cerrar sesión | sesión | propio |
| CU-12 | Ver noticias internas e historial | `news.view` | alguna dependencia de la noticia |
| CU-13 | Crear noticia (borrador) | `news.create` | todas sus dependencias |
| CU-14 | Editar noticia en borrador/rechazada y subir imágenes | `news.update` | todas sus dependencias |
| CU-15 | Enviar a revisión | `news.submit` | todas sus dependencias |
| CU-16 | Rechazar con motivo | `news.review` | todas sus dependencias |
| CU-17 | Aprobar | `news.approve` | todas sus dependencias |
| CU-18 | Publicar o programar | `news.publish` | todas sus dependencias |
| CU-19 | Archivar | `news.archive` | todas sus dependencias |
| CU-20 | Curar publicada (destacar, fijar, prioridad, relevancia, vigencia, etiquetas) | `news.curate` | todas sus dependencias |
| CU-21 | Crear categorías | `news.manage_categories` | institucional |
| CU-22 | Sincronizar dependencias desde Metri-K | `organization.sync` | institucional |
| CU-23 | Listar y consultar usuarios (roles, permisos efectivos) | `users.view` | — |
| CU-24 | Crear usuario con contraseña temporal | `users.create` | institucional |
| CU-25 | Editar datos del usuario | `users.update` | institucional |
| CU-26 | Fijar contraseña temporal (olvido) | `users.update` | institucional |
| CU-27 | Activar, desactivar, bloquear y desbloquear usuario | `users.update` | institucional |
| CU-28 | Vincular / desvincular cuenta Microsoft | `users.update` | institucional |
| CU-29 | Eliminar usuario (lógico) | `users.delete` | institucional |
| CU-30 | Asignar y revocar roles | `users.manage_roles` + cada permiso del rol | el del rol asignado |
| CU-31 | Ver y revocar sesiones de otros | `users.manage_sessions` | institucional |
| CU-32 | Consultar roles | `roles.view` (o `users.manage_roles`) | — |
| CU-33 | Crear, editar y eliminar roles y sus permisos | `roles.manage` | institucional |
| CU-34 | Consultar permisos | `permissions.view` (o `roles.manage`) | — |
| CU-35 | Crear y modificar el catálogo de permisos | `permissions.manage` | institucional |
| CU-36 | Consultar auditoría y actividad de un usuario | `audit.view` | institucional |

## Matriz rol × caso de uso

Todos los roles autenticados tienen además CU-01..CU-11.

| CU | Consulta | Editor | Centro inv. | Revisor | Publicador | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| CU-12 Ver internas | ✔ | ✔ | ✔ (su centro) | ✔ | ✔ | ✔ | ✔ |
| CU-13 Crear | | ✔ | ✔ (su centro) | | | ✔ | ✔ |
| CU-14 Editar | | ✔ | ✔ (su centro) | | | ✔ | ✔ |
| CU-15 Enviar a revisión | | ✔ | ✔ (su centro) | | | ✔ | ✔ |
| CU-16 Rechazar | | | | ✔ | | ✔ | ✔ |
| CU-17 Aprobar | | | | ✔ | | ✔ | ✔ |
| CU-18 Publicar / programar | | | | | ✔ | ✔ | ✔ |
| CU-19 Archivar | | | | | ✔ | ✔ | ✔ |
| CU-20 Curar | | | | | ✔ | ✔ | ✔ |
| CU-21 Categorías | | | | | | ✔ | ✔ |
| CU-22 Sincronizar Metri-K | | | | | | ✔ | ✔ |
| CU-23..CU-31 Usuarios | | | | | | ✔ | ✔ |
| CU-32..CU-34 Roles y permisos (consultar/gestionar roles) | | | | | | ✔ | ✔ |
| CU-35 Catálogo de permisos | | | | | | | ✔ |
| CU-36 Auditoría | | | | | | ✔ | ✔ |

## Reglas transversales

- **Contraseña temporal**: mientras no se cambie (CU-07), el backend responde 403 en todo salvo `/me`, cambio de
  clave y cierre de sesión.
- **Alcance**: un rol asignado con alcance (p. ej. un centro) solo vale para noticias asociadas a esa dependencia
  o sus hijas; sin alcance es institucional. Ver una noticia interna basta con una dependencia; cambiarla exige todas.
  Una noticia que no se puede ver responde 404.
- **Anti-escalamiento**: nadie asigna un rol con permisos que no tiene en ese alcance, ni modifica a un usuario
  con más permisos que él. Nadie se fija la contraseña a sí mismo por CU-26 (usa CU-08).
- **Último propietario**: siempre debe quedar al menos un usuario activo con `permissions.manage`.
- **Auditoría**: los CU-13..CU-36 dejan registro (historial de la noticia o `audit_log`); nunca se guardan contraseñas.

Heredado y fuera de los diagramas: activar cuenta por invitación (`/auth/register`) y reenviar invitación
(`users.create`). Siguen en el backend, pero el panel ya no los usa porque los correos no llegan.
