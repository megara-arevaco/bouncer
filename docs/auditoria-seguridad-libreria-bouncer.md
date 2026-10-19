# Auditoría de seguridad de la librería Bouncer

**Fecha:** 18 de octubre de 2026

**Alcance:** revisión del código de `bouncer` y pruebas locales. No incluye pentest externo, pruebas de carga ni validación de una aplicación consumidora desplegada.

## Resumen

Bouncer es una librería TypeScript basada en Better Auth 1.7.10, con paquetes API y React. Admite credenciales de email/usuario y contraseña, magic links, passkeys, proveedores sociales opcionales, TOTP y códigos de recuperación. Persiste usuarios, cuentas, verificaciones, sesiones y límites de abuso en SQLite o PostgreSQL. No configura sesiones JWT.

Better Auth aporta el motor y los flujos estándar. Bouncer añade políticas y límites por aplicación, aislamiento de tablas/cookies, migraciones defensivas, una interfaz de capacidades y componentes React. Una aplicación que no necesite estas decisiones ni la interfaz puede usar Better Auth directamente.

En esta implementación se corrigieron los hallazgos confirmados en sesiones, restablecimientos, abuso de correo, política de contraseñas, rehash progresivo, cifrado OAuth y revocación administrativa. Las migraciones protegen datos existentes, pero una actualización debe desplegarse de forma coordinada: instancias antiguas no entienden las nuevas representaciones de sesiones y verificaciones. La biblioteca no queda certificada para producción; aún dependen del consumidor la autorización de recursos, el proxy confiable, TLS, correo, CORS y las páginas de callback.

## Arquitectura y controles existentes

- `packages/api/src/index.ts` crea Bouncer sobre Better Auth y plugins de username, magic link, passkey y 2FA; los métodos se pueden habilitar por configuración. El enlace automático de cuentas está desactivado.
- SQLite y PostgreSQL comparten la API de persistencia. El limitador personalizado guarda contadores en la base de datos; Better Auth también usa almacenamiento persistente para rate limits.
- Las contraseñas nuevas se guardan como Argon2id con salt CSPRNG independiente de 16 bytes, 19 MiB, dos pasadas y paralelismo 1 por defecto; los parámetros se validan y configuran. Se conservan verificadores para hashes Argon2id v1 y scrypt, con rehash progresivo después de un login correcto.
- La política por defecto exige 15 puntos de código Unicode, permite configurar un mínimo entre 12 y 128 por compatibilidad y rechaza más de 128 puntos de código o 1024 bytes UTF-8. La comprobación de contraseñas comprometidas usa una lista local acotada o HIBP; en producción HIBP es el valor por defecto y falla de forma cerrada.
- Los magic links se guardan con hash, usan tokens aleatorios generados por Better Auth y caducan en 300 segundos por defecto, configurables entre 60 y 900 segundos.
- Las sesiones se persisten con un HMAC-SHA-256 del token bearer en la base de datos. La migración convierte sesiones existentes. Los endpoints y métodos públicos eliminan tokens de sus respuestas, y la revocación de otras sesiones acepta el ID tras reautenticación. El wrapper aplica caducidad absoluta de siete días, inactividad de doce horas y revoca sesiones de usuarios deshabilitados.
- Las cookies son HttpOnly y SameSite=Lax por defecto; en HTTPS son Secure y, con `Path=/`, usan prefijo `__Host-`. No se configura `Domain`.
- Los límites combinan Better Auth (5/minuto para login y alta, 3/minuto para reset, además del límite general) con una cuota persistente por tipo y destinatario de correo: 2/minuto y 8/hora. Login añade 20 intentos por combinación seudonimizada de IP e identidad cada 15 minutos.
- La verificación de correo está habilitada por defecto para contraseña. El registro puede deshabilitarse también para magic link y OAuth.

## Cambios realizados

- El GET del enlace mágico muestra una página de confirmación segura y no consume el token. El token viaja en el fragmento de URL, que no se envía en la petición HTTP; un POST same-origin realiza el intercambio. Se limita el cuerpo y se aplican CSP con nonce, `Cache-Control: no-store` y `Referrer-Policy: no-referrer`.
- El `auth.handler` expuesto pasa por el handler de Bouncer, por lo que no permite saltarse los límites, validaciones y cabeceras del wrapper.
- Se añadieron límites de tamaño para URL, cuerpos, email, token y contraseña. `hashPassword` y `verifyPassword` rechazan contraseñas que superan 1024 bytes antes de ejecutar derivaciones costosas.
- Las respuestas de autenticación reciben cabeceras defensivas; las acciones sensibles requieren autenticación reciente y la reautenticación tiene límites propios.
- Un fallo del proveedor de correo durante una solicitud de restablecimiento ya no produce una respuesta distinguible para cuentas existentes y desconocidas. Los errores internos de envío tampoco se propagan con datos del proveedor.
- El token de sesión se guarda como HMAC-SHA-256, se elimina de respuestas públicas y las sesiones se revocan por ID tras reautenticación. Las sesiones existentes se migran antes de aceptar tráfico.
- Cambio observable de API: `getSession().session.token` y los campos `token` de respuestas auth desaparecen; los consumidores deben usar cookie HttpOnly y el ID público de sesión. El panel React ya revoca por ID.
- Better Auth almacena los identificadores de verificación con SHA-256. La migración transforma filas heredadas de reset/verification y los tokens OAuth heredados a la representación cifrada que usa Better Auth; nuevos tokens OAuth también se cifran.
- El mínimo de contraseña por defecto sube a 15; Argon2id acepta parámetros configurables dentro de límites, mantiene lectura heredada y rehashea gradualmente después del login. Se añadió cuota persistente por destinatario y login por IP + identidad.
- `admin.setPassword` actualiza el hash y revoca sesiones dentro de una transacción. El flujo de cambio nativo de Better Auth también usa transacción y valida la contraseña actual.
- Se añadió cobertura para escáneres, replay, consumos concurrentes, tokens almacenados, OAuth legacy, rehash, revocación por ID, cambio administrativo de contraseña, inputs grandes, expiración, reautenticación y fallo de entrega de reset.

## Hallazgos

| Hallazgo | Severidad | Archivo / función | Estado y riesgo residual |
| --- | --- | --- | --- |
| Token bearer de sesión en claro en almacenamiento/respuestas | **High, confirmado; corregido** | `packages/api/src/session-token-adapter.ts`, `security-store.ts`, `index.ts`; `packages/react/src/account-panel.tsx` | La base ya guarda HMAC-SHA-256 del token. Las respuestas públicas eliminan `token`; la revocación por ID requiere reautenticación. Migración conserva sesiones al actualizar en una sola versión. |
| Token de reset incluido en el identificador de verificación almacenado | **Medium, confirmado; corregido** | `verification.storeIdentifier` en `index.ts`; migración de `security-store.ts` | Better Auth ahora hashea identificadores y la migración transforma los identificadores existentes. Los tokens siguen siendo bearer durante su vida útil, así que el acceso a DB debe restringirse. |
| Cuota de correo por destinatario ausente | **Medium, confirmado; mitigado** | `deliver` en `packages/api/src/index.ts`; `security-store.ts` | Se aplican 2 envíos/minuto y 8/hora por tipo y destinatario con claves HMAC. Esto reduce spam/coste, pero un atacante puede agotar el cupo y retrasar correos legítimos; el límite por IP de Better Auth también sigue activo. |
| Login limita por identidad y permite bloqueo dirigido | **Medium, confirmado; mitigado parcialmente** | Hook `before` de login en `packages/api/src/index.ts` | El límite personalizado se combina por IP e identidad (20/15 min), evitando que una IP agote el cupo global de una víctima. Better Auth mantiene 5/minuto por IP; credential stuffing distribuido requiere detección adicional. |
| Mínimo por defecto de 12 caracteres | **Medium, confirmado; corregido con opción de compatibilidad** | `minPasswordLength` en `packages/api/src/index.ts` | El valor por defecto es 15 según NIST para contraseña como único factor; se mantiene la configuración explícita de 12–128 para consumidores que necesiten una transición. |
| `admin.setPassword` no revocaba sesiones atómicamente | **Medium, confirmado; corregido** | `admin.setPassword` en `packages/api/src/index.ts` | Actualización y revocación ocurren dentro de la transacción del adapter. La prueba funcional usa SQLite; PostgreSQL aún requiere ejecución de integración. |
| Hashes scrypt antiguos no se actualizaban | **Low, confirmado; corregido** | `passwords.ts`; hook posterior al login en `index.ts` | Tras login válido, los hashes legacy scrypt y Argon2id v1 o con parámetros antiguos se reemplazan por Argon2id actual. Un fallo de rehash no bloquea el login y se reintenta después. |
| Tokens OAuth sin cifrado y persistencia legacy en claro | **Medium, condicional; corregido con caveat de secreto** | `account.encryptOAuthTokens` y migración de `security-store.ts` | Nuevas escrituras y valores heredados usan el cifrado de Better Auth. Cambiar el secreto sin una estrategia compatible puede impedir descifrar tokens ya guardados; conservarlo y planificar su rotación. |
| Páginas consumidoras pueden volver a exponer tokens | **Medium, riesgo de integración vigente** | Aplicación anfitriona; callback/reset propios | Los callbacks pueden incluir credenciales en URL o analytics incluso con cabeceras de Bouncer. Aplicar `no-store`/`no-referrer`, limpiar URL y no cargar terceros en páginas sensibles. |
| Proxy, CORS y autorización de recursos dependen del consumidor | **Medium, riesgo de integración vigente** | `createBouncer`, `trustedOrigins`, `ipAddress` y servidor anfitrión | Cabeceras falsificadas y CORS abierto debilitan controles. El consumidor debe confiar solo en proxy que sobrescribe cabeceras, restringir origen/backend y autorizar cada recurso. |
| Compatibilidad durante despliegue mixto de la migración | **Medium, riesgo operacional** | `Bouncer.migrate`; `security-store.ts` | Instancias antiguas no reconocen hashes nuevos de sesiones/verificaciones. Desplegar con instancias antiguas activas puede cerrar sesiones o interrumpir flujos. Ejecutar respaldo, migración y reemplazo coordinado antes de volver a aceptar tráfico. |

## Flujos revisados y riesgos de transición

- **Registro y login con contraseña:** Better Auth devuelve el mismo error para usuario inexistente y contraseña incorrecta; el registro evita enumeración cuando la verificación de email es obligatoria. Bouncer valida longitud y contraseñas comprometidas. Un login correcto de una cuenta no verificada tiene un estado distinto, pero para observarlo se requiere conocer la contraseña.
- **Solicitud y consumo de magic link:** el GET sirve una confirmación sin consumir el token. Un POST same-origin confirma el acceso; el consumo de verificación de Better Auth es atómico y de un solo uso. Se probaron replay y dos consumos concurrentes en SQLite. PostgreSQL aún requiere integración.
- **Magic link en cuenta con contraseña:** el enlace autentica por posesión del email verificado; el enlace automático de proveedores sociales está desactivado. El correo debe considerarse una credencial.
- **Reset de contraseña:** la respuesta se mantiene genérica para cuentas existentes/desconocidas y para fallo de entrega. El token de reset se identifica con SHA-256 en la base, expira y se consume una vez; se revocan sesiones al terminar.
- **Cambio de contraseña/email:** cambio de contraseña valida la actual y revoca otras sesiones cuando se solicita; el flujo de reset requiere el enlace de correo. Las operaciones sensibles que no validan por sí mismas una credencial exigen reautenticación reciente.
- **Logout y sesiones:** los endpoints de revocación invalidan registros persistentes. Bouncer aplica inactividad de doce horas, vida máxima de siete días y revoca sesiones de usuarios deshabilitados. Cambiar el secreto invalida hashes de sesión y puede impedir descifrar tokens OAuth.
- **Consumo concurrente y vinculación:** el consumo de magic link es atómico en Better Auth; la importación de usuario/cuenta usa transacción y el enlace automático está deshabilitado. Se requiere ejecutar las mismas pruebas sobre PostgreSQL y fallos de adapter.

## Verificación ejecutada

- `npm run typecheck`: correcto.
- `npm test`: correcto, 17/17.
- `npm run build`: correcto para los paquetes API y React y el playground.
- `npm run test:e2e`: correcto, 3/3 pruebas de navegador.
- `npm audit --omit=dev`: 0 vulnerabilidades conocidas en dependencias de producción según el registro consultado.
- `git diff --check`: correcto.
- `npm run docs:check`: correcto, 11 diagramas Mermaid renderizados.
- No hay script de lint en el proyecto.
- Las pruebas de esta auditoría usan SQLite. No se afirma verificación de PostgreSQL.

## Plan priorizado

1. **P0:** no se encontró un bypass crítico confirmado en los flujos revisados. Mantener el playground excluido de producción.
2. **P1:** ejecutar integración y concurrencia con PostgreSQL; desplegar de manera coordinada la migración de tokens porque instancias antiguas no leen las representaciones nuevas.
3. **P2:** valorar el agotamiento de la cuota por destinatario, probar fallos parciales y acordar rotación del secreto; calibrar Argon2id con la latencia y concurrencia reales.
4. **P3:** añadir protección/detección para credential stuffing distribuido, instrumentación sin secretos y revisión periódica de Better Auth/Node/dependencias.

Dependencias: hacer respaldo antes de migrar; completar la migración y sustituir todas las instancias antiguas antes de aceptar tráfico. Mantener estable el secreto mientras existan sesiones o tokens OAuth cifrados con él. No se ejecutó una migración sobre datos productivos.

## Checklist de controles

Estados: **Implementado**, **Parcial**, **Pendiente**, **No aplica**. “Parcial” identifica controles que dependen de producción, un adapter no probado o de la aplicación consumidora.

### Contraseñas

- **Parcial:** Argon2id con parámetros v2 configurables y validados (19 MiB, 2 pasadas, paralelismo 1 por defecto); falta calibración automática por hardware/despliegue.
- **Implementado:** salt CSPRNG individual de 16 bytes; no se almacena la contraseña en claro ni se usa SHA-256 para guardar contraseñas.
- **Implementado:** verificación con comparación constante para Argon2id y soporte de scrypt legacy; se rehashea progresivamente tras login correcto.
- **Implementado:** entradas Unicode largas, sin truncamiento, máximo 128 puntos de código y 1024 bytes UTF-8.
- **Implementado:** no hay reglas arbitrarias de mayúscula/número/símbolo; lista local de comprometidas y comprobación HIBP configurable, con HIBP por defecto en producción.
- **Parcial:** errores de login de cuenta inexistente y contraseña incorrecta son iguales y se hace trabajo de hash dummy; la latencia total aún puede variar por almacenamiento/red y el estado de email no verificado se distingue tras contraseña válida.
- **Implementado:** cambios/restablecimientos aplican política; cambio normal valida contraseña actual, reset consume un token único y revoca sesiones.
- **Implementado:** reautenticación reciente para operaciones sensibles cubiertas; APIs administrativas requieren autorización externa del consumidor.
- **Parcial:** el consumidor debe evitar registrar datos de login; Better Auth puede registrar email en eventos de duplicado y su configuración de logging debe revisarse por política de privacidad.

### Magic links

- **Implementado:** token Better Auth CSPRNG de 32 letras (aprox. 182 bits); se almacena su hash, con caducidad de 5 minutos por defecto y rango configurable de 1–15 minutos.
- **Implementado:** identificador ligado al flujo `magic-link`, el email y un tipo de verificación; tokens de uso único. Solicitar otro enlace no invalida expresamente enlaces anteriores aún vigentes.
- **Implementado:** GET no consume; la confirmación requiere POST same-origin y se probó replay/carrera en SQLite. La prueba PostgreSQL queda pendiente.
- **Implementado:** token en fragmento, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, CSP nonce y sin scripts externos en la confirmación.
- **Parcial:** escáneres que solo abren GET no consumen el enlace; no se puede garantizar el comportamiento de todos los agentes que simulan interacciones del usuario.
- **Implementado:** redirects verificados con orígenes de confianza y URL de origen configurada; no se construyen desde `Host` sin validar.
- **Implementado:** respuesta genérica al solicitar enlaces y cuota persistente 2/minuto + 8/hora por tipo/destinatario; un atacante aún puede agotar el cupo de la víctima durante esa ventana.
- **Implementado:** acceso al email se trata como autenticación; el enlace automático de cuentas/proveedores está desactivado.

### Sesiones

- **Implementado:** Better Auth genera IDs/tokens aleatorios; la base guarda HMAC-SHA-256 del token, no el bearer en claro. La migración transforma tokens existentes y las respuestas públicas omiten `token`.
- **Implementado:** sesiones persistentes, logout y revocación por ID tras reautenticación; sesiones de usuario deshabilitado se revocan.
- **Implementado:** cookies HttpOnly, host-only sin `Domain`, `Secure` en HTTPS y prefijo `__Host-` cuando `Path=/`; `SameSite=Lax` por defecto o `Strict` configurable.
- **Parcial:** SameSite reduce CSRF, pero site y origin no son equivalentes; las rutas sensibles verifican `Origin`, y el consumidor debe proteger sus propias mutaciones con cookie.
- **Implementado:** login crea sesión nueva; cambio de credencial y reset revocan sesiones según el flujo. La API permite expiración absoluta de 7 días e inactividad de 12 horas.
- **Parcial:** rotación de secreto puede invalidar sesiones existentes. Bouncer no expone una estrategia de transición/rotación multi-clave para HMAC de sesión.
- **Parcial:** sesión y bearer no se registran ni aparecen en respuestas públicas; el contexto interno Better Auth es una API privilegiada y el consumidor no debe serializarlo.
- **No aplica:** no hay JWT configurado.

### Rate limiting y antiabuso

- **Implementado:** login (5/minuto por IP en Better Auth y 20/15 min por IP+identidad con HMAC), magic link (5/minuto), registro (5/minuto), reset (3/minuto) y límites generales persistentes.
- **Implementado:** correo de magic link/reset/verificación con límite persistente por tipo/destinatario de 2/minuto y 8/hora; reautenticación y revocación también tienen límites.
- **Parcial:** el límite de correo protege costes pero puede retrasar mensajes de una víctima después de solicitudes maliciosas; las claves son HMAC y no exponen el email en claro.
- **Parcial:** almacenamiento SQL compartido apto para varias instancias, pero falta probar concurrencia en PostgreSQL. Las pruebas actuales de límites usan SQLite.
- **Pendiente:** backoff/detección de credential stuffing distribuido y telemetría que no registre secretos. Rate limiting no basta por sí solo.
- **Parcial:** el adaptador Node firma la IP obtenida del socket e ignora cabeceras de cliente falsificadas. Integraciones Fetch deben configurar explícitamente un origen de IP confiable; detrás de proxy se requiere sobrescribir cabeceras y restringir acceso directo.

### Validación, API, adapters y configuración

- **Implementado:** URL, cuerpo, email, contraseña y token tienen límites de tamaño; la validación corre en los límites de confianza.
- **Implementado:** redirects/orígenes pasan por Better Auth y la lista `trustedOrigins`; enlaces de correo parten de `baseURL` configurada.
- **Implementado:** SQL se delega al adapter Better Auth con parámetros; el wrapper de sesión intercepta operaciones necesarias, y los cambios administrativos usan transacciones.
- **Parcial:** atomicidad de consumo/transacciones y almacenamiento distribuido probada solo en SQLite; completar integración PostgreSQL y fallos de conexión antes de release.
- **Parcial:** CORS, TLS y autorización de recursos pertenecen al servidor consumidor; Bouncer verifica orígenes en rutas sensibles, pero no configura el perímetro del sitio.
- **Implementado:** el adaptador Node reemplaza IP provista por cliente con IP socket firmada; el uso detrás de proxy requiere configuración explícita y proxy confiable.
- **Implementado:** respuestas públicas eliminan claves de bearer y `password`, aplican `no-store`/`no-referrer` y convierten fallos críticos personalizados a errores controlados.
- **Parcial:** las páginas de recuperación/callback del consumidor deben eliminar tokens de URL, usar políticas equivalentes y excluir analytics/scripts externos.
- **Implementado:** configuración segura de producción exige HTTPS y PostgreSQL; Argon2id, verificación de email, cookies host-only y providers cifrados se activan según opciones descritas.
- **Parcial:** tokens OAuth nuevos y legacy se cifran con Better Auth; conservar el secreto es necesario y todavía no hay rotación de claves de Bouncer.
- **Parcial:** interfaces y capacidades tipadas separan API, UI y persistencia, pero Better Auth sigue expuesto como API avanzada; usar `$context` requiere privilegios de servidor y cuidado.

## Recomendaciones antes de publicar

1. Hacer respaldo y desplegar la nueva versión de forma coordinada: las instancias anteriores no entienden los hashes nuevos de sesiones/verificaciones.
2. Ejecutar la suite de integración con PostgreSQL, incluidas dos solicitudes concurrentes del mismo enlace, transacciones de `setPassword`, migraciones y fallos parciales.
3. Decidir si el límite por destinatario es aceptable para la experiencia de acceso; ofrecer alternativa de contraseña y monitorear supresión de email sin revelar identidad.
4. Definir la rotación de `secret`, que protege HMAC de sesiones y cifrado OAuth; no cambiarlo sin una migración/estrategia de transición.
5. Verificar límites y latencia de Argon2id y la comprobación HIBP en la infraestructura de destino.
6. Para cada consumidor: TLS, `baseURL`/orígenes exactos, proxy de confianza, CORS cerrado, callbacks sin terceros y logs sin tokens.
7. Implementar autorización por recurso/usuario en la aplicación anfitriona; Bouncer autentica, pero no define permisos de negocio.
8. Mantener actualización de dependencias y revisar Better Auth al actualizar la versión fijada.

## Referencias

- [Better Auth: Magic Link](https://better-auth.com/docs/plugins/magic-link)
- [Better Auth: Database](https://better-auth.com/docs/concepts/database)
- [Better Auth: Options (`encryptOAuthTokens`)](https://better-auth.com/docs/reference/options)
- [Better Auth: Create a Database Adapter (transactions)](https://better-auth.com/docs/guides/create-a-db-adapter)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
