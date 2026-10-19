# Uso de Bouncer

Bouncer son dos paquetes que se integran en tu aplicación: `@bouncer/api` para Node y `@bouncer/react` para React. Cada aplicación conserva sus usuarios, su base de datos y sus secretos. No necesitas desplegar un servidor Bouncer separado. Los pasos de cada método están en [flows de autenticación](auth-flows.md); el [README](../README.md) mantiene el proceso de release y distribución.

## Instalar y decidir la política

Requiere Node >=24, React 18.3 o 19 y PostgreSQL en producción. Instala ambos paquetes de la misma release y guarda el lockfile. El repositorio distribuye archivos npm por GitHub Releases, no mediante publicación pública en npm:

```sh
npm install --save-exact \
  https://github.com/megara-arevaco/bouncer/releases/download/v0.1.1/bouncer-api-0.1.1.tgz \
  https://github.com/megara-arevaco/bouncer/releases/download/v0.1.1/bouncer-react-0.1.1.tgz
```

Comprueba disponibilidad y sumas de esa release antes de usarla; el ejemplo fija la versión declarada actualmente por ambos paquetes. Instala el paquete API en el servidor y React en el frontend si tienes proyectos separados. Los paquetes son `UNLICENSED`: el acceso al archivo no concede licencia de distribución.

Elige un `appId` permanente, por ejemplo `mi_app`. Debe empezar por letra minúscula y contener solo minúsculas, dígitos y `_`, con máximo 32 caracteres. Cambiarlo cambia nombres de tablas y cookies. Genera un secreto independiente y aleatorio de al menos 32 caracteres por aplicación; guárdalo fuera del frontend y del repositorio. Cambiar el secreto requiere un plan para sesiones y credenciales dependientes de él.

Usa `methods` como selección explícita. Por ejemplo, `{ emailPassword: true, magicLink: true }` desactiva usuario, Google, GitHub y passkeys. `registration: false` cierra las altas por contraseña, OAuth y magic link; no elimina las cuentas existentes.

## Integrar la API Node

Este ejemplo usa un adaptador de correo de la aplicación; `applicationMailer` debe ser implementado por el anfitrión. En producción establece `NODE_ENV=production`, configura PostgreSQL y una URL pública HTTPS. El handler debe montarse antes de middleware que consuma el cuerpo de las peticiones.

```ts
import { createServer } from "node:http";
import { createBouncer, fromNodeHeaders, toNodeHandler } from "@bouncer/api";

function required(name: string) {
  const value = process.env[name];
  if (!value) throw new Error(`Falta ${name}`);
  return value;
}

const baseURL = required("PUBLIC_ORIGIN"); // https://app.example.com
const bouncer = createBouncer({
  appId: "mi_app",
  appName: "Mi aplicación",
  baseURL,
  secret: required("AUTH_SECRET"),
  database: {
    dialect: "postgres",
    config: { connectionString: required("DATABASE_URL") },
  },
  trustedOrigins: [baseURL],
  methods: { emailPassword: true, magicLink: true },
  registration: true,
  sendMail: async ({ to, url, kind, appId }) => {
    await applicationMailer.send({ to, url, kind, appId });
  },
});

// En el primer despliegue: migrar antes de aceptar tráfico.
// En producción separar esta tarea para usar un rol de migración dedicado.
await bouncer.migrate();
const handleAuth = toNodeHandler(bouncer);
const server = createServer(async (req, res) => {
  try {
    const pathname = new URL(req.url ?? "/", baseURL).pathname;
    if (pathname.startsWith("/api/auth/")) {
      await handleAuth(req, res);
      return;
    }
    if (pathname === "/api/me" && req.method === "GET") {
      const session = await bouncer.getSession(fromNodeHeaders(req.headers));
      if (!session) {
        res.writeHead(401).end();
        return;
      }
      res.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
      });
      res.end(JSON.stringify({ id: session.user.id, name: session.user.name }));
      return;
    }
    res.writeHead(404).end();
  } catch {
    if (!res.headersSent) res.writeHead(500);
    res.end();
  }
});
server.listen(3000, "127.0.0.1");

let closing = false;
async function shutdown() {
  if (closing) return;
  closing = true;
  server.close(async () => { await bouncer.close(); });
}
process.on("SIGTERM", () => { void shutdown(); });
process.on("SIGINT", () => { void shutdown(); });
```

Para recursos de negocio, filtra las consultas por `session.user.id` y comprueba roles/permisos en el servidor. No aceptes un `userId` arbitrario enviado por React como autorización. El servidor anfitrión debe añadir sus límites de cuerpos, tiempos de espera, observabilidad sin credenciales y apagado con plazo máximo.

`createBouncer` devuelve `handler(Request): Promise<Response>` para adaptadores Fetch, `getSession(Headers)`, `capabilities`, `migrate()`, `close()` y `auth` (instancia subyacente de Better Auth). Usa `toNodeHandler` si trabajas con Node HTTP: sobrescribe una cabecera interna con la IP del socket. Invocar directamente `handler` exige revisar qué cabeceras de IP recibe tu adaptador; no proporciona esa sobrescritura automáticamente.

### Base de datos y migraciones

Son válidas `{ dialect: "postgres", config }` y `{ dialect: "postgres", pool }`. Bouncer cierra solo conexiones que crea; un `Pool` aportado lo cierra la aplicación. En desarrollo se aceptan `{ dialect: "sqlite", filename }` y `{ dialect: "sqlite", connection }`, con la misma propiedad sobre la conexión.

Las tablas se prefijan `bouncer_<appId>_` e incluyen usuarios, cuentas, sesiones, verificaciones, límites de peticiones y passkeys si están activas. `migrate()` aplica el esquema; no es un sistema de rollback. Respaldar antes de actualizar, revisar el cambio de Better Auth, migrar una vez con un rol autorizado para DDL y ejecutar el servidor con permisos de datos mínimos. Prefijos no sustituyen roles ni bases separadas entre aplicaciones de distinta confianza.

### Opciones que afectan al comportamiento

| Opción | Regla actual |
| --- | --- |
| `baseURL` | URL pública estable. HTTPS fuera de localhost/loopback. Usar un origen sin ruta para evitar ambigüedad. |
| `basePath` | `/api/auth` por defecto. Ruta absoluta sin barra final; replicarla en cliente y proxy. |
| `cookiePath` | `/` por defecto. Debe incluir todas las rutas que necesitan la sesión. |
| `trustedOrigins` | Origen propio por defecto. Lista exacta de orígenes controlados, sin comodines amplios. |
| `requireEmailVerification` | `true` por defecto; con contraseña exige `sendMail`. |
| `minPasswordLength` | Entero 12–128; mínimo predeterminado 12 y máximo de contraseña 128. |
| `magicLinkExpiresIn` | Entero 60–900 segundos; predeterminado 300. |
| `socialProviders` | Credenciales servidor para `google` y/o `github`; además activar el método si existe `methods`. |
| `passkeys` | Atajo heredado utilizado solo sin `methods`; preferir `methods.passkeys`. |
| `ipAddress` | Configuración de Better Auth; detrás de proxy aplicar la política de la siguiente sección. |

`sendMail({ to, url, kind, appId })` recibe `kind` igual a `verify-email`, `reset-password` o `magic-link`. Plantillas y entrega son responsabilidad del anfitrión. Espera el envío, propaga errores y limita reintentos; nunca imprimas `url` para depurar en producción. Usa un dominio emisor con SPF/DKIM/DMARC y comprueba entrega real.

## Integrar React

Importa CSS una vez y carga capacidades desde tu propia API antes de renderizar. La aplicación debe servir `/reset-password` además de `/` y manejar errores de carga de configuración. Este fragmento usa la misma procedencia para frontend y API:

```tsx
import { createRoot } from "react-dom/client";
import {
  createBouncerClient, BouncerProvider, AuthPanel, AuthGuard, AccountPanel,
  type BouncerCapabilities,
} from "@bouncer/react";
import "@bouncer/react/styles.css";

const client = createBouncerClient();
async function start() {
  const response = await fetch("/api/auth/bouncer-config", { cache: "no-store" });
  if (!response.ok) throw new Error("No se pudo cargar la política de acceso");
  const capabilities: BouncerCapabilities = await response.json();
  const recovering = window.location.pathname === "/reset-password";
  const token = new URLSearchParams(window.location.search).get("token");
  createRoot(document.getElementById("root")!).render(
    <BouncerProvider
      client={client}
      capabilities={capabilities}
      appName="Mi aplicación"
      callbackURL={window.location.origin + "/"}
      logo={<span>Mi aplicación</span>}
      palette={{ accent: "#166534", accentForeground: "#ffffff" }}
    >
      {recovering ? (
        token ? <AuthPanel resetToken={token} /> : <p>Enlace inválido.</p>
      ) : (
        <AuthGuard fallback={<AuthPanel />}><AccountPanel /></AuthGuard>
      )}
    </BouncerProvider>,
  );
}
start().catch(() => {
  document.getElementById("root")!.textContent = "No se puede comprobar el acceso. Reintenta más tarde.";
});
```

El tipo TypeScript no valida el JSON recibido en tiempo de ejecución. Si cargas configuración desde un servicio no controlado, añade validación de esquema. Evita fuentes externas para esa política.

`createBouncerClient({ baseURL, basePath })` permite otra ubicación, pero la integración recomendada usa un mismo origen con proxy. Separar orígenes requiere diseñar CORS, cookies y HTTPS en la aplicación anfitriona; el wrapper no expone una configuración CORS ni cambia SameSite a None.

| Export | Uso |
| --- | --- |
| `BouncerProvider` | Recibe `client`, `capabilities`, `appName`, `callbackURL`, `logo` y `palette`. Crea su propio QueryClient para consultas de Bouncer. |
| `AuthPanel` | Vistas `login`, `register`, `forgot`, `magic` y `reset` mediante `initialView`; `resetToken` selecciona recuperación; `onAuthenticated` avisa tras operaciones de acceso exitosas iniciadas en el panel. OAuth vuelve por redirección. |
| `AccountPanel` | Correo, usuario, verificación pendiente, sesiones, cierre y passkeys; no incluye cambio de contraseña, borrado de cuenta ni roles. |
| `AuthGuard` | Espera la sesión; muestra error si falla y fallback si no hay sesión. No protege la API. |
| `useSession()` | Hook de sesión del cliente, con `data`, `error`, `isPending` e `isRefetching`. |
| `useSessions()` | Consulta sesiones del usuario; incluye `data`, `error`, estado y `refetch()`. |
| `useBouncer()` | Configuración del proveedor y cliente para construir formularios propios. |

`logo` admite un ReactNode; `palette` es parcial y permite `accent`, `accentForeground`, `text`, `muted`, `border`, `surface`, `inputBackground`, `buttonBackground`, `hoverBackground`, `focusRing`, `errorBackground`, `errorText`, `successBackground`, `successText` y `shadow`. Los paneles tienen textos en español; no hay API de traducción en esta versión. Los hooks deben ejecutarse dentro de `BouncerProvider`.

## Formularios propios y errores

Los métodos del cliente devuelven `{ data, error }` y una operación de red también puede lanzar una excepción. Comprueba ambos casos. No registres contraseñas, tokens, objetos de sesión completos ni URLs de correo.

```ts
const result = await client.signIn.email({ email, password });
if (result.error) {
  // Mostrar un mensaje controlado; no considerar autenticada la operación.
} else {
  const current = await client.getSession();
  // La API sigue comprobando sesión y autorización en cada petición privada.
}
```

Otros métodos públicos utilizados por los paneles son `signUp.email`, `signIn.username`, `signIn.social`, `signIn.magicLink`, `signIn.passkey`, `sendVerificationEmail`, `requestPasswordReset`, `resetPassword`, `updateUser`, `listSessions`, `revokeSession`, `revokeOtherSessions`, `signOut` y `passkey.addPasskey/deletePasskey`. Consulta requisitos y efectos de cada uno en [los flows](auth-flows.md).

## Proxy nginx y HTTPS

El proxy debe preservar `/api/auth/...`, no eliminar `/api/` al reenviar. Configura un `baseURL` fijo con el dominio público HTTPS. Para un nginx directo delante de la API:

```nginx
location /api/ {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

Esta configuración solo describe el proxy, no un servidor TLS completo. Si no configuras `ipAddress`, el adaptador Node usa la IP del socket: detrás de nginx todos los clientes pueden compartir el límite. Para el ejemplo de un único nginx controlado puedes usar `ipAddress: { ipAddressHeaders: ["x-real-ip"] }`, siempre que nginx sobrescriba esa cabecera y la API sea inaccesible directamente desde redes no confiables. Un CDN o varios proxies requieren definir qué saltos se confían y revisar la cadena; no copiar esa configuración sin adaptar la topología. [Better Auth explica el límite de confianza del proxy](https://better-auth.com/docs/reference/security).

No caches respuestas de autenticación ni la página de recuperación; excluye los tokens de access logs, Referer y analítica. En el frontend de recuperación usa `Referrer-Policy: no-referrer`, evita scripts de terceros y elimina el token de la URL cuando ya no haga falta.

## Desarrollo y comprobación

```sh
npm ci
npm run typecheck
npm run build
npm test
npx playwright install chromium
npm run test:e2e
npm run docs:check
npm run dev
```

`npm run dev` es exclusivamente desarrollo: escucha en `127.0.0.1:4310`, sirve Vite, usa SQLite si no se configura PostgreSQL y tiene un buzón de desarrollo en `/__dev/mailbox` que devuelve enlaces capaces de autenticar usuarios. No publicarlo detrás de nginx, túneles o reenvíos de puertos. `NODE_ENV=production` bloquea el playground y SQLite, pero no impide que alguien los exponga con otra configuración.

Para probar PostgreSQL, `TEST_DATABASE_URL` debe apuntar a un servidor desechable con permiso para crear y borrar bases: los tests crean bases temporales. No usar credenciales ni bases de producción. Los tests OAuth no recorren un consentimiento real; probar Google/GitHub, correo y restauración de datos en staging de la aplicación consumidora antes de abrirla.
