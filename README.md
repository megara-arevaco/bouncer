# Bouncer

Authentication libraries for application-owned Node.js APIs and React frontends, built on Better Auth. Each host application owns its database, users, sessions, secret, OAuth credentials and email delivery. Bouncer does not run a central identity service.

Better Auth supplies the authentication engine and protocol flows. Bouncer adds opinionated application defaults, per-app table and cookie isolation, security policy and migration hooks, a typed capability contract, and ready-to-use React flows. If an application does not need those defaults or components, using Better Auth directly is a reasonable choice.

- `@bouncer/api`: HTTP handler, migrations, server-side session checks and capability discovery.
- `@bouncer/react`: client, provider, authentication/account panels, session hooks and branding.
- [Guía de uso de la librería](docs/uso-libreria.md): integración de API y React, opciones, proxy, ejemplos y límites.
- [Flows de autenticación](docs/auth-flows.md): requisitos y comportamiento de cada método, recuperación, cuenta y sesiones, con diagramas Mermaid.

## Install a release

Requires Node.js 24 or newer, React 18.3/19 and PostgreSQL in production. SQLite is supported for development. Packages are distributed as compiled npm archives through [GitHub Releases](https://github.com/megara-arevaco/bouncer/releases), rather than a sibling checkout or npm registry publication.

```sh
npm install --save-exact \
  https://github.com/megara-arevaco/bouncer/releases/download/v0.1.1/bouncer-api-0.1.1.tgz \
  https://github.com/megara-arevaco/bouncer/releases/download/v0.1.1/bouncer-react-0.1.1.tgz
```

Commit the application's lockfile: it pins archive integrity and transitive dependencies. Releases also contain `SHA256SUMS` for independent archive verification. Install both packages from the same release. Never depend on a `latest` download URL. The packages retain their existing `UNLICENSED` status; distributing archives does not grant an open-source license.

## API integration

Mount the auth handler before middleware that consumes request bodies. Run migrations once before accepting traffic, with a database role allowed to create/alter the auth tables. Back up the application's database before upgrading. Migrations hash stored session tokens and verification identifiers and encrypt legacy OAuth tokens. Use a coordinated deployment so old application instances do not keep serving while these values are migrated. Bouncer prefixes its tables and cookies with `bouncer_<appId>`; keep `appId` and its secret stable and use a separate secret for each application.

```ts
import { createServer } from "node:http";
import { createBouncer, fromNodeHeaders, toNodeHandler } from "@bouncer/api";

const bouncer = createBouncer({
  appId: "my_app",
  appName: "My application",
  baseURL: "https://app.example.com",
  secret: process.env.AUTH_SECRET!, // At least 32 random characters.
  database: {
    dialect: "postgres",
    config: { connectionString: process.env.DATABASE_URL! },
  },
  trustedOrigins: ["https://app.example.com"],
  methods: { emailPassword: true, magicLink: true },
  sendMail: async ({ to, url, kind, appId }) => {
    // Deliver the URL through your application's email provider.
    // Await delivery and propagate failures; never log credential URLs.
    await applicationMailer.send({ to, url, kind, appId });
  },
});
await bouncer.migrate();
const authHandler = toNodeHandler(bouncer);
const server = createServer(async (req, res) => {
  if (req.url?.startsWith("/api/auth/")) {
    await authHandler(req, res);
    return;
  }
  const session = await bouncer.getSession(fromNodeHeaders(req.headers));
  if (!session) {
    res.writeHead(401).end();
    return;
  }
  // Authorize access to application data using session.user.id.
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ userId: session.user.id }));
});
server.listen(3000, "127.0.0.1");
```

`applicationMailer` represents the host's own mail adapter. Put error handling and graceful shutdown in the host server; call `bouncer.close()` on shutdown. Bouncer closes only database connections it created. Passing `{ dialect: "postgres", pool }` or `{ dialect: "sqlite", connection }` leaves connection ownership with the host.

### Configuration

| Option | Behavior |
| --- | --- |
| `appId` | Lowercase letter followed by lowercase letters, digits or underscores; maximum 32 characters. |
| `baseURL` | Application's public auth origin. HTTPS is required except on localhost/loopback. |
| `basePath` | Auth endpoint prefix; defaults to `/api/auth`, no trailing slash. Set the same path in the client. |
| `cookiePath` | Defaults to `/`. Must cover auth and protected API endpoints. |
| `registration` | Defaults to `true`. `false` closes new-account creation for passwords, social providers and magic links. |
| `methods` | If supplied, only explicitly enabled methods are available. At least one method is required. |
| `requireEmailVerification` | Defaults to `true`; password login requires verification and a `sendMail` callback. |
| `minPasswordLength` | Defaults to 15; configurable from 12 to 128. Maximum password length is 128 Unicode code points and 1024 UTF-8 bytes. |
| `security.passwordHash` | Argon2id parameters; defaults to 19 MiB, 2 passes and parallelism 1. Bounds are validated. |
| `security.breachedPasswords` | Defaults to `hibp` in production and `offline` elsewhere; can be set to `false`. HIBP failures reject the operation. |
| `security.reauthenticationWindow` | Defaults to 300 seconds; configurable from 60 to 900. |
| `security.sameSite` | Cookie `SameSite` policy; defaults to `lax`, with `strict` also available. |
| `magicLinkExpiresIn` | Defaults to 300 seconds; configurable from 60 to 900. Requires `sendMail`. |
| `socialProviders` | Application-owned Google/GitHub credentials. When `methods` is supplied, also enable the corresponding method there. |
| `passkeys` | Legacy shorthand when `methods` is absent. Otherwise use `methods.passkeys`. Requires a domain or localhost. |
| `ipAddress` | Better Auth IP configuration. Default Node adapter uses the socket address, ignoring forwarded client IP headers. |

Without `methods`, email/password is enabled; magic links follow mail availability; configured social providers are enabled; passkeys default to enabled on a domain/localhost. With `methods`, omitted keys are disabled. Username/password is opt-in through `methods.usernamePassword`; it can share credential registration with email/password while exposing only username login. Username syntax is 3–40 ASCII letters, digits, `.`, `_` or `-`; usernames are immutable.

`GET /api/auth/bouncer-config` reports enabled methods and registration/password policy. This response drives the frontend; hiding a button is never an authorization check. Public session objects omit bearer tokens; the API supports revoking another session by its ID after recent reauthentication. Keep the secret stable: Bouncer uses it to hash session tokens and encrypt provider tokens. Protect every application API route on the server. `toNodeHandler` trusts the socket IP and replaces client-supplied values; a direct Fetch integration has no trusted IP by default, so configure `ipAddress` only with a trusted proxy that overwrites the chosen header. Behind a reverse proxy, all clients share the proxy's socket IP by default; keep the API inaccessible directly.

Authentication responses no longer include bearer `token` fields, and `getSession()` no longer exposes `session.token`. Integrations that read those values must use the HttpOnly session cookie and the public session ID for session management.

## React integration

Load capabilities from your own API before rendering the provider. Import the stylesheet once. The panels currently use Spanish UI copy; the detailed usage and flow guides are also available in Spanish.

```tsx
import {
  AuthGuard, AuthPanel, AccountPanel,
  BouncerProvider, createBouncerClient,
} from "@bouncer/react";
import "@bouncer/react/styles.css";

const client = createBouncerClient(); // Same origin and /api/auth by default.
const response = await fetch("/api/auth/bouncer-config");
if (!response.ok) throw new Error("Unable to load authentication configuration");
const capabilities = await response.json();

export function App() {
  const token = new URLSearchParams(window.location.search).get("token");
  const recovering = window.location.pathname === "/reset-password";
  return (
    <BouncerProvider
      client={client}
      capabilities={capabilities}
      appName="My application"
      callbackURL={window.location.origin + "/"}
    >
      {recovering ? <AuthPanel resetToken={token ?? undefined} /> : (
        <AuthGuard fallback={<AuthPanel />}>
          <AccountPanel />
        </AuthGuard>
      )}
    </BouncerProvider>
  );
}
```

Serve your frontend on `/reset-password` as well as `/`. `AuthPanel` derives the recovery URL relative to `callbackURL`; if you use a subpath, serve the equivalent relative route. Never cache password-reset pages or put token URLs in analytics. `AuthGuard` displays the sign-in fallback and checks the session; the API remains responsible for authorization. `useSession`, `useSessions` and `useBouncer` expose session/client state. `BouncerProvider` accepts `logo` and `palette` for host branding; see the playground for a complete working integration.

## Develop and validate

```sh
npm ci
npx playwright install chromium
npm run typecheck
npm run build
npm test
npm run test:e2e
npm run docs:check
npm run dev
```

The playground runs at `http://localhost:4310`, stores SQLite data under `.data/` and uses an in-memory development mailbox at `/__dev/mailbox`. It must never be deployed in production. `createDevelopmentMailbox()` refuses production mode. OAuth providers require your own credentials; real Google/GitHub consent is not exercised by the automated suite. Set `TEST_DATABASE_URL` to a disposable PostgreSQL admin connection to run HTTP integration tests against PostgreSQL; the tests create and drop isolated databases. CI checks both SQLite and PostgreSQL, browser flows and actual Mermaid rendering.

## Release a version

Both packages use a coordinated SemVer version. During `0.x`, a minor version can introduce breaking API or schema changes; patch versions preserve the public API. Review database migrations and the pinned Better Auth version for every upgrade. Do not overwrite published tags or archives; fix a release with a new version.

1. Update both `packages/*/package.json` versions and the playground's matching dependencies; run `npm install --package-lock-only`.
2. Run the checks above, `npm run release:pack` and `npm run release:check`. This builds distributable JS, declarations and CSS into two npm archives, checks their contents and writes checksums under `artifacts/v<version>/`.
3. Commit and push the reviewed changes, then create and push the matching `v<version>` tag.
4. The release workflow reruns validation, installs the archives in an isolated TypeScript consumer, and publishes both archives and `SHA256SUMS` as a GitHub Release. A tag/version mismatch fails publication.
5. Consumers update both exact archive URLs together, review the release and lockfile, then run their integration tests and migrations before deployment.

Release automation uses repository-scoped `contents: write` only for the publishing job. No npm token or registry account is required.
