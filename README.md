<div align="center">
  <img src="assets/bouncer-mark.svg" width="132" height="132" alt="Bouncer logo">
  <h1>Bouncer</h1>
  <p><strong>Authentication, account security, and permissions — owned by your application.</strong></p>
  <p>
    <img alt="Node.js 24.7 or newer" src="https://img.shields.io/badge/Node.js-24.7%2B-5FA04E?logo=nodedotjs&logoColor=white">
    <img alt="React 18.3 and 19" src="https://img.shields.io/badge/React-18.3%20%7C%2019-61DAFB?logo=react&logoColor=10131A">
    <img alt="TypeScript 5" src="https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white">
    <img alt="Better Auth 1.7.10" src="https://img.shields.io/badge/Better_Auth-1.7.10-10131A">
    <img alt="License: UNLICENSED" src="https://img.shields.io/badge/License-UNLICENSED-F4BA55">
    <a href="https://github.com/megara-arevaco/bouncer/actions/workflows/ci.yml"><img alt="CI status" src="https://github.com/megara-arevaco/bouncer/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/megara-arevaco/bouncer/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/megara-arevaco/bouncer?display_name=tag"></a>
  </p>
  <p>
    <a href="#install-a-release">Install</a> ·
    <a href="#api-integration">API</a> ·
    <a href="#roles-and-permissions">Permissions</a> ·
    <a href="#react-integration">React</a> ·
    <a href="docs/uso-libreria.md">Guía en español</a>
  </p>
</div>

Bouncer is a set of TypeScript libraries for Node.js APIs and React frontends,
built on Better Auth. Your application owns its database, users, sessions,
secrets, OAuth credentials, email delivery, and role assignments.

Better Auth supplies the authentication engine and protocol flows. Bouncer adds
shared security policies, application-specific table and cookie prefixes, defensive
storage migrations, a typed capability contract, and React account flows. Use it
to carry the same integration across applications; using Better Auth directly is
also a reasonable choice when you do not need those policies or components.

## What Bouncer does

- Supports email/password, username/password, magic links, passkeys, and optional Google/GitHub sign-in.
- Provides email verification, password recovery, TOTP, and recovery codes.
- Applies Argon2id password hashing, progressive rehash, and configurable compromised-password checks.
- Adds magic-link confirmation, recent authentication for sensitive actions, and persistent abuse limits.
- Stores session token HMACs and encrypted OAuth tokens, with migrations for existing data.
- Exposes session checks, revocation, and a capability endpoint for the frontend.
- Includes React authentication and account panels with configurable branding.
- Checks application-defined roles and permissions through a separate authorization package.

| Package | Purpose |
| --- | --- |
| `@bouncer/api` | Authentication handler, migrations, session checks, and account security. |
| `@bouncer/react` | Client, provider, authentication/account panels, session hooks, and branding. |
| `@bouncer/authorization` | Role-to-permission policies and server-side permission checks. |

> [!IMPORTANT]
> Bouncer is under active development. The host application must authorize each
> resource and configure TLS, trusted origins, proxy handling, and email delivery.
> The local playground and its development mailbox must stay out of production.

## Requirements

- Node.js **24.7 or newer**.
- PostgreSQL for production; SQLite is supported for development.
- React **18.3 or 19** when using `@bouncer/react`.
- An application mail adapter for magic links, verification, and password recovery.
- Your own provider credentials when enabling Google or GitHub.

The [usage guide](docs/uso-libreria.md) and [authentication flows](docs/auth-flows.md)
cover integration details in Spanish, including configuration, proxy handling,
recovery, accounts, and session behavior.

## Install a release

Packages are distributed as compiled npm archives through [GitHub Releases](https://github.com/megara-arevaco/bouncer/releases).
Install the packages your application needs from the same release:

```sh
npm install --save-exact \
  https://github.com/megara-arevaco/bouncer/releases/download/v0.2.1/bouncer-api-0.2.1.tgz \
  https://github.com/megara-arevaco/bouncer/releases/download/v0.2.1/bouncer-react-0.2.1.tgz \
  https://github.com/megara-arevaco/bouncer/releases/download/v0.2.1/bouncer-authorization-0.2.1.tgz
```

Commit the application's lockfile: it pins archive integrity and transitive dependencies. Releases also contain `SHA256SUMS` for independent archive verification. Keep installed Bouncer packages on the same release. Never depend on a `latest` download URL. The packages retain their existing `UNLICENSED` status; distributing archives does not grant an open-source license.

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

## Roles and permissions

`@bouncer/authorization` maps application-defined roles to permissions. Resolve the
current role from your application's data and enforce permissions on the server:

```ts
import { createAuthorization } from "@bouncer/authorization";

const authorization = createAuthorization({
  roles: {
    admin: ["projects:read", "projects:write"],
    member: ["projects:read"],
  },
  getRole: async (userId: string) =>
    (await applicationUsers.findById(userId))?.role,
});

// After checking the session, before accessing the protected resource:
await authorization.requirePermission(session.user.id, "projects:write");
```

`applicationUsers` represents your own user repository. Roles remain in your
database and are resolved on each check, so changing a role does not depend on
stale grants in a session. Anonymous users and unknown roles receive no permissions.
`can()` returns a boolean; `requirePermission()` throws `AuthorizationError` with
`status: 403`, which the host should map to its HTTP response. The package does not
include a role administration panel or organization-scoped memberships.

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

All three packages use a coordinated SemVer version. During `0.x`, a minor version can introduce breaking API or schema changes; patch versions preserve the public API. Review database migrations and the pinned Better Auth version for every upgrade. Do not overwrite published tags or archives; fix a release with a new version.

1. Update all `packages/*/package.json` versions and the playground's matching dependencies; run `npm install --package-lock-only`.
2. Run the checks above, `npm run release:pack` and `npm run release:check`. This builds distributable JS, declarations and CSS into three npm archives, checks their contents and writes checksums under `artifacts/v<version>/`.
3. Commit and push the reviewed changes, then create and push the matching `v<version>` tag.
4. The release workflow reruns validation, installs the archives in an isolated TypeScript consumer, and publishes all three archives and `SHA256SUMS` as a GitHub Release. A tag/version mismatch fails publication.
5. Consumers update their installed Bouncer packages to matching exact archive URLs, review the release and lockfile, then run their integration tests and migrations before deployment.

Release automation uses repository-scoped `contents: write` only for the publishing job. No npm token or registry account is required.
