import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { passkey } from "@better-auth/passkey";
import { magicLink, username, twoFactor } from "better-auth/plugins";
import Database from "better-sqlite3";
import { Pool, type PoolConfig } from "pg";
import { toNodeHandler as betterAuthNodeHandler } from "better-auth/node";
import { isIP } from "node:net";
import { createHmac, randomUUID } from "node:crypto";
import { createAuthMiddleware, APIError } from "better-auth/api";
import { checkPassword, hashPassword, verifyPassword, PasswordPolicyError, type BreachedPasswordPolicy } from "./passwords.js";
import { securityStore } from "./security-store.js";
export { hashPassword, verifyPassword, checkPassword, PasswordPolicyError } from "./passwords.js";
import type { IncomingMessage, ServerResponse } from "node:http";
export { fromNodeHeaders } from "better-auth/node";

export function toNodeHandler(auth: {
  handler: (request: Request) => Promise<Response>;
}) {
  const handler = betterAuthNodeHandler(auth);
  return (request: IncomingMessage, response: ServerResponse) => {
    request.headers["x-bouncer-client-ip"] =
      request.socket.remoteAddress ?? "127.0.0.1";
    return handler(request, response);
  };
}

function isolatedPasskey(
  options: Parameters<typeof passkey>[0],
  modelName: string,
) {
  const plugin = passkey(options);
  return {
    ...plugin,
    schema: {
      ...plugin.schema,
      passkey: { ...plugin.schema.passkey, modelName },
    },
  };
}

export type MailMessage = {
  to: string;
  url: string;
  kind: "verify-email" | "reset-password" | "magic-link";
  appId: string;
};
export type BouncerMethods = {
  emailPassword?: boolean;
  usernamePassword?: boolean;
  magicLink?: boolean;
  google?: boolean;
  github?: boolean;
  passkeys?: boolean;
};
export type BouncerOptions = {
  appId: string;
  appName?: string;
  baseURL: string;
  basePath?: string;
  cookiePath?: string;
  secret: string;
  database:
    | { dialect: "postgres"; config: PoolConfig }
    | { dialect: "postgres"; pool: Pool }
    | { dialect: "sqlite"; filename: string; localDevelopment?: boolean }
    | { dialect: "sqlite"; connection: Database.Database; localDevelopment?: boolean };
  trustedOrigins?: BetterAuthOptions["trustedOrigins"];
  security?: {
    breachedPasswords?: BreachedPasswordPolicy;
    twoFactor?: boolean;
    reauthenticationWindow?: number;
    sameSite?: "strict" | "lax";
  };
  registration?: boolean;
  methods?: BouncerMethods;
  magicLinkExpiresIn?: number;
  minPasswordLength?: number;
  sendMail?: (message: MailMessage) => Promise<void>;
  requireEmailVerification?: boolean;
  socialProviders?: {
    google?: { clientId: string; clientSecret: string };
    github?: { clientId: string; clientSecret: string };
  };
  passkeys?: boolean;
  ipAddress?: NonNullable<BetterAuthOptions["advanced"]>["ipAddress"];
};

export function createBouncer(options: BouncerOptions) {
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(options.appId))
    throw new Error(
      "appId debe contener letras minúsculas, números o guiones bajos (máximo 32).",
    );
  if (options.secret.length < 32)
    throw new Error(
      "El secreto debe tener al menos 32 caracteres aleatorios y ser propio de la aplicación.",
    );
  const origin = new URL(options.baseURL);
  if (
    origin.protocol !== "https:" &&
    !["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname)
  )
    throw new Error("La autenticación requiere HTTPS fuera de localhost.");
  if (
    options.database.dialect === "sqlite" &&
    process.env.NODE_ENV === "production" &&
    !(options.database.localDevelopment && origin.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname))
  )
    throw new Error("Configura PostgreSQL en producción.");
  const mailEnabled = Boolean(options.sendMail);
  const emailPassword = options.methods
    ? options.methods.emailPassword === true
    : true;
  const usernamePassword = options.methods?.usernamePassword === true;
  const passwordEnabled = emailPassword || usernamePassword;
  const magicLinkEnabled = options.methods
    ? options.methods.magicLink === true
    : mailEnabled;
  const socialProviders = Object.fromEntries(
    Object.entries(options.socialProviders ?? {}).filter(
      ([key, value]) =>
        value &&
        (!options.methods ||
          options.methods[key as "google" | "github"] === true),
    ),
  );
  for (const provider of ["google", "github"] as const) {
    if (options.methods?.[provider] && !options.socialProviders?.[provider])
      throw new Error(
        `Configura las credenciales de ${provider} antes de habilitarlo.`,
      );
  }
  if (magicLinkEnabled && !mailEnabled)
    throw new Error("Magic link requiere sendMail.");
  if (
    passwordEnabled &&
    (options.requireEmailVerification ?? true) &&
    !mailEnabled
  )
    throw new Error(
      "La verificación de correo requiere sendMail. En desarrollo puedes usar createDevelopmentMailbox.",
    );
  const magicLinkExpiresIn = options.magicLinkExpiresIn ?? 300;
  if (
    !Number.isInteger(magicLinkExpiresIn) ||
    magicLinkExpiresIn < 60 ||
    magicLinkExpiresIn > 900
  )
    throw new Error(
      "La caducidad del magic link debe estar entre 60 y 900 segundos.",
    );
  const minPasswordLength = options.minPasswordLength ?? 12;
  if (
    !Number.isInteger(minPasswordLength) ||
    minPasswordLength < 12 ||
    minPasswordLength > 128
  )
    throw new Error(
      "La longitud mínima de contraseña debe estar entre 12 y 128 caracteres.",
    );
  const basePath = options.basePath ?? "/api/auth";
  if (!/^\/[a-zA-Z0-9/_-]+$/.test(basePath) || basePath.endsWith("/"))
    throw new Error("basePath debe ser una ruta absoluta sin barra final.");
  const cookiePath = options.cookiePath ?? "/";
  if (!/^\/[a-zA-Z0-9/_-]*$/.test(cookiePath))
    throw new Error("cookiePath debe ser una ruta absoluta válida.");
  const prefix = `bouncer_${options.appId}`;
  const hostCookies = origin.protocol === "https:" && cookiePath === "/";
  const database =
    options.database.dialect === "postgres"
      ? "pool" in options.database
        ? options.database.pool
        : new Pool(options.database.config)
      : "connection" in options.database
        ? options.database.connection
        : new Database(options.database.filename);
  const ownsDatabase =
    !("pool" in options.database) && !("connection" in options.database);
  if (options.database.dialect === "sqlite")
    (database as Database.Database).pragma("foreign_keys = ON");
  const deliver = async (
    kind: MailMessage["kind"],
    to: string,
    url: string,
  ) => {
    if (!options.sendMail)
      throw new Error("El envío de correo no está configurado.");
    await options.sendMail({ kind, to, url, appId: options.appId });
  };
  const registration = options.registration ?? true;
  const passkeyDomain = !isIP(origin.hostname.replace(/^\[|\]$/g, ""));
  if (
    (options.methods?.passkeys || (!options.methods && options.passkeys)) &&
    !passkeyDomain
  )
    throw new Error(
      "Las passkeys requieren un dominio o localhost, no una dirección IP.",
    );
  const passkeys = options.methods
    ? options.methods.passkeys === true
    : (options.passkeys ?? passkeyDomain);
  if (
    !passwordEnabled &&
    !magicLinkEnabled &&
    !passkeys &&
    Object.keys(socialProviders).length === 0
  )
    throw new Error("Habilita al menos un método de autenticación.");
  const passwordReset = passwordEnabled && mailEnabled;
  const disabledPaths = [
    ...(!emailPassword ? ["/sign-in/email"] : []),
    "/is-username-available",
    "/set-password",
    ...(!usernamePassword ? ["/sign-in/username"] : []),
    ...(!passwordEnabled || !(options.registration ?? true)
      ? ["/sign-up/email"]
      : []),
    ...(!passwordReset
      ? [
          "/request-password-reset",
          "/reset-password",
        ]
      : []),
  ];
  const policy = options.security?.breachedPasswords ?? (process.env.NODE_ENV === "production" ? "hibp" : "offline");
  const twoFactorEnabled = options.security?.twoFactor === true;
  const reauthenticationWindow = options.security?.reauthenticationWindow ?? 300;
  if (!Number.isInteger(reauthenticationWindow) || reauthenticationWindow < 60 || reauthenticationWindow > 900)
    throw new Error("La reautenticación debe caducar entre 60 y 900 segundos.");
  const limits = securityStore(database, options.database.dialect === "postgres", prefix);
  const validatePasswordPolicy = (password: string) => checkPassword(password, minPasswordLength, policy);
  type SecuritySession = { user: { id: string }; session: { id: string; createdAt: Date; recentlyVerifiedAt?: number } };
  let sessionForHeaders: (headers: Headers) => Promise<SecuritySession | null>;
  const requireReauthentication = async (headers: Headers): Promise<void> => {
    const session = await sessionForHeaders(headers);
    if (!session) throw new PasswordPolicyError("SESSION_EXPIRED", "Vuelve a iniciar sesión.");
    const verified = Math.max(new Date(session.session.createdAt).getTime(), (session.session.recentlyVerifiedAt ?? 0) * 1000);
    if (Date.now() - verified > reauthenticationWindow * 1000)
      throw new PasswordPolicyError("REAUTH_REQUIRED", "Confirma tu contraseña para continuar.");
  };
  const securityHooks: BetterAuthOptions["hooks"] = {
    before: createAuthMiddleware(async (ctx) => {
      try {
        const token = await ctx.getSignedCookie(ctx.context.authCookies.sessionToken.name, ctx.context.secret);
        if (token) {
          const existing = await ctx.context.internalAdapter.findSession(token);
          if (existing && (existing.user.disabled || Date.now() - new Date(existing.session.updatedAt).getTime() > 12 * 3600_000 || Date.now() - new Date(existing.session.createdAt).getTime() > 7 * 86400_000))
            await ctx.context.internalAdapter.deleteSession(token);
        }
        if (ctx.path === "/passkey/verify-authentication") {
          const encoded = ctx.body?.response?.response?.authenticatorData;
          const data = typeof encoded === "string" ? Buffer.from(encoded, "base64url") : Buffer.alloc(0);
          if (data.length < 37 || !(data[32] & 0x04))
            throw new PasswordPolicyError("PASSKEY_VERIFICATION_REQUIRED", "Verifica la passkey con tu PIN o biometría.");
        }
        if (["/sign-up/email", "/change-password", "/reset-password"].includes(ctx.path)) {
          const password = ctx.body?.newPassword ?? ctx.body?.password;
          if (typeof password === "string") await validatePasswordPolicy(password);
        }
        if (["/sign-in/email", "/sign-in/username"].includes(ctx.path)) {
          const identity = String(ctx.body?.email ?? ctx.body?.username ?? "").trim().toLowerCase();
          const key = createHmac("sha256", options.secret).update("login:" + identity).digest("hex");
          if (!await limits.consume(key, 20)) throw new PasswordPolicyError("TRY_LATER", "Demasiados intentos. Espera antes de volver a entrar.");
        }
        if (["/passkey/generate-register-options", "/passkey/verify-registration", "/passkey/delete-passkey", "/passkey/update-passkey", "/revoke-session", "/revoke-other-sessions", "/update-user"].includes(ctx.path))
          await requireReauthentication(new Headers(ctx.headers));
      } catch (error) {
        if (!(error instanceof PasswordPolicyError)) throw error;
        throw new APIError(error.code === "TRY_LATER" ? "TOO_MANY_REQUESTS" : error.code === "PASSWORD_CHECK_UNAVAILABLE" ? "SERVICE_UNAVAILABLE" : error.code === "REAUTH_REQUIRED" || error.code === "SESSION_EXPIRED" ? "FORBIDDEN" : "BAD_REQUEST", { code: error.code, message: error.message });
      }
    }),
  };
  securityHooks.after = createAuthMiddleware(async (ctx) => {
    if (ctx.path === "/passkey/generate-authenticate-options" && ctx.context.returned && typeof ctx.context.returned === "object" && "challenge" in ctx.context.returned)
      return ctx.json({ ...ctx.context.returned, userVerification: "required" });
  });
  const authOptions = {
    appName: options.appName ?? options.appId,
    baseURL: options.baseURL,
    basePath,
    secret: options.secret,
    database: database as BetterAuthOptions["database"],
    disabledPaths,
    trustedOrigins: options.trustedOrigins ?? [origin.origin],
    hooks: securityHooks,
    user: { modelName: `${prefix}_user`, additionalFields: { disabled: { type: "boolean", defaultValue: false, input: false, returned: false } } },
    databaseHooks: { session: { create: { before: async (session) => {
      const user = await (await getAuth().$context).internalAdapter.findUserById(session.userId);
      if (user && "disabled" in user && user.disabled) return false;
      const adapter = (await getAuth().$context).internalAdapter;
      const sessions = await adapter.listSessions(session.userId);
      for (const item of sessions.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).slice(9))
        await adapter.deleteSession(item.token);
      return { data: session };
    } } } },
    session: {
      modelName: `${prefix}_session`,
      expiresIn: 60 * 60 * 24 * 7,
      updateAge: 300,
      additionalFields: { recentlyVerifiedAt: { type: "number", defaultValue: 0, input: false } },
    },
    account: {
      modelName: `${prefix}_account`,
      accountLinking: { enabled: false },
    },
    verification: { modelName: `${prefix}_verification` },
    advanced: {
      ipAddress: options.ipAddress ?? {
        ipAddressHeaders: ["x-bouncer-client-ip"],
      },
      // Set Secure explicitly so Better Auth does not prepend __Secure- to __Host-.
      cookiePrefix: hostCookies ? `__Host-${prefix}` : prefix,
      useSecureCookies: origin.protocol === "https:" && !hostCookies,
      defaultCookieAttributes: {
        secure: origin.protocol === "https:",
        httpOnly: true,
        sameSite: options.security?.sameSite ?? "lax",
        path: cookiePath,
      },
    },
    rateLimit: {
      enabled: true,
      storage: "database",
      modelName: `${prefix}_rate_limit`,
      window: 60,
      max: 60,
      customRules: {
        "/sign-in/email": { window: 60, max: 5 },
        "/sign-in/username": { window: 60, max: 5 },
        "/sign-up/email": { window: 60, max: 5 },
        "/request-password-reset": { window: 60, max: 3 },
      },
    },
    emailAndPassword: {
      enabled: passwordEnabled,
      password: { hash: hashPassword, verify: verifyPassword },
      disableSignUp: !registration,
      minPasswordLength,
      maxPasswordLength: 128,
      requireEmailVerification: options.requireEmailVerification ?? true,
      revokeSessionsOnPasswordReset: true,
      ...(passwordReset
        ? {
            sendResetPassword: async ({
              user,
              url,
            }: {
              user: { email: string };
              url: string;
            }) => deliver("reset-password", user.email, url),
          }
        : {}),
    },
    emailVerification: {
      sendOnSignUp: mailEnabled,
      sendOnSignIn: mailEnabled,
      autoSignInAfterVerification: false,
      ...(mailEnabled
        ? {
            sendVerificationEmail: async ({
              user,
              url,
            }: {
              user: { email: string };
              url: string;
            }) => deliver("verify-email", user.email, url),
          }
        : {}),
    },
    socialProviders: Object.fromEntries(
      Object.entries(socialProviders).map(([key, value]) => [
        key,
        { ...value, disableSignUp: !registration },
      ]),
    ),
    plugins: [
      ...(twoFactorEnabled ? [twoFactor({
        issuer: options.appName ?? options.appId,
        twoFactorTable: `${prefix}_two_factor`,
        twoFactorCookieMaxAge: 300,
        accountLockout: { enabled: true, maxFailedAttempts: 5, durationSeconds: 900 },
        backupCodeOptions: { amount: 10, length: 16, storeBackupCodes: "encrypted" },
      })] : []),
      ...(usernamePassword
        ? [
            username({
              maxUsernameLength: 40,
              usernameValidator: (value) =>
                /^[a-zA-Z0-9._-]{3,40}$/.test(value),
              immutableUsername: true,
            }),
          ]
        : []),
      ...(magicLinkEnabled
        ? [
            magicLink({
              disableSignUp: !registration,
              storeToken: "hashed",
              expiresIn: magicLinkExpiresIn,
              sendMagicLink: async ({ email, url }) =>
                deliver("magic-link", email, url),
            }),
          ]
        : []),
      ...(passkeys
        ? [
            isolatedPasskey(
              {
                rpID: origin.hostname,
                rpName: options.appName ?? options.appId,
                authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
                origin: Array.isArray(options.trustedOrigins) ? options.trustedOrigins : [origin.origin],
                advanced: {
                  webAuthnChallengeCookie: `${prefix}_passkey_challenge`,
                },
              },
              `${prefix}_passkey`,
            ),
          ]
        : []),
    ],
  } satisfies BetterAuthOptions;
  const initializeAuth = () => betterAuth(authOptions);
  let authInstance: ReturnType<typeof initializeAuth> | undefined;
  const getAuth = () => (authInstance ??= initializeAuth());
  sessionForHeaders = (headers) => getAuth().api.getSession({ headers });
  const capabilities = {
    registration,
    requireEmailVerification: options.requireEmailVerification ?? true,
    emailPassword,
    usernamePassword,
    minPasswordLength,
    magicLink: magicLinkEnabled,
    passwordReset,
    passwordChange: passwordEnabled,
    twoFactor: twoFactorEnabled,
    reauthentication: true,
    emailVerification: mailEnabled,
    passkeys,
    socialProviders: Object.keys(socialProviders) as ("google" | "github")[],
  };
  return {
    get auth() {
      return getAuth();
    },
    capabilities,
    handler: async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      if (
        url.pathname === `${basePath}/bouncer-config` &&
        request.method === "GET"
      ) {
        return Response.json(capabilities, {
          headers: { "cache-control": "no-store" },
        });
      }
      if (url.pathname === `${basePath}/reauthenticate`) {
        try {
          if (request.method !== "POST" || request.headers.get("origin") !== url.origin || request.headers.get("content-type")?.split(";")[0] !== "application/json")
            return Response.json({ code: "FORBIDDEN" }, { status: 403 });
          const session = await sessionForHeaders(request.headers);
          if (!session) return Response.json({ code: "SESSION_EXPIRED" }, { status: 401 });
          const key = createHmac("sha256", options.secret).update("reauth:" + session.user.id).digest("hex");
          if (!await limits.consume(key, 5)) return Response.json({ code: "TRY_LATER" }, { status: 429 });
          const text = await request.text();
          if (Buffer.byteLength(text) > 8192) return Response.json({ code: "REQUEST_TOO_LARGE" }, { status: 413 });
          const body = JSON.parse(text) as { password?: unknown };
          if (typeof body.password !== "string" || Buffer.byteLength(body.password) > 1024) return Response.json({ code: "INVALID_PASSWORD" }, { status: 400 });
          const ctx = await getAuth().$context;
          const accounts = await ctx.internalAdapter.findAccounts(session.user.id);
          const credential = accounts.find((account) => account.providerId === "credential");
          if (!credential?.password || !await ctx.password.verify({ password: body.password, hash: credential.password }))
            return Response.json({ code: "INVALID_PASSWORD" }, { status: 401 });
          await ctx.adapter.update({ model: "session", where: [{ field: "id", value: session.session.id }], update: { recentlyVerifiedAt: Math.floor(Date.now() / 1000) } });
          return Response.json({ status: true }, { headers: { "cache-control": "no-store" } });
        } catch { return Response.json({ code: "REAUTH_UNAVAILABLE" }, { status: 400 }); }
      }
      return getAuth().handler(request);
    },
    migrate: async () => {
      const migration = await getMigrations(authOptions);
      await migration.runMigrations();
      await limits.migrate();
    },
    getSession: (headers: Headers) => getAuth().api.getSession({ headers }),
    requireReauthentication,
    validatePassword: validatePasswordPolicy,
    admin: {
      async findUser(email: string) { return (await (await getAuth().$context).internalAdapter.findUserByEmail(email.toLowerCase()))?.user ?? null; },
      async importCredentialUser(input: { id: string; email: string; name: string; passwordHash: string; disabled?: boolean }) {
        const ctx = await getAuth().$context;
        const existing = await ctx.internalAdapter.findUserByEmail(input.email.toLowerCase(), { includeAccounts: true });
        if (existing) {
          if (existing.user.id !== input.id) throw new Error("La cuenta ya existe con otro identificador.");
          return existing.user;
        }
        return ctx.adapter.transaction(async (tx) => {
          const user = await tx.create({ model: "user", forceAllowId: true, data: { id: input.id, name: input.name, email: input.email.toLowerCase(), emailVerified: true, disabled: input.disabled ?? false, createdAt: new Date(), updatedAt: new Date() } });
          await tx.create({ model: "account", forceAllowId: true, data: { id: randomUUID(), userId: input.id, accountId: input.id, providerId: "credential", password: input.passwordHash, createdAt: new Date(), updatedAt: new Date() } });
          return user;
        });
      },
      async createCredentialUser(input: { id: string; email: string; name: string; password: string }) {
        await validatePasswordPolicy(input.password);
        return this.importCredentialUser({ ...input, passwordHash: await hashPassword(input.password) });
      },
      async setPassword(userId: string, password: string) {
        await validatePasswordPolicy(password);
        const ctx = await getAuth().$context;
        await ctx.internalAdapter.updatePassword(userId, await hashPassword(password));
        await ctx.internalAdapter.deleteUserSessions(userId);
      },
      async revokeUserSessions(userId: string) { await (await getAuth().$context).internalAdapter.deleteUserSessions(userId); },
      async disableUser(userId: string, disabled: boolean) {
        const ctx = await getAuth().$context;
        await ctx.internalAdapter.updateUser(userId, { disabled });
        await ctx.internalAdapter.deleteUserSessions(userId);
      },
    },
    close: async () => {
      if (!ownsDatabase) return;
      if (options.database.dialect === "postgres")
        await (database as Pool).end();
      else (database as Database.Database).close();
    },
  };
}

export type Bouncer = ReturnType<typeof createBouncer>;

export function createDevelopmentMailbox() {
  if (process.env.NODE_ENV === "production")
    throw new Error("El buzón de desarrollo no está disponible en producción.");
  const messages: MailMessage[] = [];
  return {
    messages,
    sendMail: async (message: MailMessage) => {
      messages.push({ ...message });
      if (messages.length > 100) messages.shift();
    },
    clear: () => {
      messages.length = 0;
    },
  };
}
