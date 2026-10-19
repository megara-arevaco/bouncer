import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { passkey } from "@better-auth/passkey";
import { magicLink, username, twoFactor } from "better-auth/plugins";
import Database from "better-sqlite3";
import { Pool, type PoolConfig } from "pg";
import { toNodeHandler as betterAuthNodeHandler } from "better-auth/node";
import { isIP } from "node:net";
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createAuthMiddleware, APIError, getIP } from "better-auth/api";
import { getAdapter } from "better-auth/db/adapter";
import { symmetricEncrypt } from "better-auth/crypto";
import { runWithTransaction } from "@better-auth/core/context";
import { checkPassword, hashPassword, verifyPassword, passwordNeedsRehash, DEFAULT_ARGON2ID_PARAMETERS, PasswordPolicyError, type Argon2idParameters, type BreachedPasswordPolicy } from "./passwords.js";
import { securityStore } from "./security-store.js";
import { createSessionTokenAdapter, hashSessionToken } from "./session-token-adapter.js";
export { hashPassword, verifyPassword, checkPassword, PasswordPolicyError } from "./passwords.js";
export type { Argon2idParameters } from "./passwords.js";
import type { IncomingMessage, ServerResponse } from "node:http";
export { fromNodeHeaders } from "better-auth/node";

const trustedClientIPSecret = Symbol("bouncer-trusted-client-ip-secret");
const clientIPHeader = "x-bouncer-client-ip";
const clientIPSignatureHeader = "x-bouncer-client-ip-signature";

function clientIPSignature(secret: string, ip: string) {
  return createHmac("sha256", secret).update(`bouncer-node-ip-v1\0${ip}`).digest("hex");
}

async function limitRequestBody(request: Request, maximumBytes: number) {
  if (!request.body) return { request } as const;
  const contentLength = request.headers.get("content-length");
  if (contentLength && /^\d+$/.test(contentLength) && Number(contentLength) > maximumBytes) {
    return { error: "too-large" } as const;
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        return { error: "too-large" } as const;
      }
      chunks.push(value);
    }
  } catch {
    return { error: "invalid-body" } as const;
  }
  const headers = new Headers(request.headers);
  headers.delete("content-length");
  headers.delete("transfer-encoding");
  return {
    request: new Request(request.url, {
      method: request.method,
      headers,
      body: Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))),
      duplex: "half",
    } as RequestInit),
  } as const;
}

function securityResponseHeaders(headers: HeadersInit = {}) {
  const result = new Headers(headers);
  result.set("cache-control", "no-store, max-age=0");
  result.set("pragma", "no-cache");
  result.set("referrer-policy", "no-referrer");
  result.set("x-content-type-options", "nosniff");
  return result;
}

const secretOutputFields = new Set(["token", "accesstoken", "refreshtoken", "idtoken", "password"]);
type SecretOutputField = "token" | "accesstoken" | "refreshtoken" | "idtoken" | "password";
type RedactedOutput<T> =
  T extends Promise<infer Value> ? Promise<RedactedOutput<Value>> :
  T extends Date ? Date :
  T extends readonly (infer Item)[] ? readonly RedactedOutput<Item>[] :
  T extends (...args: never[]) => unknown ? T :
  T extends object ? { [Key in keyof T as Key extends string ? Lowercase<Key> extends SecretOutputField ? never : Key : Key]: RedactedOutput<T[Key]> } : T;
type RedactedMethod<T> = T extends (...args: infer Args) => infer Result ? (...args: Args) => RedactedOutput<Result> : T;
type RedactedAPI<T> = { [Key in keyof T]: RedactedMethod<T[Key]> };
function redactSensitiveOutput(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSensitiveOutput);
  if (!value || typeof value !== "object" || value instanceof Date) return value;
  const result: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (secretOutputFields.has(key.toLowerCase())) continue;
    result[key] = redactSensitiveOutput(child);
  }
  return result;
}

async function redactSensitiveResponse(response: Response) {
  if (!response.headers.get("content-type")?.toLowerCase().includes("application/json"))
    return response;
  try {
    const body = redactSensitiveOutput(await response.clone().json());
    const headers = new Headers(response.headers);
    headers.delete("content-length");
    headers.delete("content-encoding");
    return new Response(JSON.stringify(body), {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  } catch {
    return response;
  }
}

function magicLinkConfirmationPage(action: string, nonce: string) {
  const fields = ["token", "callbackURL", "newUserCallbackURL", "errorCallbackURL"];
  const inputs = fields.map((name) => `<input type="hidden" name="${name}">`).join("");
  const script = `
    const params = new URLSearchParams(location.hash.slice(1));
    history.replaceState(null, "", location.pathname);
    const form = document.querySelector("form");
    for (const name of ${JSON.stringify(fields)}) {
      const field = form.elements.namedItem(name);
      field.value = params.get(name) || "";
    }
    const valid = params.get("token")?.length > 0;
    document.querySelector("button").disabled = !valid;
    if (!valid) document.querySelector("[role=status]").textContent = "Este enlace no es válido. Solicita uno nuevo.";
  `;
  return {
    html: `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Confirmar acceso</title></head><body><main><h1>Confirmar acceso</h1><p>Continúa para iniciar sesión en esta aplicación.</p><p role="status" aria-live="polite"></p><form method="post" action="${action}">${inputs}<button type="submit">Continuar</button></form></main><script nonce="${nonce}">${script}</script></body></html>`,
    contentSecurityPolicy: `default-src 'none'; script-src 'nonce-${nonce}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
  };
}

export function toNodeHandler(auth: {
  handler: (request: Request) => Promise<Response>;
}) {
  const handler = betterAuthNodeHandler(auth);
  const secret = (auth as typeof auth & { [trustedClientIPSecret]?: string })[trustedClientIPSecret];
  return (request: IncomingMessage, response: ServerResponse) => {
    const ip = request.socket.remoteAddress ?? "127.0.0.1";
    request.headers[clientIPHeader] = ip;
    if (secret) request.headers[clientIPSignatureHeader] = clientIPSignature(secret, ip);
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
    passwordHash?: Argon2idParameters;
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
  const minPasswordLength = options.minPasswordLength ?? 15;
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
  const magicLinkConfirmPath = `${basePath}/magic-link/confirm`;
  const magicLinkConsumePath = `${basePath}/magic-link/consume`;
  const magicLinkVerifyPath = `${basePath}/magic-link/verify`;
  const revokeSessionByIdPath = `${basePath}/revoke-session-by-id`;
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
  const limits = securityStore(database, options.database.dialect === "postgres", prefix);
  const passwordHashParameters = { ...(options.security?.passwordHash ?? DEFAULT_ARGON2ID_PARAMETERS) };
  if (!Number.isInteger(passwordHashParameters.memoryKiB) || passwordHashParameters.memoryKiB < 19_456 || passwordHashParameters.memoryKiB > 262_144 ||
      !Number.isInteger(passwordHashParameters.passes) || passwordHashParameters.passes < 2 || passwordHashParameters.passes > 10 ||
      !Number.isInteger(passwordHashParameters.parallelism) || passwordHashParameters.parallelism < 1 || passwordHashParameters.parallelism > 8 ||
      passwordHashParameters.memoryKiB < 8 * passwordHashParameters.parallelism)
    throw new Error("Los parámetros Argon2id deben usar al menos 19 MiB y estar dentro de los límites admitidos.");
  const deliver = async (
    kind: MailMessage["kind"],
    to: string,
    url: string,
  ) => {
    if (!options.sendMail)
      throw new Error("El envío de correo no está configurado.");
    const recipientKey = createHmac("sha256", options.secret)
      .update(`mail:${kind}:${to.trim().toLowerCase()}`)
      .digest("hex");
    if (!await limits.consume(`mail-minute:${recipientKey}`, 2, 60_000) ||
        !await limits.consume(`mail-hour:${recipientKey}`, 8, 60 * 60_000))
      return;
    try {
      await options.sendMail({ kind, to, url, appId: options.appId });
    } catch {
      throw new Error("No se pudo enviar el correo de autenticación.");
    }
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
  const validatePasswordPolicy = (password: string) => checkPassword(password, minPasswordLength, policy);
  type SecuritySession = {
    user: { id: string; email: string; disabled?: boolean };
    session: {
      id: string;
      token: string;
      createdAt: Date;
      updatedAt: Date;
      expiresAt: Date;
      recentlyVerifiedAt?: number;
    };
  };
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
        const email = ctx.body?.email;
        if (typeof email === "string" && Buffer.byteLength(email, "utf8") > 254)
          throw new PasswordPolicyError("INVALID_EMAIL", "Correo electrónico no válido.");
        const password = ctx.body?.newPassword ?? ctx.body?.password;
        if (typeof password === "string" && Buffer.byteLength(password, "utf8") > 1024)
          throw new PasswordPolicyError("INVALID_PASSWORD", "La contraseña no es válida.");
        const inputToken = ctx.body?.token ?? ctx.query?.token;
        if (typeof inputToken === "string" && Buffer.byteLength(inputToken, "utf8") > 512)
          throw new PasswordPolicyError("INVALID_TOKEN", "El enlace no es válido.");
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
        if (["/sign-up/email", "/change-password", "/reset-password"].includes(ctx.path) && typeof password === "string")
          await validatePasswordPolicy(password);
        if (["/sign-in/email", "/sign-in/username"].includes(ctx.path)) {
          const identity = String(ctx.body?.email ?? ctx.body?.username ?? "").trim().toLowerCase();
          const ip = getIP(new Headers(ctx.headers), authOptions);
          if (ip) {
            const key = createHmac("sha256", options.secret).update(`login:${ip}:${identity}`).digest("hex");
            if (!await limits.consume(key, 20)) throw new PasswordPolicyError("TRY_LATER", "Demasiados intentos. Espera antes de volver a entrar.");
          }
        }
        if ([
          "/passkey/generate-register-options", "/passkey/verify-registration", "/passkey/delete-passkey", "/passkey/update-passkey",
          "/revoke-session", "/revoke-other-sessions", "/update-user", "/change-email",
          "/two-factor/enable", "/two-factor/disable", "/two-factor/get-totp-uri", "/two-factor/generate-backup-codes",
        ].includes(ctx.path))
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
    if (["/sign-in/email", "/sign-in/username"].includes(ctx.path) && typeof ctx.body?.password === "string" && ctx.context.newSession) {
      const userId = ctx.context.newSession.user.id;
      const credential = await ctx.context.internalAdapter.findCredentialAccount(userId);
      if (credential?.password && passwordNeedsRehash(credential.password, passwordHashParameters)) {
        try {
          const replacement = await ctx.context.password.hash(ctx.body.password);
          if (credential.password === (await ctx.context.internalAdapter.findCredentialAccount(userId))?.password)
            await ctx.context.internalAdapter.updatePassword(userId, replacement);
        } catch {
          // Keep a successful login successful; retry the upgrade on the next login.
        }
      }
    }
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
      encryptOAuthTokens: true,
    },
    verification: {
      modelName: `${prefix}_verification`,
      storeIdentifier: "hashed",
      storeInDatabase: true,
    },
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
      password: {
        hash: (password) => hashPassword(password, passwordHashParameters),
        verify: verifyPassword,
      },
      disableSignUp: !registration,
      minPasswordLength,
      maxPasswordLength: 256,
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
            }) => {
              try {
                await deliver("reset-password", user.email, url);
              } catch {
                // Keep the reset response identical for existing and unknown accounts.
              }
            },
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
              sendMagicLink: async ({ email, url }) => {
                const verification = new URL(url, origin.origin);
                if (verification.origin !== origin.origin || verification.pathname !== magicLinkVerifyPath)
                  throw new Error("Better Auth generó una URL de magic link inesperada.");
                const fragment = new URLSearchParams();
                for (const key of ["token", "callbackURL", "newUserCallbackURL", "errorCallbackURL"] as const) {
                  const value = verification.searchParams.get(key);
                  if (value !== null) fragment.set(key, value);
                }
                const token = fragment.get("token");
                if (!token || Buffer.byteLength(token, "utf8") > 512)
                  throw new Error("Better Auth generó un token de magic link no válido.");
                const confirmation = new URL(magicLinkConfirmPath, origin.origin);
                confirmation.hash = fragment.toString();
                await deliver("magic-link", email, confirmation.toString());
              },
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
  const rawAuthOptions = {
    ...authOptions,
    database: database as BetterAuthOptions["database"],
  };
  const runtimeAuthOptions: BetterAuthOptions = {
    ...authOptions,
    database: createSessionTokenAdapter(getAdapter(rawAuthOptions), options.secret),
  };
  const initializeAuth = () => betterAuth(runtimeAuthOptions);
  let authInstance: ReturnType<typeof initializeAuth> | undefined;
  const getAuth = () => (authInstance ??= initializeAuth());
  let bouncerHandler: ((request: Request) => Promise<Response>) | undefined;
  const getExposedAuth = () => new Proxy(getAuth(), {
    get(target, property) {
      if (property === "handler")
        return (request: Request) => {
          if (!bouncerHandler) throw new Error("El handler de Bouncer aún no está inicializado.");
          return bouncerHandler(request);
        };
      if (property === "api") {
        const api = Reflect.get(target, property, target) as object;
        return new Proxy(api, {
          get(apiTarget, apiProperty) {
            const value = Reflect.get(apiTarget, apiProperty, apiTarget);
            if (typeof value !== "function") return value;
            return new Proxy(value, {
              apply(method, thisArg, args) {
                return Promise.resolve(Reflect.apply(method, thisArg, args)).then(redactSensitiveOutput);
              },
            });
          },
        });
      }
      return Reflect.get(target, property, target);
    },
  });
  type ExposedAuth = Omit<ReturnType<typeof initializeAuth>, "api"> & {
    api: RedactedAPI<ReturnType<typeof initializeAuth>["api"]>;
  };
  const getValidSession = async (headers: Headers): Promise<SecuritySession | null> => {
    const session = await getAuth().api.getSession({
      headers,
      query: { disableRefresh: true, disableCookieCache: true },
    });
    if (!session) return null;
    const now = Date.now();
    const expired =
      ("disabled" in session.user && session.user.disabled === true) ||
      now - new Date(session.session.updatedAt).getTime() > 12 * 3600_000 ||
      now - new Date(session.session.createdAt).getTime() > 7 * 86400_000 ||
      new Date(session.session.expiresAt).getTime() <= now;
    if (expired) {
      await (await getAuth().$context).internalAdapter.deleteSession(session.session.token);
      return null;
    }
    return session as SecuritySession;
  };
  const getPublicSession = async (headers: Headers) => {
    const session = await getValidSession(headers);
    if (!session) return null;
    const { token: _token, ...safeSession } = session.session;
    return { ...session, session: safeSession };
  };
  sessionForHeaders = getValidSession;
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
  const bouncer = {
    get auth() {
      return getExposedAuth() as ExposedAuth;
    },
    capabilities,
    handler: async (request: Request): Promise<Response> => {
      if (!options.ipAddress) {
        const ip = request.headers.get(clientIPHeader) ?? "";
        const suppliedSignature = Buffer.from(request.headers.get(clientIPSignatureHeader) ?? "", "utf8");
        const expectedSignature = Buffer.from(clientIPSignature(options.secret, ip), "utf8");
        if (!ip || suppliedSignature.length !== expectedSignature.length || !timingSafeEqual(suppliedSignature, expectedSignature)) {
          const headers = new Headers(request.headers);
          headers.delete(clientIPHeader);
          headers.delete(clientIPSignatureHeader);
          request = new Request(request, { headers });
        }
      }
      const url = new URL(request.url);
      if (url.href.length > 8192)
        return Response.json({ code: "REQUEST_TOO_LARGE" }, { status: 414, headers: securityResponseHeaders() });
      if (request.method !== "GET" && request.method !== "HEAD") {
        const maximumBytes =
          url.pathname === magicLinkConsumePath || url.pathname === `${basePath}/reauthenticate` || url.pathname === revokeSessionByIdPath
            ? 8192
            : 256 * 1024;
        const limited = await limitRequestBody(request, maximumBytes);
        if ("error" in limited)
          return Response.json(
            { code: limited.error === "too-large" ? "REQUEST_TOO_LARGE" : "INVALID_REQUEST" },
            { status: limited.error === "too-large" ? 413 : 400, headers: securityResponseHeaders() },
          );
        request = limited.request;
      }
      if (url.pathname === magicLinkConfirmPath) {
        if (request.method !== "GET")
          return Response.json({ code: "METHOD_NOT_ALLOWED" }, { status: 405, headers: securityResponseHeaders() });
        const nonce = randomBytes(18).toString("base64url");
        const page = magicLinkConfirmationPage(magicLinkConsumePath, nonce);
        const headers = securityResponseHeaders({ "content-type": "text/html; charset=utf-8" });
        headers.set("content-security-policy", page.contentSecurityPolicy);
        headers.set("x-frame-options", "DENY");
        return new Response(page.html, { headers });
      }
      if (url.pathname === magicLinkConsumePath) {
        const requestOrigin = request.headers.get("origin");
        const sameOriginFetch = request.headers.get("sec-fetch-site") === "same-origin";
        if (
          request.method !== "POST" ||
          (requestOrigin !== origin.origin && !(requestOrigin === "null" && sameOriginFetch)) ||
          request.headers.get("content-type")?.split(";")[0] !== "application/x-www-form-urlencoded"
        )
          return Response.json({ code: "FORBIDDEN" }, { status: 403, headers: securityResponseHeaders() });
        const values = new URLSearchParams(await request.text());
        const fields = ["token", "callbackURL", "newUserCallbackURL", "errorCallbackURL"];
        if (fields.some((key) => values.getAll(key).length > 1))
          return Response.json({ code: "INVALID_TOKEN" }, { status: 400, headers: securityResponseHeaders() });
        const token = values.get("token");
        if (!token || Buffer.byteLength(token, "utf8") > 512)
          return Response.json({ code: "INVALID_TOKEN" }, { status: 400, headers: securityResponseHeaders() });
        const verification = new URL(magicLinkVerifyPath, origin.origin);
        verification.searchParams.set("token", token);
        for (const key of fields.slice(1)) {
          const value = values.get(key);
          if (value && Buffer.byteLength(value, "utf8") <= 2048)
            verification.searchParams.set(key, value);
          else if (value)
            return Response.json({ code: "INVALID_REQUEST" }, { status: 400, headers: securityResponseHeaders() });
        }
        const headers = new Headers(request.headers);
        headers.delete("content-type");
        headers.delete("content-length");
        headers.delete("transfer-encoding");
        headers.set("origin", origin.origin);
        const result = await getAuth().handler(new Request(verification, { method: "GET", headers }));
        const resultHeaders = securityResponseHeaders(result.headers);
        return new Response(result.body, {
          status: result.status,
          statusText: result.statusText,
          headers: resultHeaders,
        });
      }
      if (
        url.pathname === `${basePath}/bouncer-config` &&
        request.method === "GET"
      ) {
        return Response.json(capabilities, {
          headers: securityResponseHeaders(),
        });
      }
      if (url.pathname === `${basePath}/reauthenticate`) {
        try {
          if (request.method !== "POST" || request.headers.get("origin") !== origin.origin || request.headers.get("content-type")?.split(";")[0] !== "application/json")
            return Response.json({ code: "FORBIDDEN" }, { status: 403, headers: securityResponseHeaders() });
          const session = await sessionForHeaders(request.headers);
          if (!session) return Response.json({ code: "SESSION_EXPIRED" }, { status: 401, headers: securityResponseHeaders() });
          const key = createHmac("sha256", options.secret).update("reauth:" + session.user.id).digest("hex");
          if (!await limits.consume(key, 5)) return Response.json({ code: "TRY_LATER" }, { status: 429, headers: securityResponseHeaders() });
          const text = await request.text();
          if (Buffer.byteLength(text) > 8192) return Response.json({ code: "REQUEST_TOO_LARGE" }, { status: 413, headers: securityResponseHeaders() });
          let body: unknown;
          try { body = JSON.parse(text); }
          catch { return Response.json({ code: "INVALID_REQUEST" }, { status: 400, headers: securityResponseHeaders() }); }
          if (!body || typeof body !== "object" || Array.isArray(body)) return Response.json({ code: "INVALID_REQUEST" }, { status: 400, headers: securityResponseHeaders() });
          const password = (body as { password?: unknown }).password;
          if (typeof password !== "string" || Buffer.byteLength(password) > 1024) return Response.json({ code: "INVALID_PASSWORD" }, { status: 400, headers: securityResponseHeaders() });
          const ctx = await getAuth().$context;
          const accounts = await ctx.internalAdapter.findAccounts(session.user.id);
          const credential = accounts.find((account) => account.providerId === "credential");
          if (!credential?.password || !await ctx.password.verify({ password, hash: credential.password }))
            return Response.json({ code: "INVALID_PASSWORD" }, { status: 401, headers: securityResponseHeaders() });
          await ctx.adapter.update({ model: "session", where: [{ field: "id", value: session.session.id }], update: { recentlyVerifiedAt: Math.floor(Date.now() / 1000) } });
          return Response.json({ status: true }, { headers: securityResponseHeaders() });
        } catch { return Response.json({ code: "REAUTH_UNAVAILABLE" }, { status: 503, headers: securityResponseHeaders() }); }
      }
      if (url.pathname === revokeSessionByIdPath) {
        try {
          if (request.method !== "POST" || request.headers.get("origin") !== origin.origin || request.headers.get("content-type")?.split(";")[0] !== "application/json")
            return Response.json({ code: "FORBIDDEN" }, { status: 403, headers: securityResponseHeaders() });
          const session = await sessionForHeaders(request.headers);
          if (!session) return Response.json({ code: "SESSION_EXPIRED" }, { status: 401, headers: securityResponseHeaders() });
          const verified = Math.max(new Date(session.session.createdAt).getTime(), (session.session.recentlyVerifiedAt ?? 0) * 1000);
          if (Date.now() - verified > reauthenticationWindow * 1000)
            return Response.json({ code: "REAUTH_REQUIRED" }, { status: 403, headers: securityResponseHeaders() });
          const rateKey = createHmac("sha256", options.secret).update(`revoke-session:${session.user.id}`).digest("hex");
          if (!await limits.consume(rateKey, 10, 60_000))
            return Response.json({ code: "TRY_LATER" }, { status: 429, headers: securityResponseHeaders() });
          let body: unknown;
          try { body = JSON.parse(await request.text()); }
          catch { return Response.json({ code: "INVALID_REQUEST" }, { status: 400, headers: securityResponseHeaders() }); }
          if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).some((key) => key !== "id"))
            return Response.json({ code: "INVALID_REQUEST" }, { status: 400, headers: securityResponseHeaders() });
          const id = (body as { id?: unknown }).id;
          if (typeof id !== "string" || id.length < 1 || id.length > 128)
            return Response.json({ code: "INVALID_REQUEST" }, { status: 400, headers: securityResponseHeaders() });
          const ctx = await getAuth().$context;
          const target = (await ctx.internalAdapter.listSessions(session.user.id, { onlyActiveSessions: true }))
            .find((candidate) => candidate.id === id);
          if (target) await ctx.internalAdapter.deleteSession(target.token);
          return Response.json({ status: true }, { headers: securityResponseHeaders() });
        } catch {
          return Response.json({ code: "SESSION_OPERATION_UNAVAILABLE" }, { status: 503, headers: securityResponseHeaders() });
        }
      }
      const response = await redactSensitiveResponse(await getAuth().handler(request));
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: securityResponseHeaders(response.headers),
      });
    },
    migrate: async () => {
      const migration = await getMigrations(rawAuthOptions);
      await migration.runMigrations();
      await limits.migrate();
      await limits.migrateCredentialStorage(
        `${prefix}_session`,
        `${prefix}_verification`,
        `${prefix}_account`,
        (token) => hashSessionToken(options.secret, token),
        (token) => symmetricEncrypt({ key: options.secret, data: token }),
      );
    },
    getSession: getPublicSession,
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
        return this.importCredentialUser({ ...input, passwordHash: await hashPassword(input.password, passwordHashParameters) });
      },
      async setPassword(userId: string, password: string) {
        await validatePasswordPolicy(password);
        const ctx = await getAuth().$context;
        const passwordHash = await hashPassword(password, passwordHashParameters);
        await runWithTransaction(ctx.adapter, async () => {
          await ctx.internalAdapter.deleteUserSessions(userId);
          await ctx.internalAdapter.updatePassword(userId, passwordHash);
        });
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
  Object.defineProperty(bouncer, trustedClientIPSecret, { value: options.secret });
  bouncerHandler = bouncer.handler;
  return bouncer;
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
