import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { passkey } from "@better-auth/passkey";
import { magicLink, username } from "better-auth/plugins";
import Database from "better-sqlite3";
import { Pool, type PoolConfig } from "pg";
import { toNodeHandler as betterAuthNodeHandler } from "better-auth/node";
import { isIP } from "node:net";
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
    | { dialect: "sqlite"; filename: string }
    | { dialect: "sqlite"; connection: Database.Database };
  trustedOrigins?: string[];
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
    process.env.NODE_ENV === "production"
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
    ...(!usernamePassword ? ["/sign-in/username"] : []),
    ...(!passwordEnabled || !(options.registration ?? true)
      ? ["/sign-up/email"]
      : []),
    ...(!passwordReset
      ? [
          "/request-password-reset",
          "/reset-password",
          "/change-password",
          "/set-password",
        ]
      : []),
  ];
  const authOptions = {
    appName: options.appName ?? options.appId,
    baseURL: options.baseURL,
    basePath,
    secret: options.secret,
    database: database as BetterAuthOptions["database"],
    disabledPaths,
    trustedOrigins: options.trustedOrigins ?? [origin.origin],
    user: { modelName: `${prefix}_user` },
    session: {
      modelName: `${prefix}_session`,
      expiresIn: 60 * 60 * 24 * 7,
      updateAge: 60 * 60 * 24,
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
      cookiePrefix: prefix,
      useSecureCookies: origin.protocol === "https:",
      defaultCookieAttributes: {
        httpOnly: true,
        sameSite: "lax",
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
                origin: options.trustedOrigins ?? [origin.origin],
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
  const capabilities = {
    registration,
    requireEmailVerification: options.requireEmailVerification ?? true,
    emailPassword,
    usernamePassword,
    minPasswordLength,
    magicLink: magicLinkEnabled,
    passwordReset,
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
      return getAuth().handler(request);
    },
    migrate: async () => {
      const migration = await getMigrations(authOptions);
      await migration.runMigrations();
    },
    getSession: (headers: Headers) => getAuth().api.getSession({ headers }),
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
