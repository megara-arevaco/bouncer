import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, createHmac, createHash, scrypt, argon2 } from "node:crypto";
import { Pool } from "pg";
import {
  createBouncer,
  createDevelopmentMailbox,
  hashPassword,
  verifyPassword,
  toNodeHandler,
  fromNodeHeaders,
  type BouncerOptions,
} from "../packages/api/src/index.js";
import { securityStore } from "../packages/api/src/security-store.js";

const apiRequire = createRequire(new URL("../packages/api/package.json", import.meta.url));
const Database = apiRequire("better-sqlite3") as typeof import("better-sqlite3");

async function fixture(
  appId: string,
  registration = true,
  overrides: Partial<BouncerOptions> = {},
) {
  const dir = await mkdtemp(join(tmpdir(), "bouncer-test-"));
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  const baseURL = `http://localhost:${address.port}`;
  const mailbox = createDevelopmentMailbox();
  const admin = process.env.TEST_DATABASE_URL
    ? new Pool({ connectionString: process.env.TEST_DATABASE_URL })
    : null;
  const dbName = `bouncer_${appId}_${randomBytes(6).toString("hex")}`;
  if (admin) await admin.query(`CREATE DATABASE ${dbName}`);
  const connectionURL = process.env.TEST_DATABASE_URL
    ? new URL(process.env.TEST_DATABASE_URL)
    : null;
  if (connectionURL) connectionURL.pathname = `/${dbName}`;
  const bouncer = createBouncer({
    appId,
    baseURL,
    secret: randomBytes(48).toString("hex"),
    registration,
    database: process.env.TEST_DATABASE_URL
      ? {
          dialect: "postgres",
          config: { connectionString: connectionURL!.href },
        }
      : { dialect: "sqlite", filename: join(dir, "auth.sqlite") },
    sendMail: mailbox.sendMail,
    ...overrides,
  });
  await bouncer.migrate();
  const handler = toNodeHandler(bouncer);
  server.on("request", async (request, response) => {
    if (request.url === "/api/private") {
      const session = await bouncer.getSession(
        fromNodeHeaders(request.headers),
      );
      response.writeHead(session ? 200 : 401, {
        "content-type": "application/json",
      });
      response.end(
        JSON.stringify(
          session ? { email: session.user.email } : { error: "Unauthorized" },
        ),
      );
      return;
    }
    await handler(request, response);
  });
  const call = (
    path: string,
    body?: object,
    cookie?: string,
    origin = baseURL,
  ) =>
    fetch(`${baseURL}/api/auth${path}`, {
      method: body ? "POST" : "GET",
      headers: {
        origin,
        ...(body ? { "content-type": "application/json" } : {}),
        ...(cookie ? { cookie } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      redirect: "manual",
    });
  return {
    bouncer,
    mailbox,
    call,
    baseURL,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await bouncer.close();
      if (admin) {
        await admin.query(`DROP DATABASE ${dbName}`);
        await admin.end();
      }
      await rm(dir, { recursive: true, force: true });
    },
  };
}
function cookie(response: Response) {
  return response.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .filter((value) => !value.endsWith("="))
    .join("; ");
}
function submitMagicLink(baseURL: string, link: string, origin = baseURL) {
  const values = new URLSearchParams(new URL(link).hash.slice(1));
  return fetch(`${baseURL}/api/auth/magic-link/consume`, {
    method: "POST",
    headers: {
      origin,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: values,
    redirect: "manual",
  });
}
const user = {
  name: "Baul",
  email: "baul@example.test",
  password: "Bouncer isolated fixture phrase 7391",
};

async function legacyScryptHash(password: string) {
  const salt = randomBytes(16).toString("hex");
  const hash = await new Promise<Buffer>((resolve, reject) => scrypt(
    password.normalize("NFKC"),
    salt,
    64,
    { N: 16_384, r: 16, p: 1, maxmem: 128 * 16_384 * 16 * 2 },
    (error, key) => error ? reject(error) : resolve(key),
  ));
  return `${salt}:${hash.toString("hex")}`;
}

test("password helpers reject inputs over the byte limit before hashing", async () => {
  const oversized = "x".repeat(1025);
  await assert.rejects(hashPassword(oversized), { code: "PASSWORD_LENGTH" });
  assert.equal(await verifyPassword({ password: oversized, hash: "legacy-scrypt-placeholder" }), false);
});

test("Argon2id acepta parámetros configurables y verifica formatos heredados", async () => {
  const password = "Phrase avec Unicode 🧭 et gestionnaire 4821";
  const parameters = { memoryKiB: 19_456, passes: 2, parallelism: 2 };
  const current = await hashPassword(password, parameters);
  assert.match(current, /^argon2id-v2:19456:2:2:/);
  assert.equal(await verifyPassword({ password, hash: current }), true);

  const salt = randomBytes(16);
  const oldArgonTag = await new Promise<Buffer>((resolve, reject) => argon2("argon2id", {
    message: password,
    nonce: salt,
    memory: 19_456,
    passes: 2,
    parallelism: 1,
    tagLength: 32,
  }, (error, value) => error ? reject(error) : resolve(value)));
  assert.equal(await verifyPassword({ password, hash: `argon2id-v1:${salt.toString("hex")}:${oldArgonTag.toString("hex")}` }), true);

  const legacy = await legacyScryptHash(password);
  assert.equal(await verifyPassword({ password, hash: legacy }), true);
  assert.equal(await verifyPassword({ password: "incorrect password", hash: legacy }), false);
  assert.equal(await verifyPassword({ password, hash: "plaintext-password" }), false);
  assert.equal(await verifyPassword({ password, hash: `${legacy}:unexpected` }), false);
});

test("password reset response stays generic when email delivery fails", async () => {
  let deliveryUnavailable = false;
  const f = await fixture("reset_delivery", true, {
    requireEmailVerification: false,
    methods: { emailPassword: true },
    sendMail: async ({ url }) => {
      if (deliveryUnavailable) throw new Error(`SMTP failure for ${url}`);
    },
  });
  try {
    await f.call("/sign-up/email", { email: "known@example.test", name: "Known", password: "Bouncer reset fixture phrase 1284" });
    deliveryUnavailable = true;
    const [known, unknown] = await Promise.all([
      f.call("/request-password-reset", { email: "known@example.test" }),
      f.call("/request-password-reset", { email: "unknown@example.test" }),
    ]);
    assert.equal(known.status, 200);
    assert.equal(unknown.status, 200);
    assert.deepEqual(await known.json(), await unknown.json());
  } finally { await f.close(); }
});

test("un login válido migra progresivamente un hash scrypt a Argon2id", async () => {
  const f = await fixture("password_rehash", true, {
    requireEmailVerification: false,
    methods: { emailPassword: true },
  });
  const email = "rehash@example.test";
  const password = "Bouncer legacy password phrase 4927";
  try {
    await f.call("/sign-up/email", { email, name: "Rehash", password });
    const ctx = await f.bouncer.auth.$context;
    const user = await ctx.internalAdapter.findUserByEmail(email, { includeAccounts: true });
    assert(user);
    const credential = user.accounts.find((account) => account.providerId === "credential");
    assert(credential);
    await ctx.adapter.update({
      model: "account",
      where: [{ field: "id", value: credential.id }],
      update: { password: await legacyScryptHash(password) },
    });

    assert.equal((await f.call("/sign-in/email", { email, password })).status, 200);
    const upgraded = await ctx.internalAdapter.findCredentialAccount(user.user.id);
    assert(upgraded?.password);
    assert.match(upgraded.password, /^argon2id-v2:/);
    assert.equal(await verifyPassword({ password, hash: upgraded.password }), true);
  } finally { await f.close(); }
});

test("admin.setPassword actualiza la credencial y revoca sesiones juntas", async () => {
  const f = await fixture("admin_password", true, {
    requireEmailVerification: false,
    methods: { emailPassword: true },
  });
  const email = "admin-password@example.test";
  const oldPassword = "Bouncer admin password fixture 3481";
  const newPassword = "Bouncer admin replacement phrase 6274";
  try {
    await f.call("/sign-up/email", { email, name: "Admin password", password: oldPassword });
    const login = await f.call("/sign-in/email", { email, password: oldPassword });
    const oldCookie = cookie(login);
    const session = await f.bouncer.getSession(new Headers({ cookie: oldCookie }));
    assert(session);

    await f.bouncer.admin.setPassword(session.user.id, newPassword);

    assert.equal(await f.bouncer.getSession(new Headers({ cookie: oldCookie })), null);
    assert.equal((await f.call("/sign-in/email", { email, password: oldPassword })).status, 401);
    assert.equal((await f.call("/sign-in/email", { email, password: newPassword })).status, 200);
  } finally { await f.close(); }
});

test("migración protege sesiones, verificaciones y tokens OAuth heredados", async () => {
  const database = new Database(":memory:");
  const secret = "bouncer migration fixture secret 8472";
  try {
    database.exec(`
      CREATE TABLE "bouncer_migrate_session" ("id" TEXT PRIMARY KEY, "token" TEXT NOT NULL);
      CREATE TABLE "bouncer_migrate_verification" ("id" TEXT PRIMARY KEY, "identifier" TEXT NOT NULL);
      CREATE TABLE "bouncer_migrate_account" (
        "id" TEXT PRIMARY KEY, "accessToken" TEXT, "refreshToken" TEXT, "idToken" TEXT
      );
    `);
    database.prepare(`INSERT INTO "bouncer_migrate_session" VALUES (?, ?)`)
      .run("session-1", "legacy-session-token");
    database.prepare(`INSERT INTO "bouncer_migrate_verification" VALUES (?, ?)`)
      .run("verification-1", "reset-password:legacy-reset-token");
    database.prepare(`INSERT INTO "bouncer_migrate_account" VALUES (?, ?, ?, ?)`)
      .run("account-1", "legacy-access-token", "legacy-refresh-token", null);

    const store = securityStore(database, false, "bouncer_migrate");
    await store.migrate();
    await store.migrateCredentialStorage(
      "bouncer_migrate_session",
      "bouncer_migrate_verification",
      "bouncer_migrate_account",
      (token) => `bouncer-session-hmac-v1:${token}`,
      async (token) => Buffer.from(`${secret}:${token}`).toString("hex"),
    );

    const session = database.prepare(`SELECT "token" FROM "bouncer_migrate_session" WHERE "id" = ?`).get("session-1") as { token: string };
    assert.equal(session.token, "bouncer-session-hmac-v1:legacy-session-token");
    const verification = database.prepare(`SELECT "identifier" FROM "bouncer_migrate_verification" WHERE "id" = ?`).get("verification-1") as { identifier: string };
    assert.equal(verification.identifier, createHash("sha256").update("reset-password:legacy-reset-token").digest("base64url"));
    const account = database.prepare(`SELECT "accessToken", "refreshToken" FROM "bouncer_migrate_account" WHERE "id" = ?`).get("account-1") as { accessToken: string; refreshToken: string };
    assert.match(account.accessToken, /^[a-f0-9]+$/);
    assert.match(account.refreshToken, /^[a-f0-9]+$/);
    assert.equal(Buffer.from(account.accessToken, "hex").toString(), `${secret}:legacy-access-token`);
    assert.equal(Buffer.from(account.refreshToken, "hex").toString(), `${secret}:legacy-refresh-token`);
    database.prepare(`DELETE FROM "bouncer_migrate_security_meta" WHERE "key" = ?`)
      .run("oauth-tokens-encrypted-v1");
    await store.migrateCredentialStorage(
      "bouncer_migrate_session",
      "bouncer_migrate_verification",
      "bouncer_migrate_account",
      (token) => `bouncer-session-hmac-v1:${token}`,
      async (token) => Buffer.from(`${secret}:${token}`).toString("hex"),
    );
    const stillEncrypted = database.prepare(`SELECT "accessToken" FROM "bouncer_migrate_account" WHERE "id" = ?`).get("account-1") as { accessToken: string };
    assert.equal(stillEncrypted.accessToken, account.accessToken);
  } finally { database.close(); }
});

test("handler Fetch no confía en una cabecera de IP falsificada", async () => {
  const f = await fixture("forged_ip", true, {
    requireEmailVerification: false,
    methods: { emailPassword: true },
  });
  const email = "forged-ip@example.test";
  const password = "Bouncer forged client IP fixture 5284";
  try {
    await f.call("/sign-up/email", { email, name: "Forged IP", password });
    const response = await f.bouncer.handler(new Request(`${f.baseURL}/api/auth/sign-in/email`, {
      method: "POST",
      headers: {
        origin: f.baseURL,
        "content-type": "application/json",
        "x-bouncer-client-ip": "203.0.113.77",
      },
      body: JSON.stringify({ email, password }),
    }));
    assert.equal(response.status, 200);
    const session = await f.bouncer.getSession(new Headers({ cookie: cookie(response) }));
    assert(session);
    const ctx = await f.bouncer.auth.$context;
    const storedSession = await ctx.adapter.findOne({ model: "session", where: [{ field: "id", value: session.session.id }] });
    assert.notEqual((storedSession as { ipAddress?: string } | null)?.ipAddress, "203.0.113.77");
  } finally { await f.close(); }
});

test("HTTP: registro, verificación, login, sesiones, recuperación y aislamiento", async () => {
  const a = await fixture("alpha");
  const b = await fixture("bravo");
  try {
    const config = await (await a.call("/bouncer-config")).json();
    assert.equal(config.magicLink, true);
    assert.deepEqual(config.socialProviders, []);
    assert.equal((await a.call("/sign-up/email", user)).status, 200);
    const stored = await a.bouncer.auth.$context;
    const account = await stored.internalAdapter.findAccounts(
      (await stored.internalAdapter.findUserByEmail(user.email))!.user.id,
    );
    assert(account[0].password && account[0].password !== user.password);
    assert.match(account[0].password!, /^argon2id-v2:/);
    assert.equal(stored.options.account?.encryptOAuthTokens, true);
    assert.equal((await a.call("/sign-in/email", user)).status, 403);
    const verification = a.mailbox.messages.find(
      (message) => message.kind === "verify-email",
    )!;
    assert(verification);
    assert.equal(
      (await fetch(verification.url, { redirect: "manual" })).status,
      302,
    );
    const login = await a.call("/sign-in/email", user);
    assert.equal(login.status, 200);
    assert.equal("token" in await login.clone().json(), false);
    const firstCookie = cookie(login);
    assert(firstCookie.includes("bouncer_alpha"));
    assert(
      login.headers.getSetCookie().some((value) => /; Path=\//i.test(value)),
    );
    const privateResponse = await fetch(`${a.baseURL}/api/private`, {
      headers: { cookie: firstCookie },
    });
    assert.equal(privateResponse.status, 200);
    assert.equal((await privateResponse.json()).email, user.email);
    assert.equal((await fetch(`${a.baseURL}/api/private`)).status, 401);
    const sessionResponse = await a.call(
      "/get-session",
      undefined,
      firstCookie,
    );
    const sessionBody = await sessionResponse.json();
    assert.equal(sessionBody.user.email, user.email);
    assert.equal("token" in sessionBody.session, false);
    const publicSession = await a.bouncer.getSession(new Headers({ cookie: firstCookie }));
    assert(publicSession && !("token" in publicSession.session));
    const directApiSession = await a.bouncer.auth.api.getSession({ headers: new Headers({ cookie: firstCookie }) });
    assert(directApiSession && !("token" in directApiSession.session));
    const userId = (await stored.internalAdapter.findUserByEmail(user.email))!.user.id;
    const persistedSessions = await stored.adapter.findMany({ model: "session", where: [{ field: "userId", value: userId }] });
    assert(persistedSessions.length > 0);
    assert(persistedSessions.every((session) => String((session as { token: string }).token).startsWith("bouncer-session-hmac-v1:")));
    assert.equal(
      await (await b.call("/get-session", undefined, firstCookie)).json(),
      null,
    );
    assert.equal((await b.call("/sign-in/email", user)).status, 401);
    const secondLogin = await a.call("/sign-in/email", user);
    assert.equal(secondLogin.status, 200);
    const secondCookie = cookie(secondLogin);
    const listedSessions = await (await a.call("/list-sessions", undefined, firstCookie)).json();
    assert.equal(listedSessions.length, 2);
    assert(listedSessions.every((session: Record<string, unknown>) => !("token" in session)));
    const secondSession = await (await a.call("/get-session", undefined, secondCookie)).json();
    assert.equal((await a.call("/reauthenticate", { password: user.password }, firstCookie)).status, 200);
    assert.equal((await a.call("/revoke-session-by-id", { id: secondSession.session.id }, firstCookie)).status, 200);
    assert.equal(await (await a.call("/get-session", undefined, secondCookie)).json(), null);
    assert.equal(
      (await a.call("/revoke-other-sessions", {}, firstCookie)).status,
      200,
    );
    assert.equal(
      await (await a.call("/get-session", undefined, secondCookie)).json(),
      null,
    );
    assert.equal(
      (
        await a.call(
          "/revoke-sessions",
          {},
          firstCookie,
          "https://attacker.example",
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await a.call("/request-password-reset", {
          email: user.email,
          redirectTo: a.baseURL + "/reset-password",
        })
      ).status,
      200,
    );
    const reset = a.mailbox.messages.find(
      (message) => message.kind === "reset-password",
    )!;
    assert(reset);
    const rawResetToken = new URL(reset.url).pathname.split("/").at(-1)!;
    const resetRows = await stored.adapter.findMany({
      model: "verification",
      where: [{ field: "identifier", value: createHash("sha256").update(`reset-password:${rawResetToken}`).digest("base64url") }],
    });
    const hashedResetIdentifier = createHash("sha256").update(`reset-password:${rawResetToken}`).digest("base64url");
    assert(resetRows.some((row) => (row as { identifier: string }).identifier === hashedResetIdentifier));
    assert(resetRows.every((row) => !(row as { identifier: string }).identifier.includes(rawResetToken)));
    const resetRedirect = await fetch(reset.url, { redirect: "manual" });
    assert.equal(resetRedirect.status, 302);
    const token = new URL(
      resetRedirect.headers.get("location")!,
      a.baseURL,
    ).searchParams.get("token");
    assert(token);
    assert.equal(
      (
        await a.call("/reset-password", {
          token,
          newPassword: "a much newer password value",
        })
      ).status,
      200,
    );
    assert.equal(
      await (await a.call("/get-session", undefined, firstCookie)).json(),
      null,
    );
    assert.equal(
      (
        await a.call("/reset-password", {
          token,
          newPassword: "a much newer password value",
        })
      ).status,
      400,
    );
    assert.equal(
      (
        await a.call("/sign-in/email", {
          email: user.email,
          password: "a much newer password value",
        })
      ).status,
      200,
    );
  } finally {
    await a.close();
    await b.close();
  }
});

test("HTTP: enlace mágico de un solo uso, logout y registro cerrado", async () => {
  const a = await fixture("magic");
  const closed = await fixture("closed", false);
  try {
    assert.equal(
      (
        await a.call("/sign-in/magic-link", {
          email: user.email,
          callbackURL: "/",
        })
      ).status,
      200,
    );
    const message = a.mailbox.messages.at(-1)!;
    assert.equal(message.kind, "magic-link");
    const scanner = await a.bouncer.auth.handler(new Request(message.url));
    assert.equal(scanner.status, 200);
    assert.equal(scanner.headers.get("cache-control"), "no-store, max-age=0");
    assert.equal(scanner.headers.get("referrer-policy"), "no-referrer");
    assert.equal(scanner.headers.getSetCookie().length, 0);
    assert.equal(new URL(message.url).searchParams.has("token"), false);
    assert.equal((await submitMagicLink(a.baseURL, message.url, "https://attacker.example")).status, 403);
    const redeemed = await submitMagicLink(a.baseURL, message.url);
    assert.equal(redeemed.status, 302);
    const sessionCookie = cookie(redeemed);
    assert.equal(
      (await (await a.call("/get-session", undefined, sessionCookie)).json())
        .user.email,
      user.email,
    );
    const replay = await submitMagicLink(a.baseURL, message.url);
    assert.match(replay.headers.get("location") ?? "", /error=/);
    assert.equal((await a.call("/sign-out", {}, sessionCookie)).status, 200);
    assert.equal(
      await (await a.call("/get-session", undefined, sessionCookie)).json(),
      null,
    );
    assert.equal((await closed.call("/sign-up/email", user)).status, 404);
    await closed.call("/sign-in/magic-link", {
      email: user.email,
      callbackURL: "/",
    });
    const deniedLink = closed.mailbox.messages.at(-1)!.url;
    assert.equal((await fetch(deniedLink, { redirect: "manual" })).status, 200);
    const denied = await submitMagicLink(closed.baseURL, deniedLink);
    assert.match(denied.headers.get("location") ?? "", /error=/);
    assert.equal(
      await (
        await closed.call("/get-session", undefined, cookie(denied))
      ).json(),
      null,
    );
    assert.equal((await a.call("/list-sessions")).status, 401);

    await a.call("/sign-in/magic-link", {
      email: "concurrent@example.test",
      callbackURL: "/",
    });
    const concurrentLink = a.mailbox.messages.at(-1)!.url;
    assert.equal((await fetch(concurrentLink, { redirect: "manual" })).status, 200);
    const competing = await Promise.all([
      submitMagicLink(a.baseURL, concurrentLink),
      submitMagicLink(a.baseURL, concurrentLink),
    ]);
    const resultingSessions = await Promise.all(
      competing.map((response) =>
        a.call("/get-session", undefined, cookie(response)).then((result) => result.json()),
      ),
    );
    assert.equal(resultingSessions.filter((session) => session?.user).length, 1);
  } finally {
    await a.close();
    await closed.close();
  }
});

test("cuotas persistentes limitan el envío masivo de magic links por destinatario", async () => {
  const f = await fixture("mail_recipient_limit", true, { methods: { magicLink: true } });
  try {
    const responses = await Promise.all(Array.from({ length: 3 }, () =>
      f.call("/sign-in/magic-link", { email: "target@example.test" }),
    ));
    assert(responses.every((response) => response.status === 200));
    assert.equal(
      f.mailbox.messages.filter((message) => message.kind === "magic-link" && message.to === "target@example.test").length,
      2,
    );
    assert.deepEqual(await Promise.all(responses.map((response) => response.json())), [
      { status: true }, { status: true }, { status: true },
    ]);
  } finally { await f.close(); }
});

test("HTTP: limita intentos de login", async () => {
  const a = await fixture("ratelimit");
  try {
    for (let i = 0; i < 5; i++) await a.call("/sign-in/email", user);
    assert.equal((await a.call("/sign-in/email", user)).status, 429);
  } finally {
    await a.close();
  }
});

test("infra de la app: conexión externa, migración repetible y métodos desactivados", async () => {
  const { default: Database } = await import("better-sqlite3");
  const database = new Database(":memory:");
  const bouncer = createBouncer({
    appId: "host_owned",
    baseURL: "http://localhost:4320",
    secret: randomBytes(48).toString("hex"),
    database: { dialect: "sqlite", connection: database },
    requireEmailVerification: false,
    passkeys: false,
  });
  try {
    await bouncer.migrate();
    await bouncer.migrate();
    assert.equal(bouncer.capabilities.magicLink, false);
    assert.equal(bouncer.capabilities.passkeys, false);
    assert.equal(bouncer.capabilities.passwordReset, false);
    assert.equal(bouncer.capabilities.socialProviders.length, 0);
    await bouncer.close();
    assert.equal(
      (
        database
          .prepare("SELECT COUNT(*) AS count FROM bouncer_host_owned_user")
          .get() as { count: number }
      ).count,
      0,
    );
  } finally {
    database.close();
  }
});

test("HTTP: methods are an API allowlist; username login and magic links work independently", async () => {
  const a = await fixture("username_methods", true, {
    methods: { usernamePassword: true, magicLink: true },
    minPasswordLength: 15,
  });
  const magicOnly = await fixture("magic_only", true, {
    methods: { magicLink: true },
  });
  try {
    const input = {
      ...user,
      username: "test.owner",
      password: "a sufficiently long unique password",
    };
    assert.equal((await a.call("/sign-up/email", input)).status, 200);
    await fetch(
      a.mailbox.messages.find((item) => item.kind === "verify-email")!.url,
      { redirect: "manual" },
    );
    const login = await a.call("/sign-in/username", {
      username: input.username,
      password: input.password,
    });
    assert.equal(login.status, 200);
    assert.equal(
      (await (await a.call("/get-session", undefined, cookie(login))).json())
        .user.username,
      input.username,
    );
    assert.equal((await a.call("/sign-in/email", input)).status, 404);
    assert.equal(
      (await a.call("/passkey/generate-authenticate-options")).status,
      404,
    );
    const config = await (await a.call("/bouncer-config")).json();
    assert.equal(config.emailPassword, false);
    assert.equal(config.usernamePassword, true);
    assert.equal(config.passkeys, false);
    assert.equal(config.minPasswordLength, 15);
    assert.deepEqual(config.socialProviders, []);
    assert.equal(
      (await a.call("/is-username-available", { username: input.username }))
        .status,
      404,
    );
    assert.equal((await magicOnly.call("/sign-in/email", input)).status, 404);
    assert.equal(
      (await magicOnly.call("/sign-in/username", input)).status,
      404,
    );
    assert.equal((await magicOnly.call("/sign-up/email", input)).status, 404);
    assert.equal(
      (await magicOnly.call("/request-password-reset", { email: input.email }))
        .status,
      404,
    );
    assert.equal(
      (
        await magicOnly.call("/sign-in/magic-link", {
          email: input.email,
          callbackURL: "/",
        })
      ).status,
      200,
    );
    const link = magicOnly.mailbox.messages.at(-1)!;
    assert.equal((await fetch(link.url, { redirect: "manual" })).status, 200);
    const redeemed = await submitMagicLink(magicOnly.baseURL, link.url);
    assert.equal(redeemed.status, 302);
    assert(
      (
        await (
          await magicOnly.call("/get-session", undefined, cookie(redeemed))
        ).json()
      ).user,
    );
    assert.equal(
      (await magicOnly.call("/bouncer-config").then((r) => r.json()))
        .passwordReset,
      false,
    );
  } finally {
    await a.close();
    await magicOnly.close();
  }
});

test("HTTP: contraseñas filtradas, reautenticación y revocación persistente", async () => {
  const f = await fixture("security", true, { sendMail: undefined, requireEmailVerification: false, minPasswordLength: 15, methods: { emailPassword: true } });
  try {
    const weak = await f.call("/sign-up/email", { email: "weak@example.test", password: "correct horse battery staple", name: "Weak" });
    assert.equal(weak.status, 400);
    assert.equal((await weak.json()).code, "PASSWORD_COMPROMISED");
    const password = "Bouncer private security phrase 8734";
    assert.equal((await f.call("/sign-up/email", { email: "safe@example.test", password, name: "Safe" })).status, 200);
    assert.equal((await f.call("/sign-in/email", { email: "safe@example.test", password: "x".repeat(1025) })).status, 400);
    assert.equal((await f.call("/sign-in/email", { email: `${"x".repeat(250)}@example.test`, password })).status, 400);
    const login = await f.call("/sign-in/email", { email: "safe@example.test", password });
    assert.equal(login.headers.get("cache-control"), "no-store, max-age=0");
    assert.equal(login.headers.get("referrer-policy"), "no-referrer");
    const cookie = login.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
    const session = await f.bouncer.getSession(new Headers({ cookie }));
    assert(session);
    const ctx = await f.bouncer.auth.$context;
    await ctx.adapter.update({ model: "session", where: [{ field: "id", value: session.session.id }], update: { createdAt: new Date(Date.now() - 600_000) } });
    assert.equal((await f.call("/revoke-other-sessions", {}, cookie)).status, 403);
    assert.equal((await f.call("/change-email", { newEmail: "new-safe@example.test" }, cookie)).status, 403);
    assert.equal((await f.call("/reauthenticate", { password: "x".repeat(8192) }, cookie)).status, 413);
    assert.equal((await f.call("/reauthenticate", { password: "incorrect" }, cookie)).status, 401);
    assert.equal((await f.call("/reauthenticate", { password }, cookie, "https://attacker.example")).status, 403);
    assert.equal((await f.call("/reauthenticate", { password }, cookie)).status, 200);
    assert.equal((await f.call("/revoke-other-sessions", {}, cookie)).status, 200);
    await f.bouncer.admin.disableUser(session.user.id, true);
    assert.equal(await f.bouncer.getSession(new Headers({ cookie })), null);
    assert.notEqual((await f.call("/sign-in/email", { email: "safe@example.test", password })).status, 200);
  } finally { await f.close(); }
});

test("Bouncer.getSession revoca sesiones inactivas y de vida absoluta excedida", async () => {
  const f = await fixture("session_expiry", true, { sendMail: undefined, requireEmailVerification: false, methods: { emailPassword: true } });
  try {
    const password = "Bouncer session expiry fixture 3471";
    await f.call("/sign-up/email", { email: "expiry@example.test", name: "Expiry", password });
    const first = await f.call("/sign-in/email", { email: "expiry@example.test", password });
    const firstCookie = cookie(first);
    const ctx = await f.bouncer.auth.$context;
    const firstSession = await f.bouncer.getSession(new Headers({ cookie: firstCookie }));
    assert(firstSession);
    await ctx.adapter.update({
      model: "session",
      where: [{ field: "id", value: firstSession.session.id }],
      update: { updatedAt: new Date(Date.now() - 13 * 3600_000) },
    });
    assert.equal(await f.bouncer.getSession(new Headers({ cookie: firstCookie })), null);

    const second = await f.call("/sign-in/email", { email: "expiry@example.test", password });
    const secondCookie = cookie(second);
    const secondSession = await f.bouncer.getSession(new Headers({ cookie: secondCookie }));
    assert(secondSession);
    await ctx.adapter.update({
      model: "session",
      where: [{ field: "id", value: secondSession.session.id }],
      update: { createdAt: new Date(Date.now() - 8 * 86400_000) },
    });
    assert.equal(await f.bouncer.getSession(new Headers({ cookie: secondCookie })), null);
  } finally { await f.close(); }
});

function totpFor(uri: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const secret = new URL(uri).searchParams.get("secret")!;
  const bits = [...secret.toUpperCase().replace(/=/g, "")].map(letter => alphabet.indexOf(letter).toString(2).padStart(5, "0")).join("");
  const key = Buffer.from(bits.match(/.{8}/g)!.map(byte => parseInt(byte, 2)));
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const digest = createHmac("sha1", key).update(counter).digest();
  return ((digest.readUInt32BE(digest[19] & 15) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
}

test("HTTP: TOTP exige segundo factor y los códigos de recuperación son de un uso", async () => {
  const f = await fixture("mfa", true, { sendMail: undefined, requireEmailVerification: false, methods: { emailPassword: true }, security: { twoFactor: true } });
  const cookies = (response: Response) => response.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
  try {
    const password = "Bouncer private MFA phrase 9248";
    await f.call("/sign-up/email", { email: "mfa@example.test", name: "MFA", password });
    const login = await f.call("/sign-in/email", { email: "mfa@example.test", password });
    let cookie = cookies(login);
    const session = await f.bouncer.getSession(new Headers({ cookie }));
    assert(session);
    const ctx = await f.bouncer.auth.$context;
    await ctx.adapter.update({ model: "session", where: [{ field: "id", value: session.session.id }], update: { createdAt: new Date(Date.now() - 600_000) } });
    assert.equal((await f.call("/two-factor/enable", { password }, cookie)).status, 403);
    assert.equal((await f.call("/reauthenticate", { password }, cookie)).status, 200);
    const enrollment = await f.call("/two-factor/enable", { password }, cookie);
    assert.equal(enrollment.status, 200);
    const setup = await enrollment.json();
    assert.equal(setup.backupCodes.length, 10);
    const activation = await f.call("/two-factor/verify-totp", { code: totpFor(setup.totpURI) }, cookie);
    assert.equal(activation.status, 200);
    cookie = cookies(activation) || cookie;
    const enabled = await f.bouncer.getSession(new Headers({ cookie }));
    assert(enabled && "twoFactorEnabled" in enabled.user && enabled.user.twoFactorEnabled);
    const attempt = await f.call("/sign-in/email", { email: "mfa@example.test", password });
    assert.equal((await attempt.json()).twoFactorRedirect, true);
    const pending = cookies(attempt);
    assert.equal(await f.bouncer.getSession(new Headers({ cookie: pending })), null);
    const verified = await f.call("/two-factor/verify-backup-code", { code: setup.backupCodes[0] }, pending);
    assert.equal(verified.status, 200);
    assert(await f.bouncer.getSession(new Headers({ cookie: cookies(verified) })));
    const again = await f.call("/sign-in/email", { email: "mfa@example.test", password });
    assert.notEqual((await f.call("/two-factor/verify-backup-code", { code: setup.backupCodes[0] }, cookies(again))).status, 200);
    assert.equal((await f.call("/two-factor/verify-totp", { code: totpFor(setup.totpURI) }, cookies(again))).status, 200);
  } finally { await f.close(); }
});

test("HTTP: HTTPS emite cookies __Host sin Domain para aislar subdominios", async () => {
  const origin = "https://secure.example.test";
  const f = await fixture("secure_cookies", true, { baseURL: origin, sendMail: undefined, requireEmailVerification: false, methods: { emailPassword: true } });
  try {
    const response = await f.call("/sign-up/email", { email: "secure@example.test", name: "Secure", password: "Bouncer secure cookie fixture 8347" }, undefined, origin);
    assert.equal(response.status, 200);
    const cookie = response.headers.getSetCookie().find(value => value.startsWith("__Host-bouncer_secure_cookies.session_token="));
    assert(cookie);
    assert.match(cookie, /; Secure(?:;|$)/i);
    assert.match(cookie, /; HttpOnly(?:;|$)/i);
    assert.match(cookie, /; Path=\/(?:;|$)/i);
    assert.doesNotMatch(cookie, /; Domain=/i);
  } finally { await f.close(); }
});
