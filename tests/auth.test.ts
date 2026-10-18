import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, createHmac } from "node:crypto";
import { Pool } from "pg";
import {
  createBouncer,
  createDevelopmentMailbox,
  toNodeHandler,
  fromNodeHeaders,
  type BouncerOptions,
} from "../packages/api/src/index.js";

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
const user = {
  name: "Baul",
  email: "baul@example.test",
  password: "Bouncer isolated fixture phrase 7391",
};

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
    assert.equal((await sessionResponse.json()).user.email, user.email);
    assert.equal(
      await (await b.call("/get-session", undefined, firstCookie)).json(),
      null,
    );
    assert.equal((await b.call("/sign-in/email", user)).status, 401);
    const secondLogin = await a.call("/sign-in/email", user);
    assert.equal(secondLogin.status, 200);
    const secondCookie = cookie(secondLogin);
    assert.equal(
      (await (await a.call("/list-sessions", undefined, firstCookie)).json())
        .length,
      2,
    );
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
    const redeemed = await fetch(message.url, { redirect: "manual" });
    assert.equal(redeemed.status, 302);
    const sessionCookie = cookie(redeemed);
    assert.equal(
      (await (await a.call("/get-session", undefined, sessionCookie)).json())
        .user.email,
      user.email,
    );
    const replay = await fetch(message.url, { redirect: "manual" });
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
    const denied = await fetch(closed.mailbox.messages.at(-1)!.url, {
      redirect: "manual",
    });
    assert.match(denied.headers.get("location") ?? "", /error=/);
    assert.equal(
      await (
        await closed.call("/get-session", undefined, cookie(denied))
      ).json(),
      null,
    );
    assert.equal((await a.call("/list-sessions")).status, 401);
  } finally {
    await a.close();
    await closed.close();
  }
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
    const redeemed = await fetch(link.url, { redirect: "manual" });
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
    const login = await f.call("/sign-in/email", { email: "safe@example.test", password });
    const cookie = login.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
    const session = await f.bouncer.getSession(new Headers({ cookie }));
    assert(session);
    const ctx = await f.bouncer.auth.$context;
    await ctx.adapter.update({ model: "session", where: [{ field: "id", value: session.session.id }], update: { createdAt: new Date(Date.now() - 600_000) } });
    assert.equal((await f.call("/revoke-other-sessions", {}, cookie)).status, 403);
    assert.equal((await f.call("/reauthenticate", { password: "incorrect" }, cookie)).status, 401);
    assert.equal((await f.call("/reauthenticate", { password }, cookie, "https://attacker.example")).status, 403);
    assert.equal((await f.call("/reauthenticate", { password }, cookie)).status, 200);
    assert.equal((await f.call("/revoke-other-sessions", {}, cookie)).status, 200);
    await f.bouncer.admin.disableUser(session.user.id, true);
    assert.equal(await f.bouncer.getSession(new Headers({ cookie })), null);
    assert.notEqual((await f.call("/sign-in/email", { email: "safe@example.test", password })).status, 200);
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
