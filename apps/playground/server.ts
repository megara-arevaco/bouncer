import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { createServer as createViteServer } from "vite";
import {
  createBouncer,
  createDevelopmentMailbox,
  toNodeHandler,
} from "@bouncer/api";

if (process.env.NODE_ENV === "production")
  throw new Error("El playground es solo para desarrollo.");
const port = Number(process.env.PORT ?? 4310);
const baseURL = `http://localhost:${port}`;
await mkdir(".data", { recursive: true });
let secret = process.env.BOUNCER_SECRET;
if (!secret) {
  try {
    secret = await readFile(".data/secret", "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    secret = randomBytes(48).toString("base64url");
    await writeFile(".data/secret", secret, { mode: 0o600, flag: "wx" });
  }
}
const mailbox = createDevelopmentMailbox();
const socialProviders = {
  ...(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
    ? {
        google: {
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        },
      }
    : {}),
  ...(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET
    ? {
        github: {
          clientId: process.env.GITHUB_CLIENT_ID,
          clientSecret: process.env.GITHUB_CLIENT_SECRET,
        },
      }
    : {}),
};
const bouncer = createBouncer({
  appId: "playground",
  appName: "Bouncer",
  baseURL,
  secret,
  database: process.env.DATABASE_URL
    ? {
        dialect: "postgres",
        config: { connectionString: process.env.DATABASE_URL },
      }
    : {
        dialect: "sqlite",
        filename: process.env.BOUNCER_SQLITE ?? ".data/playground.sqlite",
      },
  sendMail: mailbox.sendMail,
  socialProviders,
});
await bouncer.migrate();
const server = createServer();
const vite = await createViteServer({
  configFile: "apps/playground/vite.config.ts",
  server: { middlewareMode: true, hmr: { server } },
});
const authHandler = toNodeHandler(bouncer);
server.on("request", async (req, res) => {
  try {
    if (req.url?.split("?")[0] === "/__dev/mailbox") {
      if (
        req.method !== "GET" ||
        (req.headers.origin && req.headers.origin !== baseURL)
      ) {
        res.writeHead(403).end();
        return;
      }
      res.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
      });
      res.end(JSON.stringify(mailbox.messages));
      return;
    }
    if (req.url?.startsWith("/api/auth/")) {
      await authHandler(req, res);
      return;
    }
    vite.middlewares(req, res);
  } catch {
    res.writeHead(500).end("No se ha podido completar la petición.");
  }
});
server.listen(port, "127.0.0.1", () => console.log(`Bouncer: ${baseURL}`));
async function shutdown() {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await vite.close();
  await bouncer.close();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
