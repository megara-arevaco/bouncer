import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const { version } = JSON.parse(await readFile("packages/api/package.json", "utf8"));
const directory = await mkdtemp(join(tmpdir(), "bouncer-consumer-"));
const compiler = resolve("node_modules/typescript/bin/tsc");
try {
  await writeFile(join(directory, "package.json"), JSON.stringify({ private: true, type: "module" }));
  execFileSync("npm", ["install", "--no-audit", "--no-fund",
    ...["api", "react"].map((name) => resolve(`artifacts/v${version}/bouncer-${name}-${version}.tgz`)),
    "react@19", "react-dom@19", "@types/react@19", "@types/react-dom@19"],
  { cwd: directory, stdio: "inherit" });
  await writeFile(join(directory, "consumer.mts"), `
import { createBouncer, createDevelopmentMailbox } from "@bouncer/api";
import { AuthPanel, createBouncerClient } from "@bouncer/react";
const auth = createBouncer({
  appId: "consumer", baseURL: "http://localhost:3000",
  secret: "release-smoke-test-secret-at-least-32-characters",
  database: { dialect: "sqlite", filename: ":memory:" },
  sendMail: createDevelopmentMailbox().sendMail,
});
await auth.migrate();
const response = await auth.handler(new Request("http://localhost:3000/api/auth/bouncer-config"));
if (!response.ok || !(await response.json()).emailPassword) throw new Error("Missing capabilities");
if (typeof AuthPanel !== "function" || typeof createBouncerClient !== "function") throw new Error("Missing React exports");
await auth.close();
`);
  execFileSync(process.execPath, [compiler, "consumer.mts", "--noEmit", "--strict",
    "--skipLibCheck", "--module", "NodeNext", "--target", "ES2022"],
  { cwd: directory, stdio: "inherit" });
  execFileSync(process.execPath, ["consumer.mts"], {
    cwd: directory, stdio: "inherit", env: { ...process.env, NODE_ENV: "test" },
  });
  console.log("Compiled package exports and declarations work in an isolated consumer.");
} finally {
  await rm(directory, { recursive: true, force: true });
}
