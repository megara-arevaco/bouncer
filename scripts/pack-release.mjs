import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";

const packages = ["api", "react", "authorization"];
const manifests = await Promise.all(packages.map(async (name) =>
  JSON.parse(await readFile(`packages/${name}/package.json`, "utf8"))));
const version = manifests[0].version;
if (!/^\d+\.\d+\.\d+$/.test(version) || manifests.some((p) => p.version !== version))
  throw new Error("All packages must use the same stable SemVer version.");
if (process.env.GITHUB_REF_TYPE === "tag" && process.env.GITHUB_REF_NAME !== `v${version}`)
  throw new Error("Release tag and package versions do not match.");
const destination = `artifacts/v${version}`;
await rm(destination, { recursive: true, force: true });
await mkdir(destination, { recursive: true });
const checksums = [];
for (const name of packages) {
  const output = execFileSync("npm", ["pack", "--workspace", `@bouncer/${name}`,
    "--pack-destination", destination, "--json"], { encoding: "utf8" });
  const [packed] = JSON.parse(output);
  for (const required of ["dist/index.js", "dist/index.d.ts",
    ...(name === "react" ? ["dist/styles.css"] : [])]) {
    if (!packed.files.some((file) => file.path === required))
      throw new Error(`${packed.name}: missing ${required}`);
  }
  if (packed.files.some((file) => /(^|\/)(node_modules|src|\.env)(\/|$)/.test(file.path)))
    throw new Error(`${packed.name}: unexpected source or private files`);
  const archive = await readFile(`${destination}/${packed.filename}`);
  checksums.push(`${createHash("sha256").update(archive).digest("hex")}  ${packed.filename}`);
}
await writeFile(`${destination}/SHA256SUMS`, checksums.join("\n") + "\n");
console.log(`Release assets ready in ${destination}`);
