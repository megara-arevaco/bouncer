import { argon2, createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { verifyPassword as verifyScryptPassword } from "better-auth/crypto";

export class PasswordPolicyError extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}
export type BreachedPasswordPolicy = "offline" | "hibp" | false;
const compromised = new Set([
  "123456789012345", "1234567890123456", "12345678901234567890",
  "passwordpassword", "passwordpasswordpassword", "password123456789",
  "qwertyuiopasdfgh", "qwertyuiopasdfghjkl", "correct horse battery staple",
  "this is a password", "thisismypassword", "iloveyouiloveyou", "letmeinletmeinletmein",
]);
const ranges = new Map<string, { expires: number; suffixes: Set<string> }>();
let hashes = 0;
async function derive(password: string, salt: Buffer) {
  if (hashes >= 4) throw new PasswordPolicyError("TRY_LATER", "Inténtalo más tarde.");
  hashes++;
  try {
    return await new Promise<Buffer>((resolve, reject) => argon2("argon2id", {
      message: password, nonce: salt, memory: 19456, passes: 2, parallelism: 1, tagLength: 32,
    }, (error, value) => error ? reject(error) : resolve(value)));
  } finally { hashes--; }
}
export async function hashPassword(password: string) {
  const salt = randomBytes(16);
  return `argon2id-v1:${salt.toString("hex")}:${(await derive(password, salt)).toString("hex")}`;
}
export async function verifyPassword({ password, hash }: { password: string; hash: string }) {
  if (!hash.startsWith("argon2id-v1:")) return verifyScryptPassword({ password, hash });
  const match = /^argon2id-v1:([a-f0-9]{32}):([a-f0-9]{64})$/.exec(hash);
  if (!match || Buffer.byteLength(password) > 1024) return false;
  return timingSafeEqual(await derive(password, Buffer.from(match[1], "hex")), Buffer.from(match[2], "hex"));
}
export async function checkPassword(password: string, minimum: number, policy: BreachedPasswordPolicy) {
  if (Array.from(password).length < minimum || Array.from(password).length > 128 || Buffer.byteLength(password) > 1024)
    throw new PasswordPolicyError("PASSWORD_LENGTH", `La contraseña debe tener entre ${minimum} y 128 caracteres.`);
  if (!policy) return;
  let found = compromised.has(password.trim().toLowerCase());
  if (!found && policy === "hibp") {
    const digest = createHash("sha1").update(password).digest("hex").toUpperCase();
    const prefix = digest.slice(0, 5);
    let cached = ranges.get(prefix);
    if (!cached || cached.expires <= Date.now()) {
      try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
          headers: { "Add-Padding": "true", "User-Agent": "Bouncer-Password-Check" },
          redirect: "error", signal: AbortSignal.timeout(5000),
        });
        if (!response.ok) throw new Error();
        const text = await response.text();
        if (text.length > 2_000_000) throw new Error();
        const suffixes = new Set<string>();
        for (const line of text.split(/\r?\n/)) {
          const match = /^([A-F0-9]{35}):([0-9]+)$/.exec(line.trim());
          if (match && Number(match[2]) > 0) suffixes.add(match[1]);
        }
        if (!suffixes.size) throw new Error();
        if (ranges.size >= 256) ranges.delete(ranges.keys().next().value!);
        cached = { expires: Date.now() + 3600_000, suffixes };
        ranges.set(prefix, cached);
      } catch {
        throw new PasswordPolicyError("PASSWORD_CHECK_UNAVAILABLE", "No se ha podido comprobar la contraseña. Inténtalo más tarde.");
      }
    }
    found = cached.suffixes.has(digest.slice(5));
  }
  if (found) throw new PasswordPolicyError("PASSWORD_COMPROMISED", "Esta contraseña aparece en filtraciones conocidas. Elige otra distinta.");
}
