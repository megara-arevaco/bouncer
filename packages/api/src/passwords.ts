import { argon2, createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { verifyPassword as verifyScryptPassword } from "better-auth/crypto";

export class PasswordPolicyError extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}
export type BreachedPasswordPolicy = "offline" | "hibp" | false;
export type Argon2idParameters = { memoryKiB: number; passes: number; parallelism: number };
export const DEFAULT_ARGON2ID_PARAMETERS: Argon2idParameters = {
  memoryKiB: 19_456,
  passes: 2,
  parallelism: 1,
};
const compromised = new Set([
  "123456789012345", "1234567890123456", "12345678901234567890",
  "passwordpassword", "passwordpasswordpassword", "password123456789",
  "qwertyuiopasdfgh", "qwertyuiopasdfghjkl", "correct horse battery staple",
  "this is a password", "thisismypassword", "iloveyouiloveyou", "letmeinletmeinletmein",
]);
const ranges = new Map<string, { expires: number; suffixes: Set<string> }>();
let hashes = 0;
function validArgon2idParameters(parameters: Argon2idParameters) {
  return Number.isInteger(parameters.memoryKiB) && parameters.memoryKiB >= 19_456 && parameters.memoryKiB <= 262_144 &&
    Number.isInteger(parameters.passes) && parameters.passes >= 2 && parameters.passes <= 10 &&
    Number.isInteger(parameters.parallelism) && parameters.parallelism >= 1 && parameters.parallelism <= 8 &&
    parameters.memoryKiB >= 8 * parameters.parallelism;
}
async function derive(password: string, salt: Buffer, parameters: Argon2idParameters) {
  if (hashes >= 4) throw new PasswordPolicyError("TRY_LATER", "Inténtalo más tarde.");
  hashes++;
  try {
    return await new Promise<Buffer>((resolve, reject) => argon2("argon2id", {
      message: password, nonce: salt, memory: parameters.memoryKiB, passes: parameters.passes, parallelism: parameters.parallelism, tagLength: 32,
    }, (error, value) => error ? reject(error) : resolve(value)));
  } finally { hashes--; }
}
export async function hashPassword(password: string, parameters = DEFAULT_ARGON2ID_PARAMETERS) {
  if (!validArgon2idParameters(parameters))
    throw new PasswordPolicyError("INVALID_HASH_PARAMETERS", "Los parámetros Argon2id no son válidos.");
  if (Buffer.byteLength(password, "utf8") > 1024)
    throw new PasswordPolicyError("PASSWORD_LENGTH", "La contraseña supera el tamaño máximo permitido.");
  const salt = randomBytes(16);
  const hash = await derive(password, salt, parameters);
  return `argon2id-v2:${parameters.memoryKiB}:${parameters.passes}:${parameters.parallelism}:${salt.toString("hex")}:${hash.toString("hex")}`;
}
export async function verifyPassword({ password, hash }: { password: string; hash: string }) {
  if (Buffer.byteLength(password, "utf8") > 1024) return false;
  if (hash.startsWith("argon2id-v1:")) {
    const match = /^argon2id-v1:([a-f0-9]{32}):([a-f0-9]{64})$/.exec(hash);
    if (!match) return false;
    return timingSafeEqual(await derive(password, Buffer.from(match[1], "hex"), DEFAULT_ARGON2ID_PARAMETERS), Buffer.from(match[2], "hex"));
  }
  if (hash.startsWith("argon2id-v2:")) {
    const match = /^argon2id-v2:(\d+):(\d+):(\d+):([a-f0-9]{32}):([a-f0-9]{64})$/.exec(hash);
    if (!match) return false;
    const parameters = { memoryKiB: Number(match[1]), passes: Number(match[2]), parallelism: Number(match[3]) };
    if (!validArgon2idParameters(parameters)) return false;
    return timingSafeEqual(await derive(password, Buffer.from(match[4], "hex"), parameters), Buffer.from(match[5], "hex"));
  }
  if (hash.startsWith("argon2id-")) return false;
  return verifyScryptPassword({ password, hash });
}
export function passwordNeedsRehash(hash: string, parameters = DEFAULT_ARGON2ID_PARAMETERS) {
  const match = /^argon2id-v2:(\d+):(\d+):(\d+):[a-f0-9]{32}:[a-f0-9]{64}$/.exec(hash);
  if (!match) return true;
  return Number(match[1]) !== parameters.memoryKiB || Number(match[2]) !== parameters.passes || Number(match[3]) !== parameters.parallelism;
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
