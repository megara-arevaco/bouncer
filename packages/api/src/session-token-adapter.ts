import { createHmac } from "node:crypto";
import type { BetterAuthOptions } from "better-auth";
import type { getAdapter } from "better-auth/db/adapter";

export const SESSION_TOKEN_HASH_PREFIX = "bouncer-session-hmac-v1:";

export function hashSessionToken(secret: string, token: string) {
  if (token.startsWith(SESSION_TOKEN_HASH_PREFIX)) return token;
  return `${SESSION_TOKEN_HASH_PREFIX}${createHmac("sha256", secret)
    .update(`bouncer-session-v1\0${token}`)
    .digest("hex")}`;
}

type Adapter = Awaited<ReturnType<typeof getAdapter>>;
type AdapterInput = { model?: string; where?: Array<Record<string, unknown>>; [key: string]: unknown };
const adapterMethods = new Set([
  "create", "findOne", "findMany", "count", "update", "updateMany",
  "delete", "deleteMany", "consumeOne", "incrementOne", "createSchema",
]);

function remapWhere(where: AdapterInput["where"], secret: string, restored: Map<string, string>) {
  return where?.map((item) => {
    if (item.field !== "token") return item;
    const value = item.value;
    const remap = (token: unknown) => {
      if (typeof token !== "string") return token;
      const stored = hashSessionToken(secret, token);
      if (stored !== token) restored.set(stored, token);
      return stored;
    };
    return { ...item, value: Array.isArray(value) ? value.map(remap) : remap(value) };
  });
}

function restoreTokens(value: unknown, restored: Map<string, string>): unknown {
  if (Array.isArray(value)) return value.map((item) => restoreTokens(item, restored));
  if (!value || typeof value !== "object" || value instanceof Date) return value;
  const record = value as Record<string, unknown>;
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(record)) {
    result[key] = key === "token" && typeof item === "string" && restored.has(item)
      ? restored.get(item)
      : restoreTokens(item, restored);
  }
  return result;
}

function wrapAdapter(adapterPromise: Promise<Adapter>, secret: string): Adapter {
  return new Proxy({} as Adapter, {
    get(_target, property) {
      if (property === "id") return "kysely";
      if (property === "options") return { adapterConfig: { transaction: true } };
      if (property === "transaction") {
        return async (callback: (transaction: unknown) => Promise<unknown>) => {
          const adapter = await adapterPromise;
          return adapter.transaction(async (transaction) =>
            callback(wrapAdapter(Promise.resolve(transaction as Adapter), secret)),
          );
        };
      }
      if (typeof property !== "string" || !adapterMethods.has(property)) return undefined;
      return async (...args: unknown[]) => {
        const adapter = await adapterPromise;
        const method = Reflect.get(adapter, property, adapter);
        if (typeof method !== "function") return method;
        const input = args[0] as AdapterInput | undefined;
        if (!input || input.model !== "session")
          return Reflect.apply(method, adapter, args);

        const restored = new Map<string, string>();
        const transformed: AdapterInput = { ...input };
        if (Array.isArray(input.where))
          transformed.where = remapWhere(input.where, secret, restored);
        if (input.data && typeof input.data === "object" && "token" in input.data) {
          const data = input.data as Record<string, unknown>;
          if (typeof data.token === "string") {
            const stored = hashSessionToken(secret, data.token);
            if (stored !== data.token) restored.set(stored, data.token);
            transformed.data = { ...data, token: stored };
          }
        }
        if (input.update && typeof input.update === "object" && "token" in input.update) {
          const update = input.update as Record<string, unknown>;
          if (typeof update.token === "string") {
            const stored = hashSessionToken(secret, update.token);
            if (stored !== update.token) restored.set(stored, update.token);
            transformed.update = { ...update, token: stored };
          }
        }
        const result = await Reflect.apply(method, adapter, [transformed, ...args.slice(1)]);
        return restoreTokens(result, restored);
      };
    },
  });
}

export function createSessionTokenAdapter(
  adapterPromise: Promise<Adapter>,
  secret: string,
) {
  return (_options: BetterAuthOptions): Adapter => wrapAdapter(adapterPromise, secret);
}
