import type Database from "better-sqlite3";
import type { Pool } from "pg";
import { createHash } from "node:crypto";

function isLikelyEncryptedOAuthToken(token: string) {
  return token.startsWith("$ba$") || (token.length % 2 === 0 && /^[0-9a-f]+$/i.test(token));
}

export function securityStore(database: Pool | Database.Database, postgres: boolean, prefix: string) {
  const table = `"${prefix}_security_limit"`;
  const query = async (sql: string, values: (string | number)[] = []) => {
    if (postgres) return (await (database as Pool).query(sql, values)).rows as Record<string, unknown>[];
    const statement = (database as Database.Database).prepare(sql.replace(/\$\d+/g, "?"));
    if (!statement.reader) { statement.run(...[...sql.matchAll(/\$(\d+)/g)].map(match => values[Number(match[1]) - 1])); return [] as Record<string, unknown>[]; }
    return statement.all(...[...sql.matchAll(/\$(\d+)/g)].map(match => values[Number(match[1]) - 1])) as Record<string, unknown>[];
  };
  return {
    async migrate() {
      await query(`CREATE TABLE IF NOT EXISTS ${table} ("key" TEXT PRIMARY KEY, "count" INTEGER NOT NULL, "expires" BIGINT NOT NULL)`);
      await query(`CREATE INDEX IF NOT EXISTS "${prefix}_security_expiry" ON ${table} ("expires")`);
      await query(`CREATE TABLE IF NOT EXISTS "${prefix}_security_meta" ("key" TEXT PRIMARY KEY, "value" TEXT NOT NULL)`);
    },
    async migrateCredentialStorage(
      sessionTable: string,
      verificationTable: string,
      accountTable: string,
      hashSessionToken: (token: string) => string,
      encryptOAuthToken: (token: string) => Promise<string>,
    ) {
      const meta = `"${prefix}_security_meta"`;
      const migrateRows = async (executor: { query: (sql: string, values?: unknown[]) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number | null }> }) => {
        const sessions = await executor.query(`SELECT "id", "token" FROM "${sessionTable}"`);
        for (const row of sessions.rows) {
          const token = String(row.token);
          if (token.startsWith("bouncer-session-hmac-v1:")) continue;
          await executor.query(`UPDATE "${sessionTable}" SET "token" = $1 WHERE "id" = $2 AND "token" = $3`, [hashSessionToken(token), row.id, token]);
        }
        const claimed = await executor.query(`INSERT INTO ${meta} ("key", "value") VALUES ($1, $2) ON CONFLICT ("key") DO NOTHING RETURNING "key"`, ["verification-identifiers-sha256-v1", "running"]);
        if (!claimed.rowCount) return;
        const verifications = await executor.query(`SELECT "id", "identifier" FROM "${verificationTable}"`);
        for (const row of verifications.rows) {
          const identifier = String(row.identifier);
          const hashed = createHash("sha256").update(identifier).digest("base64url");
          await executor.query(`UPDATE "${verificationTable}" SET "identifier" = $1 WHERE "id" = $2 AND "identifier" = $3`, [hashed, row.id, identifier]);
        }
        await executor.query(`UPDATE ${meta} SET "value" = $1 WHERE "key" = $2`, ["complete", "verification-identifiers-sha256-v1"]);
      };

      if (postgres) {
        const client = await (database as Pool).connect();
        try {
          await client.query("BEGIN");
          await migrateRows(client as unknown as Parameters<typeof migrateRows>[0]);
          await client.query("COMMIT");
        } catch (error) {
          await client.query("ROLLBACK");
          throw error;
        } finally {
          client.release();
        }
        await migrateOAuthTokens(meta, accountTable, encryptOAuthToken, async (sql, values = []) => (database as Pool).query(sql, values));
        return;
      }

      const db = database as Database.Database;
      const migrate = db.transaction(() => {
        const sessions = db.prepare(`SELECT "id", "token" FROM "${sessionTable}"`).all() as Record<string, unknown>[];
        const updateSession = db.prepare(`UPDATE "${sessionTable}" SET "token" = ? WHERE "id" = ? AND "token" = ?`);
        for (const row of sessions) {
          const token = String(row.token);
          if (!token.startsWith("bouncer-session-hmac-v1:")) updateSession.run(hashSessionToken(token), row.id, token);
        }
        const claim = db.prepare(`INSERT OR IGNORE INTO ${meta} ("key", "value") VALUES (?, ?)`)
          .run("verification-identifiers-sha256-v1", "running");
        if (claim.changes === 0) return;
        const verifications = db.prepare(`SELECT "id", "identifier" FROM "${verificationTable}"`).all() as Record<string, unknown>[];
        const updateVerification = db.prepare(`UPDATE "${verificationTable}" SET "identifier" = ? WHERE "id" = ? AND "identifier" = ?`);
        for (const row of verifications) {
          const identifier = String(row.identifier);
          const hashed = createHash("sha256").update(identifier).digest("base64url");
          updateVerification.run(hashed, row.id, identifier);
        }
        db.prepare(`UPDATE ${meta} SET "value" = ? WHERE "key" = ?`)
          .run("complete", "verification-identifiers-sha256-v1");
      });
      migrate.immediate();
      await migrateOAuthTokens(meta, accountTable, encryptOAuthToken, async (sql, values = []) => {
        const statement = db.prepare(sql.replace(/\$\d+/g, "?"));
        const parameters = [...sql.matchAll(/\$(\d+)/g)].map((match) => values[Number(match[1]) - 1]);
        if (statement.reader) return { rows: statement.all(...parameters) as Record<string, unknown>[] };
        return { rows: [], rowCount: statement.run(...parameters).changes };
      });
    },
    async consume(key: string, limit: number, window = 15 * 60_000) {
      const now = Date.now();
      await query(`DELETE FROM ${table} WHERE "expires" <= $1`, [now]);
      const [row] = await query(`INSERT INTO ${table} ("key", "count", "expires") SELECT $1, 1, $2 WHERE EXISTS (SELECT 1 FROM ${table} WHERE "key" = $1) OR (SELECT COUNT(*) FROM ${table}) < 10000
        ON CONFLICT ("key") DO UPDATE SET "count" = ${table}."count" + 1 RETURNING "count"`, [key, now + window]);
      return Boolean(row) && Number(row.count) <= limit;
    },
  };

  async function migrateOAuthTokens(
    meta: string,
    accountTable: string,
    encryptOAuthToken: (token: string) => Promise<string>,
    execute: (sql: string, values?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }>,
  ) {
    const migrationKey = "oauth-tokens-encrypted-v1";
    const completed = await execute(`SELECT "value" FROM ${meta} WHERE "key" = $1`, [migrationKey]);
    if (completed.rows.some((row) => row.value === "complete")) return;
    const fields = ["accessToken", "refreshToken", "idToken"] as const;
    const predicate = fields.map((field) => `("${field}" IS NOT NULL AND "${field}" NOT LIKE '$ba$%')`).join(" OR ");
    const accounts = await execute(`SELECT "id", "accessToken", "refreshToken", "idToken" FROM "${accountTable}" WHERE ${predicate}`);
    for (const row of accounts.rows) {
      for (const field of fields) {
        const token = row[field];
        if (typeof token !== "string" || !token || isLikelyEncryptedOAuthToken(token)) continue;
        const encrypted = await encryptOAuthToken(token);
        await execute(`UPDATE "${accountTable}" SET "${field}" = $1 WHERE "id" = $2 AND "${field}" = $3`, [encrypted, row.id as string, token]);
      }
    }
    await execute(`INSERT INTO ${meta} ("key", "value") VALUES ($1, $2) ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value"`, [migrationKey, "complete"]);
  }
}
