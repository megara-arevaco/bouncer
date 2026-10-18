import type Database from "better-sqlite3";
import type { Pool } from "pg";

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
    },
    async consume(key: string, limit: number, window = 15 * 60_000) {
      const now = Date.now();
      await query(`DELETE FROM ${table} WHERE "expires" <= $1`, [now]);
      const [row] = await query(`INSERT INTO ${table} ("key", "count", "expires") SELECT $1, 1, $2 WHERE EXISTS (SELECT 1 FROM ${table} WHERE "key" = $1) OR (SELECT COUNT(*) FROM ${table}) < 10000
        ON CONFLICT ("key") DO UPDATE SET "count" = ${table}."count" + 1 RETURNING "count"`, [key, now + window]);
      return Boolean(row) && Number(row.count) <= limit;
    },
  };
}
