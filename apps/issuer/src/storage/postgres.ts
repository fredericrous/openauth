/**
 * Postgres-backed storage adapter for @fredericrous/openauth.
 *
 * Persists refresh tokens, password hashes, and other openauth state
 * in a single `openauth_kv (key, value, expires_at)` table. Survives
 * pod restarts and works under multiple replicas (the upstream
 * MemoryStorage doesn't — see chart values comment).
 *
 * Wire via `DATABASE_URL` env in the HelmRelease (CNPG-generated
 * connection string in the openauth-db-app Secret).
 *
 * @effect/sql under the hood (matches builder-api / homelab Effect-
 * everywhere convention); openauth's StorageAdapter interface is
 * Promise-based, so each method does Effect.runPromise on a small
 * gen-Effect.
 */
import { SqlClient } from "@effect/sql"
import type { StorageAdapter } from "@fredericrous/openauth/storage/storage"
import { joinKey, splitKey } from "@fredericrous/openauth/storage/storage"
import { Effect, type ManagedRuntime } from "effect"

// SqlError surfaces from PgClient.layer construction; we let it die
// at the runtime level rather than threading it through the
// Promise-based StorageAdapter interface.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Runtime = ManagedRuntime.ManagedRuntime<SqlClient.SqlClient, any>

const TABLE = "openauth_kv"

/**
 * Run once at boot, before issuer() needs the adapter. Idempotent.
 */
export const ensureSchema = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  yield* sql`
    CREATE TABLE IF NOT EXISTS ${sql(TABLE)} (
      key        text PRIMARY KEY,
      value      jsonb NOT NULL,
      expires_at timestamptz NULL
    )
  `
  // GIN-less prefix index for scan()'s prefix LIKE — btree is enough
  // because we use the leading-prefix form ("foo%").
  yield* sql`
    CREATE INDEX IF NOT EXISTS ${sql(TABLE + "_key_btree_idx")}
    ON ${sql(TABLE)} (key text_pattern_ops)
  `
})

/** Build the StorageAdapter once you have a runtime that provides SqlClient. */
export function PostgresStorage(runtime: Runtime): StorageAdapter {
  const run = <A>(effect: Effect.Effect<A, unknown, SqlClient.SqlClient>) =>
    runtime.runPromise(effect)

  return {
    get: (key) =>
      run(
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient
          const rows = yield* sql<{
            value: Record<string, unknown>
          }>`
            SELECT value FROM ${sql(TABLE)}
            WHERE key = ${joinKey(key)}
              AND (expires_at IS NULL OR expires_at > now())
            LIMIT 1
          `
          return rows[0]?.value
        }),
      ),
    set: (key, value, expiry) =>
      run(
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient
          const expiresAt = expiry ?? null
          // node-postgres serializes JS objects through its
          // built-in type oid 114 (json) / 3802 (jsonb) handling, so
          // just pass the JSON string and cast.
          const valueJson = JSON.stringify(value)
          yield* sql`
            INSERT INTO ${sql(TABLE)} (key, value, expires_at)
            VALUES (${joinKey(key)}, ${valueJson}::jsonb, ${expiresAt})
            ON CONFLICT (key) DO UPDATE
              SET value      = excluded.value,
                  expires_at = excluded.expires_at
          `
        }),
      ),
    remove: (key) =>
      run(
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient
          yield* sql`DELETE FROM ${sql(TABLE)} WHERE key = ${joinKey(key)}`
        }),
      ),
    scan: async function* (prefix) {
      const rows = await run(
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient
          // text_pattern_ops + LIKE 'prefix%' is index-friendly and
          // bypasses locale collation issues that plain LIKE has.
          const escaped = joinKey(prefix)
            .replaceAll("%", "\\%")
            .replaceAll("_", "\\_")
          return yield* sql<{
            key: string
            value: Record<string, unknown>
          }>`
            SELECT key, value FROM ${sql(TABLE)}
            WHERE key LIKE ${escaped + "%"}
              AND (expires_at IS NULL OR expires_at > now())
            ORDER BY key
          `
        }),
      )
      for (const r of rows) {
        yield [splitKey(r.key), r.value] as [string[], unknown]
      }
    },
  }
}
