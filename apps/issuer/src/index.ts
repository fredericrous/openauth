/**
 * openauth issuer for the website-builder.
 *
 * Wraps @fredericrous/openauth with:
 *   - PasswordProvider + PasswordUI (email/password flow, themeable
 *     prebuilt UI)
 *   - PostgresStorage when DATABASE_URL is set (survives restarts +
 *     multi-pod), otherwise MemoryStorage persisted to a PVC file.
 *   - SMTP password-reset email sender (nodemailer) when
 *     OPENAUTH_SMTP_URL is set; otherwise stdout-logs the code so
 *     ops can deliver manually during early access.
 *   - A `getUser(email)` stub that creates+returns a deterministic
 *     subject id. Real user storage (Postgres, with the account row
 *     from packages/schemas) lands when builder-api's account creation
 *     flow is wired in M2.
 *
 * Env vars (read at boot):
 *   OPENAUTH_PORT           HTTP listen port (default 3000)
 *   OPENAUTH_PERSIST_PATH   MemoryStorage persist path (file fallback)
 *   OPENAUTH_SMTP_URL       SMTP URL (e.g. smtp://stalwart.stalwart.svc:25)
 *   OPENAUTH_FROM           From address for password-reset emails
 *   DATABASE_URL            Postgres connection string; when set, the
 *                           PostgresStorage adapter replaces
 *                           MemoryStorage. Format:
 *                           postgres://<user>:<pw>@<host>:5432/<db>
 */
import { serve } from "@hono/node-server"
import { issuer } from "@fredericrous/openauth"
import { createSubjects } from "@fredericrous/openauth/subject"
import { PasswordProvider } from "@fredericrous/openauth/provider/password"
import { MemoryStorage } from "@fredericrous/openauth/storage/memory"
import type { StorageAdapter } from "@fredericrous/openauth/storage/storage"
import { PasswordUI } from "@fredericrous/openauth/ui/password"
import { PgClient } from "@effect/sql-pg"
import { ManagedRuntime, Redacted } from "effect"
import { createTransport, type Transporter } from "nodemailer"
import * as v from "valibot"

import { PostgresStorage, ensureSchema } from "./storage/postgres.js"

const PORT = Number(process.env["OPENAUTH_PORT"] ?? 3000)
const PERSIST_PATH =
  process.env["OPENAUTH_PERSIST_PATH"] ?? "/data/openauth.json"
const SMTP_URL = process.env["OPENAUTH_SMTP_URL"] ?? ""
const FROM_ADDR = process.env["OPENAUTH_FROM"] ?? "noreply@daddyshome.fr"
// Either set DATABASE_URL directly, or compose it from PG_* parts (the
// homelab CNPG pattern: env.PG_HOST/PORT/DB inline + valueFrom the
// openauth-db-app secret for PG_USER/PG_PASS).
const DATABASE_URL =
  process.env["DATABASE_URL"] ??
  (process.env["PG_HOST"]
    ? `postgres://${encodeURIComponent(process.env["PG_USER"] ?? "")}:${encodeURIComponent(process.env["PG_PASS"] ?? "")}@${process.env["PG_HOST"]}:${process.env["PG_PORT"] ?? "5432"}/${process.env["PG_DB"] ?? ""}`
    : "")

// ----------------------------------------------------- audiences config
//
// `OPENAUTH_AUDIENCES` shape: comma-separated `<client_id>:<aud1>,<aud2>,...`
// segments separated by `;`. Each segment maps a client_id to the
// extra audiences its tokens should carry. The client_id itself is
// always included; only list the *additional* audiences.
//
// Example:
//   OPENAUTH_AUDIENCES="builder-webapp:builder-api;admin-webapp:builder-api,builder-admin"
// → builder-webapp tokens get aud=["builder-webapp","builder-api"]
// → admin-webapp tokens get aud=["admin-webapp","builder-api","builder-admin"]
//
// When unset, openauth's default single-string `aud` behavior is kept.
function parseAudiences(raw: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const seg of raw.split(";")) {
    const trimmed = seg.trim();
    if (!trimmed) continue;
    const [clientID, audsRaw] = trimmed.split(":", 2);
    if (!clientID || !audsRaw) continue;
    const auds = audsRaw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (auds.length > 0) out[clientID] = auds;
  }
  return out;
}
const AUDIENCES = parseAudiences(process.env["OPENAUTH_AUDIENCES"] ?? "");

const transporter: Transporter | null = SMTP_URL
  ? createTransport(SMTP_URL)
  : null

// ----------------------------------------------------- storage selection
async function makeStorage(): Promise<StorageAdapter> {
  if (!DATABASE_URL) {
    return MemoryStorage({ persist: PERSIST_PATH })
  }
  const PgLive = PgClient.layer({ url: Redacted.make(DATABASE_URL) })
  const runtime = ManagedRuntime.make(PgLive)
  await runtime.runPromise(ensureSchema)
  return PostgresStorage(runtime)
}

const storage = await makeStorage()

// ----------------------------------------------------- issuer
const subjects = createSubjects({
  user: v.object({
    id: v.string(),
  }),
})

async function getUser(email: string): Promise<string> {
  const enc = new TextEncoder().encode(email.toLowerCase())
  const digest = await crypto.subtle.digest("SHA-256", enc)
  const bytes = new Uint8Array(digest)
  return Buffer.from(bytes).toString("base64url")
}

const app = issuer({
  subjects,
  storage,
  audiences: AUDIENCES,
  providers: {
    password: PasswordProvider(
      PasswordUI({
        sendCode: async (email, code) => {
          if (transporter) {
            await transporter.sendMail({
              from: FROM_ADDR,
              to: email,
              subject: "Your verification code",
              text: `Your verification code is: ${code}\n\nIf you didn't request this, ignore this email.\n`,
            })
          } else {
            // eslint-disable-next-line no-console
            console.log(
              JSON.stringify({
                level: "info",
                msg: "password-reset-code (dev: SMTP not configured)",
                email,
                code,
              }),
            )
          }
        },
      }),
    ),
  },
  success: async (ctx, value) => {
    if (value.provider === "password") {
      return ctx.subject("user", {
        id: await getUser(value.email),
      })
    }
    throw new Error("Unsupported provider")
  },
})

// eslint-disable-next-line no-console
console.log(
  JSON.stringify({
    level: "info",
    msg: "openauth listening",
    port: PORT,
    persistPath: DATABASE_URL ? null : PERSIST_PATH,
    storage: DATABASE_URL ? "postgres" : "memory",
    smtpConfigured: Boolean(SMTP_URL),
  }),
)

serve({ fetch: app.fetch, port: PORT })
