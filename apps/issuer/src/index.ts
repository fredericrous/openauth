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
// Presentation for verification emails. A real display name, a working
// Reply-To, and an HTML+text body materially lower the spam score versus
// a bare "noreply@" + plain text — which matters because outbound leaves
// from a residential IPv6 with no warm sending reputation.
const FROM_NAME = process.env["OPENAUTH_FROM_NAME"] ?? "daddyshome"
const REPLY_TO = process.env["OPENAUTH_REPLY_TO"] ?? "admin@daddyshome.fr"
const BRAND = process.env["OPENAUTH_BRAND"] ?? FROM_NAME
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
  const out: Record<string, string[]> = {}
  for (const seg of raw.split(";")) {
    const trimmed = seg.trim()
    if (!trimmed) continue
    const [clientID, audsRaw] = trimmed.split(":", 2)
    if (!clientID || !audsRaw) continue
    const auds = audsRaw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
    if (auds.length > 0) out[clientID] = auds
  }
  return out
}
const AUDIENCES = parseAudiences(process.env["OPENAUTH_AUDIENCES"] ?? "")

// Public origin to embed in the JWT `iss` claim, discovery doc, and
// authorize/callback redirect URLs. When unset, openauth derives the
// URL from the incoming request — which leaks the internal listening
// port `:3000` when the gateway doesn't send `x-forwarded-port`. Set
// this to the public hostname (no trailing slash) in any production
// deployment behind a proxy.
const ISSUER_URL = process.env["OPENAUTH_ISSUER_URL"] ?? ""

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
    // Preserved through the access-token `properties` so downstream
    // services (and builder-webapp's session) can render the user's
    // email instead of the hashed subject id. Note: callers that
    // treat this as PII should respect the JWT's audience scope.
    email: v.string(),
  }),
})

async function getUser(email: string): Promise<string> {
  const enc = new TextEncoder().encode(email.toLowerCase())
  const digest = await crypto.subtle.digest("SHA-256", enc)
  const bytes = new Uint8Array(digest)
  return Buffer.from(bytes).toString("base64url")
}

// ----------------------------------------------------- redirect allow-list
//
// openauth's default `allow` permits a redirect on localhost or the issuer's
// own registrable domain. The native (Expo) app is a PUBLIC client whose
// redirect is a CUSTOM-SCHEME deep link (e.g. durobuilder://auth), which the
// default would reject. Permit the registered native client_id + its scheme;
// every other client keeps the default behavior, copied verbatim from
// @fredericrous/openauth so the existing web flow stays byte-identical.
const NATIVE_CLIENT_ID =
  process.env["OPENAUTH_NATIVE_CLIENT_ID"] ?? "builder-native"
const NATIVE_REDIRECT_SCHEME =
  process.env["OPENAUTH_NATIVE_REDIRECT_SCHEME"] ?? "durobuilder"

const twoPartTlds = [
  "co.uk",
  "co.jp",
  "co.kr",
  "co.nz",
  "co.za",
  "co.in",
  "com.au",
  "com.br",
  "com.cn",
  "com.mx",
  "com.tw",
  "net.au",
  "org.uk",
  "ne.jp",
  "ac.uk",
  "gov.uk",
  "edu.au",
  "gov.au",
]
function isDomainMatch(a: string, b: string): boolean {
  if (a === b) return true
  const partsA = a.split(".")
  const partsB = b.split(".")
  const hasTwoPartTld = twoPartTlds.some(
    (tld) => a.endsWith("." + tld) || b.endsWith("." + tld),
  )
  const numParts = hasTwoPartTld ? -3 : -2
  const min = Math.min(partsA.length, partsB.length, numParts)
  const tailA = partsA.slice(min).join(".")
  const tailB = partsB.slice(min).join(".")
  return tailA === tailB
}

async function allowRedirect(
  input: { clientID: string; redirectURI: string; audience?: string },
  req: Request,
): Promise<boolean> {
  // Native public client: a custom-scheme deep link.
  if (input.clientID === NATIVE_CLIENT_ID) {
    try {
      if (
        new URL(input.redirectURI).protocol === `${NATIVE_REDIRECT_SCHEME}:`
      ) {
        return true
      }
    } catch {
      /* malformed → fall through to the default check */
    }
  }
  // Default behavior (verbatim from openauth's built-in allow).
  let redir: string
  try {
    redir = new URL(input.redirectURI).hostname
  } catch {
    return false
  }
  if (redir === "localhost" || redir === "127.0.0.1") return true
  const forwarded = req.headers.get("x-forwarded-host")
  const host = forwarded
    ? new URL(`https://${forwarded}`).hostname
    : new URL(req.url).hostname
  return isDomainMatch(redir, host)
}

const app = issuer({
  subjects,
  storage,
  audiences: AUDIENCES,
  allow: allowRedirect,
  ...(ISSUER_URL ? { issuer: ISSUER_URL } : {}),
  providers: {
    password: PasswordProvider(
      PasswordUI({
        sendCode: async (email, code) => {
          if (transporter) {
            const text =
              `Your ${BRAND} verification code is: ${code}\n\n` +
              `Enter it on the page where you started signing in. ` +
              `The code expires shortly.\n\n` +
              `If you didn't request this, you can safely ignore this email.\n`
            const html =
              `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;font-size:15px;color:#1a1a1a;line-height:1.5">` +
              `<p>Your ${BRAND} verification code is:</p>` +
              `<p style="font-size:28px;font-weight:700;letter-spacing:4px;margin:16px 0">${code}</p>` +
              `<p>Enter it on the page where you started signing in. The code expires shortly.</p>` +
              `<p style="color:#666;font-size:13px;margin-top:24px">If you didn't request this, you can safely ignore this email.</p>` +
              `</div>`
            await transporter.sendMail({
              // Object form so a real display name rides along even when
              // OPENAUTH_FROM is a bare address.
              from: FROM_ADDR.includes("<")
                ? FROM_ADDR
                : { name: FROM_NAME, address: FROM_ADDR },
              to: email,
              replyTo: REPLY_TO,
              subject: `${code} is your ${BRAND} verification code`,
              text,
              html,
              headers: {
                // Mark as machine-generated transactional mail so receivers
                // (and any auto-responders) treat it correctly.
                "Auto-Submitted": "auto-generated",
                "X-Auto-Response-Suppress": "All",
              },
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
        email: value.email,
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
