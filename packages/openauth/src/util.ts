import type { Context } from "hono"

export type Prettify<T> = {
  [K in keyof T]: T[K]
}

/**
 * Hono ctx key used by issuer.ts to publish the configured static
 * issuer URL (IssuerInput.issuer). When set, getRelativeUrl rebases
 * onto it — bypassing request-URL inspection entirely. Without this
 * override the JWT `iss` ends up as e.g.
 * `https://auth.example.com:3000` (port leaks from listening port
 * + unset x-forwarded-port) and any exact-match issuer verifier
 * rejects it.
 */
export const ISSUER_BASE_CTX_KEY = "openauth.issuerBase" as const
export type IssuerBaseCtxKey = typeof ISSUER_BASE_CTX_KEY

export function getRelativeUrl(ctx: Context, path: string) {
  const baseOverride = ctx.get(ISSUER_BASE_CTX_KEY) as string | undefined
  if (baseOverride) {
    return new URL(path, baseOverride).toString()
  }
  const result = new URL(path, ctx.req.url)
  result.host = ctx.req.header("x-forwarded-host") || result.host
  result.protocol = ctx.req.header("x-forwarded-proto") || result.protocol
  result.port = ctx.req.header("x-forwarded-port") || result.port
  return result.toString()
}

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

export function isDomainMatch(a: string, b: string): boolean {
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

export function lazy<T>(fn: () => T): () => T {
  let value: T | undefined
  return () => {
    if (value === undefined) {
      value = fn()
    }
    return value
  }
}
