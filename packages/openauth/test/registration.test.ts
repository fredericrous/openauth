/**
 * Dynamic client registration (RFC 7591) and the rules a registered client
 * is held to: exact redirect, PKCE S256, an RFC 8707 resource bound through
 * code, token and refresh, and a consent screen before the first code.
 */
import { describe, expect, test } from "bun:test"
import { decodeJwt } from "jose"
import { object, string } from "valibot"
import { issuer } from "../src/issuer.js"
import { createSubjects } from "../src/subject.js"
import { MemoryStorage } from "../src/storage/memory.js"
import { Provider } from "../src/provider/provider.js"
import { generatePKCE } from "../src/pkce.js"

const RESOURCE = "https://mcp.example.com/mcp"
const REDIRECT = "http://127.0.0.1:33418/callback"
const BASE = "https://auth.example.com"

const subjects = createSubjects({
  user: object({ userID: string() }),
})

function makeIssuer() {
  return issuer({
    storage: MemoryStorage(),
    subjects,
    // Static clients: anything goes, so a registered client passing is never
    // `allow` letting it through.
    allow: async () => true,
    registration: { resources: [RESOURCE], permission: "edit your sites" },
    providers: {
      dummy: {
        type: "dummy",
        init(route, ctx) {
          route.get("/authorize", async (c) =>
            ctx.success(c, { email: "foo@bar.com" }),
          )
        },
      } satisfies Provider<{ email: string }>,
    },
    success: async (ctx) => ctx.subject("user", { userID: "123" }),
  })
}

type App = ReturnType<typeof makeIssuer>

/** Follows the browser's side of the flow, cookies included. */
class Browser {
  private jar = new Map<string, string>()
  constructor(private app: App) {}

  async request(path: string, init: RequestInit = {}) {
    const url = path.startsWith("http") ? path : BASE + path
    const cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ")
    const res = await this.app.request(url, {
      ...init,
      headers: { ...(init.headers ?? {}), ...(cookie ? { cookie } : {}) },
    })
    for (const set of res.headers.getSetCookie()) {
      const [pair] = set.split(";")
      const i = pair!.indexOf("=")
      const name = pair!.slice(0, i)
      const value = pair!.slice(i + 1)
      if (value === "" || /max-age=0/i.test(set)) this.jar.delete(name)
      else this.jar.set(name, value)
    }
    return res
  }
}

async function register(app: App, body: unknown) {
  return app.request(BASE + "/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  })
}

async function registerClient(app: App) {
  const res = await register(app, {
    client_name: "Test MCP client",
    redirect_uris: [REDIRECT],
  })
  expect(res.status).toBe(201)
  return (await res.json()).client_id as string
}

function authorizeUrl(params: Record<string, string | undefined>) {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined) q.set(k, v)
  return `/authorize?${q}`
}

/** Authorize as `clientID` and walk the redirects up to the first stop that
 *  is not on the issuer: returns that final response. */
async function walk(browser: Browser, first: string) {
  let res = await browser.request(first)
  for (let i = 0; i < 5 && res.status === 302; i++) {
    const loc = res.headers.get("location")!
    const url = new URL(loc, BASE)
    if (url.origin !== BASE) return res
    res = await browser.request(url.pathname + url.search)
  }
  return res
}

async function approveConsent(browser: Browser, decision = "approve") {
  const page = await browser.request("/consent")
  expect(page.status).toBe(200)
  const html = await page.text()
  const nonce = /name="nonce" value="([^"]+)"/.exec(html)![1]!
  return browser.request("/consent", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ nonce, decision }).toString(),
  })
}

function token(app: App, form: Record<string, string>) {
  return app.request(BASE + "/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  })
}

/** A full, successful grant: returns the code and what produced it. */
async function obtainCode(app: App, browser: Browser, clientID: string) {
  const pkce = await generatePKCE()
  let res = await walk(
    browser,
    authorizeUrl({
      client_id: clientID,
      redirect_uri: REDIRECT,
      response_type: "code",
      state: "st",
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
      resource: RESOURCE,
    }),
  )
  if (res.status === 200) res = await approveConsent(browser)
  expect(res.status).toBe(302)
  const loc = new URL(res.headers.get("location")!)
  expect(loc.origin + loc.pathname).toBe(REDIRECT)
  expect(loc.searchParams.get("state")).toBe("st")
  const code = loc.searchParams.get("code")!
  expect(code).toBeTruthy()
  return { code, verifier: pkce.verifier }
}

describe("registration", () => {
  test("registers a public client", async () => {
    const app = makeIssuer()
    const res = await register(app, {
      client_name: "Claude",
      redirect_uris: [REDIRECT, "https://claude.ai/api/mcp/auth_callback"],
    })
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.client_id).toMatch(/^dcr_/)
    expect(body.token_endpoint_auth_method).toBe("none")
    expect(body.redirect_uris).toHaveLength(2)
  })

  test.each([
    ["http off loopback", { redirect_uris: ["http://evil.example/cb"] }],
    ["a fragment", { redirect_uris: ["https://a.example/cb#x"] }],
    ["no redirect", { redirect_uris: [] }],
    [
      "a client secret",
      {
        redirect_uris: [REDIRECT],
        token_endpoint_auth_method: "client_secret_basic",
      },
    ],
    [
      "an implicit grant",
      { redirect_uris: [REDIRECT], grant_types: ["implicit"] },
    ],
  ])("refuses %s", async (_label, body) => {
    const res = await register(makeIssuer(), body)
    expect(res.status).toBe(400)
  })

  test("advertises itself and PKCE S256 in the metadata", async () => {
    const res = await makeIssuer().request(
      BASE + "/.well-known/oauth-authorization-server",
    )
    const meta = await res.json()
    expect(meta.registration_endpoint).toBe(BASE + "/register")
    expect(meta.code_challenge_methods_supported).toEqual(["S256"])
  })
})

describe("registered client grant", () => {
  test("consent, code, token and refresh, all bound to the resource", async () => {
    const app = makeIssuer()
    const browser = new Browser(app)
    const clientID = await registerClient(app)

    // First authorization stops at the consent page.
    const pkce = await generatePKCE()
    const stop = await walk(
      browser,
      authorizeUrl({
        client_id: clientID,
        redirect_uri: REDIRECT,
        response_type: "code",
        state: "st",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      }),
    )
    expect(stop.status).toBe(200)
    const html = await stop.text()
    expect(html).toContain("127.0.0.1:33418")
    expect(html).toContain("Test MCP client")
    expect(html).toContain("edit your sites")

    const approved = await approveConsent(browser)
    const code = new URL(approved.headers.get("location")!).searchParams.get(
      "code",
    )!

    const res = await token(app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT,
      client_id: clientID,
      code_verifier: pkce.verifier,
      resource: RESOURCE,
    })
    expect(res.status).toBe(200)
    const tokens = await res.json()
    expect(tokens.token_type).toBe("Bearer")
    expect(decodeJwt(tokens.access_token).aud).toBe(RESOURCE)

    const refreshed = await token(app, {
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: clientID,
      resource: RESOURCE,
    })
    expect(refreshed.status).toBe(200)
    const next = await refreshed.json()
    expect(next.token_type).toBe("Bearer")
    expect(decodeJwt(next.access_token).aud).toBe(RESOURCE)

    // Consent is remembered: the next authorization goes straight through.
    const again = await walk(
      browser,
      authorizeUrl({
        client_id: clientID,
        redirect_uri: REDIRECT,
        response_type: "code",
        state: "st2",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      }),
    )
    expect(again.status).toBe(302)
    const againLoc = new URL(again.headers.get("location")!)
    expect(againLoc.origin + againLoc.pathname).toBe(REDIRECT)
    expect(againLoc.searchParams.get("code")).toBeTruthy()
  })

  test("denying consent returns access_denied and no code", async () => {
    const app = makeIssuer()
    const browser = new Browser(app)
    const clientID = await registerClient(app)
    const pkce = await generatePKCE()
    await walk(
      browser,
      authorizeUrl({
        client_id: clientID,
        redirect_uri: REDIRECT,
        response_type: "code",
        state: "st",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      }),
    )
    const res = await approveConsent(browser, "deny")
    const loc = new URL(res.headers.get("location")!)
    expect(loc.searchParams.get("error")).toBe("access_denied")
    expect(loc.searchParams.get("code")).toBeNull()
  })

  test("a consent POST without the page's nonce is refused", async () => {
    const app = makeIssuer()
    const browser = new Browser(app)
    const clientID = await registerClient(app)
    const pkce = await generatePKCE()
    await walk(
      browser,
      authorizeUrl({
        client_id: clientID,
        redirect_uri: REDIRECT,
        response_type: "code",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      }),
    )
    const res = await browser.request("/consent", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "nonce=guessed&decision=approve",
    })
    expect(res.status).toBe(400)
  })
})

describe("registered client authorize refusals", () => {
  async function authorizeWith(params: Record<string, string | undefined>) {
    const app = makeIssuer()
    const clientID = await registerClient(app)
    const pkce = await generatePKCE()
    return app.request(
      BASE +
        authorizeUrl({
          client_id: clientID,
          redirect_uri: REDIRECT,
          response_type: "code",
          code_challenge: pkce.challenge,
          code_challenge_method: "S256",
          resource: RESOURCE,
          ...params,
        }),
    )
  }
  const errorOf = (res: Response) =>
    new URL(res.headers.get("location")!).searchParams.get("error")

  test("an unregistered redirect gets a 400 and no redirect at all", async () => {
    const res = await authorizeWith({
      redirect_uri: "http://127.0.0.1:9999/other",
    })
    expect(res.status).toBe(400)
    expect(res.headers.get("location")).toBeNull()
  })

  test("missing PKCE", async () => {
    const res = await authorizeWith({
      code_challenge: undefined,
      code_challenge_method: undefined,
    })
    expect(errorOf(res)).toBe("invalid_request")
  })

  test("plain PKCE", async () => {
    const res = await authorizeWith({ code_challenge_method: "plain" })
    expect(errorOf(res)).toBe("invalid_request")
  })

  test("missing resource", async () => {
    const res = await authorizeWith({ resource: undefined })
    expect(errorOf(res)).toBe("invalid_target")
  })

  test("a resource this issuer does not serve", async () => {
    const res = await authorizeWith({
      resource: "https://other.example/mcp",
    })
    expect(errorOf(res)).toBe("invalid_target")
  })

  test("the implicit flow", async () => {
    const res = await authorizeWith({ response_type: "token" })
    expect(errorOf(res)).toBe("unsupported_response_type")
  })
})

describe("registered client token refusals", () => {
  async function setup() {
    const app = makeIssuer()
    const browser = new Browser(app)
    const clientID = await registerClient(app)
    const { code, verifier } = await obtainCode(app, browser, clientID)
    const base = {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT,
      client_id: clientID,
      code_verifier: verifier,
      resource: RESOURCE,
    }
    return { app, clientID, base }
  }

  test("wrong code verifier", async () => {
    const { app, base } = await setup()
    const res = await token(app, { ...base, code_verifier: "x".repeat(64) })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe("invalid_grant")
  })

  test("another client redeeming the code", async () => {
    const { app, base } = await setup()
    const other = await registerClient(app)
    const res = await token(app, { ...base, client_id: other })
    expect(res.status).toBe(403)
  })

  test("resource mismatch at the token endpoint", async () => {
    const { app, base } = await setup()
    const res = await token(app, {
      ...base,
      resource: "https://other.example/mcp",
    })
    expect((await res.json()).error).toBe("invalid_target")
  })

  test("resource missing at the token endpoint", async () => {
    const { app, base } = await setup()
    const { resource: _omit, ...rest } = base
    const res = await token(app, rest)
    expect((await res.json()).error).toBe("invalid_target")
  })

  test("refresh by another client, or for another resource", async () => {
    const { app, clientID, base } = await setup()
    const tokens = await (await token(app, base)).json()
    const other = await registerClient(app)

    const stolen = await token(app, {
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: other,
    })
    expect(stolen.status).toBe(400)
    expect((await stolen.json()).error).toBe("invalid_grant")

    const reaimed = await token(app, {
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: clientID,
      resource: "https://other.example/mcp",
    })
    expect((await reaimed.json()).error).toBe("invalid_target")
  })
})

describe("static clients", () => {
  test("keep their audience: a resource parameter changes nothing", async () => {
    const app = makeIssuer()
    const browser = new Browser(app)
    const res = await walk(
      browser,
      authorizeUrl({
        client_id: "builder-webapp",
        redirect_uri: "https://app.example.com/cb",
        response_type: "code",
        resource: RESOURCE,
      }),
    )
    expect(res.status).toBe(302)
    const code = new URL(res.headers.get("location")!).searchParams.get("code")!
    const tokens = await (
      await token(app, {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.example.com/cb",
        client_id: "builder-webapp",
      })
    ).json()
    expect(decodeJwt(tokens.access_token).aud).toBe("builder-webapp")
  })
})
