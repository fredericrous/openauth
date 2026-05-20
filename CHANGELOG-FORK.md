# @fredericrous/openauth — fork changelog

This file tracks the divergence between `@fredericrous/openauth` and
upstream `@openauthjs/openauth` (anomalyco). Versioning resets to
`0.5.0` at the fork point to make it clear we're not claiming
compatibility with future upstream versions of the same minor.

## 0.5.2 (2026-05-20) — multi-audience access tokens

### Added — `IssuerInput.audiences`

`issuer({ ..., audiences })` accepts a `Record<client_id, string[]>`
map of extra audiences to embed in the access-token `aud` claim. By
default the token's `aud` is the requesting client_id as a single
string (RFC 7519 §4.1.3). When this map has an entry for a client_id,
the token's `aud` becomes an array `[<client_id>, ...extras]`.

**Motivation:** in a multi-service backend, the user's UI client
(e.g. `builder-webapp`) holds the access token, but the same token
needs to authenticate to sibling APIs (e.g. `builder-api`). Without
multi-audience tokens, each downstream API's JWT verifier rejects
the token on `aud` mismatch (401). Multi-audience is the standard
OIDC pattern for this; the alternative is per-API token exchange
(RFC 8693), which is heavier.

```ts
issuer({
  audiences: {
    "builder-webapp": ["builder-api"],
  },
  ...
})
// → tokens for client_id="builder-webapp" carry
//   aud=["builder-webapp", "builder-api"]
```

When the map is empty or unset, the previous single-string `aud`
behavior is preserved — no breaking change.

## 0.5.1 (2026-05-20) — build-script fix

`script/build.ts` switched from per-file `Bun.build({ external: ["*"] })`
to `tsc` for the `.js` output (declarations + `ui/base.tsx` bundle
still use bun). bun 1.2+ aggressively dead-strips imports whose only
use is a re-export, producing `index.js` with bare `export { X };`
statements and no in-scope binding — node refuses to load with
"Export 'X' is not defined in module". tsc preserves all imports
and exports verbatim regardless of bun version. SDK now builds
cleanly on bun 1.3.14 (and any future version).

src/index.ts also rewritten from `export {} from "./..."` re-export
syntax to plain `import` + `export` blocks — equivalent semantics,
cleaner shape, doesn't depend on bun's re-export codegen.

No public API change.

## 0.5.0 (2026-05-20) — forked from upstream 0.4.3

### Added — `ClientInput.internalUrl`

`createClient({ ..., internalUrl })` accepts an alternative base URL
used for server-to-server calls only:

- `GET /.well-known/oauth-authorization-server`
- `POST /token` (both `exchange` and `refresh`)
- `GET <wk.jwks_uri>` (rewritten from the discovery doc response)

Browser-facing flows (`authorize` redirect URL) and JWT `iss`
verification continue to use the public `issuer`.

**Motivation:** in Istio ambient-mode Kubernetes, public hostnames
hairpin out to the gateway, which may enforce mTLS / WAF rules that
in-cluster pods don't satisfy. Pointing `internalUrl` at the
ClusterIP / Service DNS keeps the exchange on-cluster:

```ts
createClient({
  clientID: "my-app",
  issuer: "https://auth.builder.example.com", // signed iss, browser redirects
  internalUrl: "http://openauth.openauth.svc.cluster.local:3000",
})
```

The wrapper spoofs `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto`
to the values parsed from `issuer` so the auth server still signs
JWTs with `iss = <issuer>` and returns public URLs in its discovery
response — downstream verifiers don't need to know `internalUrl`
exists.

Implementation: see `packages/openauth/src/client.ts`
`createClient()` (the `if (input.internalUrl && input.internalUrl !==
issuer)` block that wraps `baseFetch`).
