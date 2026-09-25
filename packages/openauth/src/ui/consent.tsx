/**
 * The consent screen shown to a user before a dynamically registered client
 * (RFC 7591) receives its first authorization code for them.
 *
 * A registered client names itself, so its name proves nothing. The screen
 * therefore leads with the host the code will be sent to — the one fact the
 * issuer verified at registration — and shows the name as a claim.
 *
 * ```ts
 * import { Consent } from "@openauthjs/openauth/ui/consent"
 *
 * export default issuer({
 *   registration: {
 *     resources: ["https://mcp.example.com/mcp"],
 *     consent: Consent({ title: "Allow access?" }),
 *   },
 *   // ...
 * })
 * ```
 *
 * @packageDocumentation
 */
/** @jsxImportSource hono/jsx */

import { Layout } from "./base.js"

/** What the consent page is asked to show. */
export interface ConsentProps {
  /** The client's self-declared name. */
  clientName: string
  /** Host of the redirect URI the authorization code goes to. */
  redirectHost: string
  /** What approving grants, in words. */
  permission: string
  /** Form field values the page must POST back to `action`. */
  form: {
    action: string
    nonce: string
  }
}

export interface ConsentOptions {
  title?: string
}

export function Consent(options?: ConsentOptions) {
  return async (props: ConsentProps, _req: Request): Promise<Response> => {
    const jsx = (
      <Layout>
        <form data-component="form" method="post" action={props.form.action}>
          <p>
            <strong>{options?.title ?? "Allow access?"}</strong>
          </p>
          <p>
            An application at <strong>{props.redirectHost}</strong>, calling
            itself “{props.clientName}”, asks to {props.permission}.
          </p>
          <p>Only continue if you started this from that application.</p>
          <input type="hidden" name="nonce" value={props.form.nonce} />
          <button
            data-component="button"
            type="submit"
            name="decision"
            value="approve"
          >
            Allow
          </button>
          <button
            data-component="button"
            data-color="ghost"
            type="submit"
            name="decision"
            value="deny"
          >
            Deny
          </button>
        </form>
      </Layout>
    )
    return new Response(jsx.toString(), {
      headers: {
        "Content-Type": "text/html",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "frame-ancestors 'none'",
      },
    })
  }
}
