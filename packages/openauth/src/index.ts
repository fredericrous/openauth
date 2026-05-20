import { createClient } from "./client.js"
import { createSubjects } from "./subject.js"
import { issuer } from "./issuer.js"

export {
  /**
   * @deprecated
   * Use `import { createClient } from "@fredericrous/openauth/client"` instead - it will tree shake better
   */
  createClient,
  /**
   * @deprecated
   * Use `import { createSubjects } from "@fredericrous/openauth/subject"` instead - it will tree shake better
   */
  createSubjects,
  /**
   * @deprecated
   * Use `import { issuer } from "@fredericrous/openauth"` instead, it was renamed
   */
  issuer as authorizer,
  issuer,
}
