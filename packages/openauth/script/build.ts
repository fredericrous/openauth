import { $ } from "bun"
import pkg from "../package.json"

// Note on the per-file build approach:
//
//   bun 1.1.42 used to handle `Bun.build({ external: ["*"] })` on a
//   single-entrypoint correctly — it transpiled the file in isolation
//   and kept all imports + exports verbatim. bun 1.2+ aggressively
//   dead-code-strips imports whose only use is a re-export (and
//   sometimes strips them even when locally used via `void` sentinel),
//   producing output like `export { createClient }` with no binding
//   in scope. Node then refuses to load it with "Export 'X' is not
//   defined in module".
//
//   Switching the per-file path to `tsc` makes the build version-
//   resilient: tsc's job is "transpile TypeScript → JavaScript", it
//   does not bundle and does not strip imports. The `dist/esm/`
//   layout (one .js per .ts) is preserved.
//
//   The `ui/base.tsx` entry below still uses Bun.build because we
//   want the StyleX-style JSX → string output bundled into a single
//   file with deps bundled in (UI doesn't need to expose each file).
//   That entrypoint only IMPORTS values; it doesn't have the
//   re-export pattern, so bun's stripper leaves it alone.

await $`rm -rf dist`

await $`tsc \
  --project tsconfig.json \
  --outDir dist/esm \
  --module ESNext \
  --moduleResolution Bundler \
  --target ES2022 \
  --declaration false`

await Bun.build({
  format: "esm",
  outdir: "dist/esm",
  external: [
    ...Object.keys(pkg.dependencies),
    ...Object.keys(pkg.peerDependencies),
  ],
  root: "src",
  entrypoints: ["./src/ui/base.tsx"],
})

await $`tsc --outDir dist/types --declaration --emitDeclarationOnly --declarationMap`
