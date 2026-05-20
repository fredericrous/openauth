# openauth issuer — Hono server behind @fredericrous/openauth.
# bun-managed monorepo install; runtime is node + tsx so we keep the
# deploy image small and avoid baking bun into prod.
# oven/bun isn't on mirror.gcr.io (only docker hub `library/*` is
# mirrored). Pull straight from Docker Hub; build is on ubuntu-latest
# so rate-limit risk is bounded.
#
# Pinned to 1.1.42 because bun 1.2+ rewrites
# `export { foo } from "./x.js"` (re-export) into a bare
# `export { foo };` — strips the source path and produces a runtime
# ReferenceError. Until upstream fixes that, hold the version.
FROM oven/bun:1.1.42 AS deps
WORKDIR /workspace
COPY package.json bun.lockb bunfig.toml ./
COPY packages/openauth/package.json packages/openauth/
COPY apps/issuer/package.json apps/issuer/
# `--production` would skip devDeps, but tsx is declared as a devDep
# in apps/issuer and we need it at runtime. Keep full install.
RUN bun install --frozen-lockfile

FROM deps AS build
WORKDIR /workspace
# Build the SDK package — runtime resolves
# `@fredericrous/openauth/...` through a workspace symlink, so
# packages/openauth/dist/ must exist.
COPY packages/openauth packages/openauth
RUN cd packages/openauth && bun run build

FROM mirror.gcr.io/library/node:24-alpine
WORKDIR /workspace
ENV NODE_ENV=production
ENV OPENAUTH_PORT=3000
ENV OPENAUTH_PERSIST_PATH=/data/openauth.json
RUN addgroup -S app && adduser -S app -G app && \
    mkdir -p /data && chown app:app /data
# bun's flat layout: every package lives under /workspace/node_modules/<name>;
# per-package node_modules are symlinks back to that root.
COPY --from=deps --chown=app:app /workspace/node_modules /workspace/node_modules
# packages/openauth comes from the `build` stage (which is `deps`
# plus the SDK's dist/ output). The runtime resolves
# `@fredericrous/openauth/...` to packages/openauth/dist/esm/...
COPY --from=build --chown=app:app /workspace/packages/openauth /workspace/packages/openauth
COPY --chown=app:app apps/issuer/src /workspace/apps/issuer/src
COPY --chown=app:app apps/issuer/package.json apps/issuer/tsconfig.json /workspace/apps/issuer/
USER app
WORKDIR /workspace/apps/issuer
VOLUME ["/data"]
EXPOSE 3000
CMD ["node", "--import", "tsx", "./src/index.ts"]
