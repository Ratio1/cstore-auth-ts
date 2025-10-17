# Collaboration Blueprint

## Repo Architect

- Confirmed against `@ratio1/ratio1-sdk-ts@1.1.5`: CStore service methods accept `{ hkey, key }` objects. `CStoreClientAdapter` hides that detail and exposes `hget`, `hset`, `hgetAll` signatures used throughout the package.
- Builds produce ESM, CJS, and declaration bundles via `tsup`. Entry point is `src/index.ts` and only exports typed surface area for tree-shaking.
- `tsconfig.json` enables strict mode and preserves module resolution for Node 18+. Source maps are emitted for debugging consumers.
- Provider modules live alongside the orchestrator: `src/simple-auth.ts` implements the current simple provider so `src/auth.ts` can stay lean as new providers (OAuth, etc.) are introduced.

## Security Reviewer

- `PasswordHasher` prefers `@node-rs/argon2` with Argon2id params (timeCost=3, memoryCost=64MiB, parallelism=1). When the native addon fails to load, the module downgrades to Node's `crypto.scrypt` fallback once per process and emits a warning through the injected logger.
- Hash comparison uses `timingSafeEqual`. Salts are 16 random bytes, pepper is injected secret; both algorithms persist versioned metadata for migrations.
- Secrets and hash material never leave the module through logs or thrown errors.

## DX Writer

- README covers installation, env vars, quick start, API, security posture, and roadmap. Typedoc config emits API docs to `docs/`.
- Examples type-check thanks to `PublicUser<TMeta>` generics and inline doc comments.
- Error classes have clear, actionable messages for app developers.

## CI Engineer

- GitHub Actions workflow runs lint, type-check (`tsc --noEmit`), tests (`vitest run`), build (`tsup`), and docs (`typedoc`). Matrix covers Node 18 and 20.
- Changesets is configured in `.changeset/config.json` for future release flow.

## QA

- Vitest suite exercises admin bootstrap idempotency, username validation, Argon2id hashing, and forced Scrypt fallback (via dependency injection). In-memory CStore mock mirrors hash semantics and serializes JSON payloads.
- Tests assert public user shape snapshots and error conditions (duplicates, invalid credentials, malformed env).

## Definition of Done

- All commands (`lint`, `test`, `build`, `docs`) succeed locally and in CI.
- Public API is fully typed, no `any` leaks.
- No secret leakage in logs, and README/Typedoc accurately reflect the implemented behavior.
