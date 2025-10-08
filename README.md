# @ratio1/cstore-auth-ts

Plug-and-play authentication layer for Ratio1 CStore hashes. This TypeScript library wraps the official [@ratio1/edge-node-client](https://github.com/Ratio1/edge-node-client) SDK, providing a minimal API to bootstrap an admin account and manage simple username/password credentials.

## Features

- Hash-backed user store with Argon2id hashing and automatic Node.js scrypt fallback
- Strict username validation and canonicalisation (lowercase keys)
- Admin bootstrap workflow driven by environment variables
- Strong typing, unit tests (Vitest), linting, and dual ESM/CJS builds via tsup
- Works in Node.js services and Next.js API routes

## Installation

```bash
pnpm add @ratio1/cstore-auth-ts
# or
npm install @ratio1/cstore-auth-ts
```

## Required environment variables

| Variable                         | Description                                                                                        |
| -------------------------------- | -------------------------------------------------------------------------------------------------- |
| `EE_CSTORE_AUTH_HKEY`            | Hash key that stores all user records (e.g. `auth:default`).                                       |
| `EE_CSTORE_AUTH_SECRET`          | Long-lived server-side pepper mixed into password hashes.                                          |
| `EE_CSTORE_BOOTSTRAP_ADMIN_PASS` | One-time bootstrap password for the initial `admin` user. Required until the admin account exists. |

## Quick start

```ts
import { CStoreAuth } from '@ratio1/cstore-auth-ts';

const auth = new CStoreAuth();
await auth.simple.init();

await auth.simple.createUser('alice', 'S3curePassw0rd', {
  metadata: { email: 'alice@example.com' }
});

const user = await auth.simple.authenticate('alice', 'S3curePassw0rd');
console.log(user);
// → { username: 'alice', role: 'user', metadata: { email: 'alice@example.com' }, createdAt: '...', updatedAt: '...', type: 'simple' }
```

### Public API

```ts
interface CStoreAuthOptions {
  hkey?: string;
  secret?: string;
  client?: CStoreLikeClient;
  hasher?: PasswordHasher;
  now?: () => Date;
  logger?: Pick<Console, 'debug' | 'info' | 'warn' | 'error'>;
}

class CStoreAuth {
  constructor(opts?: CStoreAuthOptions);

  simple: {
    init(): Promise<void>;
    createUser<TMeta = Record<string, unknown>>(
      username: string,
      password: string,
      opts?: CreateUserOptions<TMeta>
    ): Promise<PublicUser<TMeta>>;
    authenticate<TMeta = Record<string, unknown>>(
      username: string,
      password: string
    ): Promise<PublicUser<TMeta>>;
    getUser<TMeta = Record<string, unknown>>(
      username: string
    ): Promise<PublicUser<TMeta> | null>;
  };

}
```

Errors are surfaced as descriptive subclasses (`EnvVarMissingError`, `AuthInitError`, `InvalidUsernameError`, `InvalidCredentialsError`, `UserExistsError`, etc.).

## Security notes

- Argon2id (via `@node-rs/argon2`) is used when available. The module automatically downgrades to Node's built-in `crypto.scrypt` with strong defaults when Argon2 cannot load.
- Each user receives a random 16-byte salt and a global pepper (`EE_CSTORE_AUTH_SECRET`).
- Password hashes are stored versioned to enable future migrations.
- Usernames are canonicalised to lowercase and must match `[a-z0-9._-]{3,64}`. Validation happens on every entry point.
- Secrets and hash material never leave the module through logs; only metadata is returned publicly.

## Development

```bash
pnpm install
pnpm run lint
pnpm test
pnpm run build
pnpm run docs
```

Typedoc emits HTML documentation to `docs/`. GitHub Actions (see `.github/workflows/ci.yml`) runs linting, type-checking, tests, build, and docs generation on Node.js 18 and 20.

## Roadmap

- Additional providers (Google, OAuth 2.0) alongside the current `simple` method
- Session issuance (JWT/cookies) and rate limiting/lockouts
- Password rotation and secret (pepper) rotation workflows
- Multi-tenant or namespaced user separation
