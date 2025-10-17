# @ratio1/cstore-auth-ts

Plug-and-play authentication layer for Ratio1 CStore hashes. This TypeScript library wraps the official [@ratio1/ratio1-sdk-ts](https://github.com/Ratio1/ratio1-sdk-ts) SDK, providing a minimal API to bootstrap an admin account and manage simple username/password credentials.

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

| Variable                            | Description                                                                                        |
| ----------------------------------- | -------------------------------------------------------------------------------------------------- |
| `EE_CSTORE_AUTH_HKEY`               | Hash key that stores all user records (e.g. `auth:default`).                                       |
| `EE_CSTORE_AUTH_SECRET`             | Long-lived server-side pepper mixed into password hashes.                                          |
| `EE_CSTORE_AUTH_BOOTSTRAP_ADMIN_PW` | One-time bootstrap password for the initial `admin` user. Required until the admin account exists. |

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

// Retrieve all users
const allUsers = await auth.simple.getAllUsers();
console.log(`Total users: ${allUsers.length}`);
allUsers.forEach((u) => console.log(`- ${u.username} (${u.role})`));

// Update user metadata or role
// IMPORTANT: Implement authorization checks in your application layer!
// Example: Only allow users to edit themselves or admins to edit anyone
await auth.simple.updateUser('alice', {
  metadata: { email: 'newemail@example.com', verified: true }
});

// Change password (requires current password)
await auth.simple.changePassword('alice', 'S3curePassw0rd', 'NewP@ssw0rd!');
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
    getUser<TMeta = Record<string, unknown>>(username: string): Promise<PublicUser<TMeta> | null>;
    getAllUsers<TMeta = Record<string, unknown>>(): Promise<PublicUser<TMeta>[]>;
    updateUser<TMeta = Record<string, unknown>>(
      username: string,
      opts: UpdateUserOptions<TMeta>
    ): Promise<PublicUser<TMeta>>;
    changePassword(username: string, currentPassword: string, newPassword: string): Promise<void>;
  };
}
```

Errors are surfaced as descriptive subclasses (`EnvVarMissingError`, `AuthInitError`, `InvalidUsernameError`, `InvalidCredentialsError`, `UserExistsError`, `UserNotFoundError`, etc.).

### Authorization Patterns

⚠️ **IMPORTANT**: `updateUser` does not enforce authorization. You must implement authorization checks in your application layer.

```ts
// Example: Users can edit themselves, admins can edit anyone
async function updateUserWithAuth(
  currentUser: PublicUser,
  targetUsername: string,
  updates: UpdateUserOptions
) {
  // Check if user is editing themselves OR is an admin
  const isEditingSelf = currentUser.username === targetUsername;
  const isAdmin = currentUser.role === 'admin';

  if (!isEditingSelf && !isAdmin) {
    throw new Error('Unauthorized: You can only edit your own profile');
  }

  // Only admins can change roles
  if (updates.role && !isAdmin) {
    throw new Error('Unauthorized: Only admins can change roles');
  }

  return await auth.simple.updateUser(targetUsername, updates);
}

// Example: Express.js middleware
app.put('/api/users/:username', async (req, res) => {
  const currentUser = req.session.user; // From authenticated session
  const { username } = req.params;
  const updates = req.body;

  try {
    // Authorization check
    if (currentUser.username !== username && currentUser.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    // Only admins can change roles
    if (updates.role && currentUser.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can change roles' });
    }

    const updated = await auth.simple.updateUser(username, updates);
    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
```

## Security notes

### Password Security

- Argon2id (via `@node-rs/argon2`) is used when available. The module automatically downgrades to Node's built-in `crypto.scrypt` with strong defaults when Argon2 cannot load.
- Each user receives a random 16-byte salt and a global pepper (`EE_CSTORE_AUTH_SECRET`).
- Password hashes are stored versioned to enable future migrations.
- `changePassword` always requires current password verification.
- Secrets and hash material never leave the module through logs.

### Authorization

- ⚠️ **`updateUser` does NOT enforce authorization** - implement checks in your application layer
- Recommended pattern: Users can edit themselves, admins can edit anyone
- Role changes should be restricted to admins only
- Consider field-level permissions (e.g., users can't set `verified: true` on themselves)

### Data Validation

- Usernames are canonicalised to lowercase and must match `[a-z0-9._-]{3,64}`.
- Validation happens on every entry point.
- Only metadata is returned publicly (passwords never exposed).

## Development

```bash
pnpm install
pnpm run lint
pnpm test                  # Run unit tests
pnpm run test:integration  # Run integration tests
pnpm run test:all          # Run all tests
pnpm run build
pnpm run docs
```

### Testing

The project includes two test suites:

- **Unit tests** (`test/**/*.spec.ts`): Fast, isolated tests with mocked dependencies
- **Integration tests** (`test/integration/**/*.integration.spec.ts`): Complete workflow tests with realistic cleanup patterns

Integration tests follow best practices including:

- Cleanup before and after each test (setting values to null before deletion)
- Isolated test environments with unique hash keys
- Serial execution to avoid race conditions
- Extended timeouts for password hashing operations

See `test/integration/README.md` for detailed integration testing documentation.

Typedoc emits HTML documentation to `docs/`. GitHub Actions (see `.github/workflows/ci.yml`) runs linting, type-checking, tests, build, and docs generation on Node.js 18 and 20.

## Roadmap

- Additional providers (Google, OAuth 2.0) alongside the current `simple` method
- Session issuance (JWT/cookies) and rate limiting/lockouts
- Password rotation and secret (pepper) rotation workflows
- Multi-tenant or namespaced user separation
