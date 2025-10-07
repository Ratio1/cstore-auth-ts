import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { CStoreAuth } from '../src/auth';
import {
  EnvVarMissingError,
  InvalidCredentialsError,
  InvalidUserRoleError,
  InvalidUsernameError,
  UserExistsError
} from '../src/util/errors';
import { MemoryCStore } from './fixtures/memory-cstore';

let cstore: MemoryCStore;

const BASE_ENV = {
  hkey: 'auth:test',
  secret: 'super-secret-pepper',
  bootstrap: 'boot-password'
};

describe('CStoreAuth', () => {
  beforeEach(() => {
    cstore = new MemoryCStore();
    setEnv(BASE_ENV);
  });

  afterEach(() => {
    unsetEnv();
  });

  it('bootstraps the admin user when missing', async () => {
    const auth = createAuth();
    await auth.initAuth();

    const admin = await auth.getUser('admin');
    expect(admin).not.toBeNull();
    expect(admin?.role).toBe('admin');

    const adminRaw = await cstore.hget(BASE_ENV.hkey, 'admin');
    expect(adminRaw).toBeTruthy();
    const record = JSON.parse(adminRaw!) as { password: { hash: string } };
    expect(record.password.hash).toBeTypeOf('string');
  });

  it('does not require bootstrap password when admin already exists', async () => {
    const firstAuth = createAuth();
    await firstAuth.initAuth();

    const originalRecord = await cstore.hget(BASE_ENV.hkey, 'admin');
    expect(originalRecord).toBeTruthy();

    unsetEnv();
    setEnv({ hkey: BASE_ENV.hkey, secret: BASE_ENV.secret });

    const secondAuth = createAuth();
    await secondAuth.initAuth();

    const recordAfter = await cstore.hget(BASE_ENV.hkey, 'admin');
    expect(recordAfter).toBe(originalRecord);
  });

  it('throws when bootstrap password missing and admin absent', async () => {
    unsetEnv();
    setEnv({ hkey: BASE_ENV.hkey, secret: BASE_ENV.secret });

    const auth = createAuth();
    await expect(auth.initAuth()).rejects.toBeInstanceOf(EnvVarMissingError);
  });

  it('creates users with metadata and returns public view', async () => {
    const auth = createAuth();
    await auth.initAuth();

    const metadata = { email: 'alice@example.com' };
    const user = await auth.createUser('Alice', 'Passw0rd!', { metadata });
    metadata.email = 'mutated@example.com';

    expect(user.username).toBe('alice');
    expect(user.metadata).toEqual({ email: 'alice@example.com' });
    expect(user.type).toBe('simple');
    expect(user.role).toBe('user');

    const storedRaw = await cstore.hget(BASE_ENV.hkey, 'alice');
    const storedRecord = JSON.parse(storedRaw!) as {
      metadata: { email: string };
      password: unknown;
    };
    expect(storedRecord.metadata).toEqual({ email: 'alice@example.com' });
    expect(storedRecord.password).toMatchObject({ hash: expect.any(String) });
  });

  it('rejects duplicate usernames', async () => {
    const auth = createAuth();
    await auth.initAuth();

    await auth.createUser('Bob', 'AnotherPass1');
    await expect(auth.createUser('bob', 'AnotherPass1')).rejects.toBeInstanceOf(UserExistsError);
  });

  it('canonicalizes usernames during authentication', async () => {
    const auth = createAuth();
    await auth.initAuth();

    await auth.createUser('Charlie', 'S3cureP@ss');

    const user = await auth.authenticate('CHARLIE', 'S3cureP@ss');
    expect(user.username).toBe('charlie');
  });

  it('rejects invalid credentials', async () => {
    const auth = createAuth();
    await auth.initAuth();

    await auth.createUser('Dana', 'StrongPass1');

    await expect(auth.authenticate('dana', 'wrong-pass')).rejects.toBeInstanceOf(
      InvalidCredentialsError
    );
    await expect(auth.authenticate('unknown', 'anything')).rejects.toBeInstanceOf(
      InvalidCredentialsError
    );
  });

  it('validates username input', async () => {
    const auth = createAuth();
    await auth.initAuth();

    await expect(auth.createUser('??bad??', 'Pass123!')).rejects.toBeInstanceOf(
      InvalidUsernameError
    );
  });

  it('validates roles', async () => {
    const auth = createAuth();
    await auth.initAuth();

    await expect(
      auth.createUser('eve', 'Pass123!', { role: 'superuser' as unknown as 'admin' })
    ).rejects.toBeInstanceOf(InvalidUserRoleError);
  });

  it('returns null for missing users', async () => {
    const auth = createAuth();
    await auth.initAuth();

    const user = await auth.getUser('missing');
    expect(user).toBeNull();
  });
});

function createAuth(): CStoreAuth {
  const now = () => new Date('2024-01-01T00:00:00Z');
  return new CStoreAuth({ client: cstore, now });
}

function setEnv(values: { hkey: string; secret: string; bootstrap?: string }): void {
  process.env.EE_CSTORE_AUTH_HKEY = values.hkey;
  process.env.EE_CSTORE_AUTH_SECRET = values.secret;
  if (values.bootstrap) {
    process.env.EE_CSTORE_BOOTSTRAP_ADMIN_PASS = values.bootstrap;
  } else {
    delete process.env.EE_CSTORE_BOOTSTRAP_ADMIN_PASS;
  }
}

function unsetEnv(): void {
  delete process.env.EE_CSTORE_AUTH_HKEY;
  delete process.env.EE_CSTORE_AUTH_SECRET;
  delete process.env.EE_CSTORE_BOOTSTRAP_ADMIN_PASS;
}
