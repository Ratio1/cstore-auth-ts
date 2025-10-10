import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { CStoreAuth } from '../src/auth';
import {
  EnvVarMissingError,
  InvalidCredentialsError,
  InvalidUserRoleError,
  InvalidUsernameError,
  UserExistsError,
  UserNotFoundError
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
    await auth.simple.init();

    const admin = await auth.simple.getUser('admin');
    expect(admin).not.toBeNull();
    expect(admin?.role).toBe('admin');

    const adminRaw = await cstore.hget(BASE_ENV.hkey, 'admin');
    expect(adminRaw).toBeTruthy();
    const record = JSON.parse(adminRaw!) as { password: { hash: string } };
    expect(record.password.hash).toBeTypeOf('string');
  });

  it('does not require bootstrap password when admin already exists', async () => {
    const firstAuth = createAuth();
    await firstAuth.simple.init();

    const originalRecord = await cstore.hget(BASE_ENV.hkey, 'admin');
    expect(originalRecord).toBeTruthy();

    unsetEnv();
    setEnv({ hkey: BASE_ENV.hkey, secret: BASE_ENV.secret });

    const secondAuth = createAuth();
    await secondAuth.simple.init();

    const recordAfter = await cstore.hget(BASE_ENV.hkey, 'admin');
    expect(recordAfter).toBe(originalRecord);
  });

  it('throws when bootstrap password missing and admin absent', async () => {
    unsetEnv();
    setEnv({ hkey: BASE_ENV.hkey, secret: BASE_ENV.secret });

    const auth = createAuth();
    await expect(auth.simple.init()).rejects.toBeInstanceOf(EnvVarMissingError);
  });

  it('creates users with metadata and returns public view', async () => {
    const auth = createAuth();
    await auth.simple.init();

    const metadata = { email: 'alice@example.com' };
    const user = await auth.simple.createUser('Alice', 'Passw0rd!', { metadata });
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
    await auth.simple.init();

    await auth.simple.createUser('Bob', 'AnotherPass1');
    await expect(auth.simple.createUser('bob', 'AnotherPass1')).rejects.toBeInstanceOf(
      UserExistsError
    );
  });

  it('canonicalizes usernames during authentication', async () => {
    const auth = createAuth();
    await auth.simple.init();

    await auth.simple.createUser('Charlie', 'S3cureP@ss');

    const user = await auth.simple.authenticate('CHARLIE', 'S3cureP@ss');
    expect(user.username).toBe('charlie');
  });

  it('rejects invalid credentials', async () => {
    const auth = createAuth();
    await auth.simple.init();

    await auth.simple.createUser('Dana', 'StrongPass1');

    await expect(auth.simple.authenticate('dana', 'wrong-pass')).rejects.toBeInstanceOf(
      InvalidCredentialsError
    );
    await expect(auth.simple.authenticate('unknown', 'anything')).rejects.toBeInstanceOf(
      InvalidCredentialsError
    );
  });

  it('validates username input', async () => {
    const auth = createAuth();
    await auth.simple.init();

    await expect(auth.simple.createUser('??bad??', 'Pass123!')).rejects.toBeInstanceOf(
      InvalidUsernameError
    );
  });

  it('validates roles', async () => {
    const auth = createAuth();
    await auth.simple.init();

    await expect(
      auth.simple.createUser('eve', 'Pass123!', { role: 'superuser' as unknown as 'admin' })
    ).rejects.toBeInstanceOf(InvalidUserRoleError);
  });

  it('returns null for missing users', async () => {
    const auth = createAuth();
    await auth.simple.init();

    const user = await auth.simple.getUser('missing');
    expect(user).toBeNull();
  });

  it('returns all users', async () => {
    const auth = createAuth();
    await auth.simple.init();

    // Create multiple users with different metadata
    await auth.simple.createUser('alice', 'Pass123!', {
      metadata: { email: 'alice@example.com' }
    });
    await auth.simple.createUser('bob', 'Pass456!', {
      metadata: { email: 'bob@example.com' }
    });
    await auth.simple.createUser('charlie', 'Pass789!', {
      role: 'admin',
      metadata: { email: 'charlie@example.com' }
    });

    const users = await auth.simple.getAllUsers();

    // Should include the bootstrap admin plus three created users
    expect(users).toHaveLength(4);

    // Verify admin is present
    const admin = users.find(u => u.username === 'admin');
    expect(admin).toBeDefined();
    expect(admin?.role).toBe('admin');

    // Verify created users
    const alice = users.find(u => u.username === 'alice');
    expect(alice).toBeDefined();
    expect(alice?.role).toBe('user');
    expect(alice?.metadata).toEqual({ email: 'alice@example.com' });
    expect(alice?.type).toBe('simple');

    const bob = users.find(u => u.username === 'bob');
    expect(bob).toBeDefined();
    expect(bob?.role).toBe('user');
    expect(bob?.metadata).toEqual({ email: 'bob@example.com' });

    const charlie = users.find(u => u.username === 'charlie');
    expect(charlie).toBeDefined();
    expect(charlie?.role).toBe('admin');
    expect(charlie?.metadata).toEqual({ email: 'charlie@example.com' });

    // Ensure no passwords are leaked
    users.forEach(user => {
      expect(user).not.toHaveProperty('password');
    });
  });

  it('returns only bootstrap admin when no other users exist', async () => {
    const emptyAuth = new CStoreAuth({
      client: new MemoryCStore(),
      now: () => new Date('2024-01-01T00:00:00Z'),
      hkey: 'auth:empty',
      secret: 'test-secret'
    });

    await emptyAuth.simple.init();

    const users = await emptyAuth.simple.getAllUsers();
    
    // Should only have the bootstrap admin
    expect(users).toHaveLength(1);
    expect(users[0].username).toBe('admin');
    expect(users[0].role).toBe('admin');
  });

  it('filters out malformed user records when getting all users', async () => {
    const auth = createAuth();
    await auth.simple.init();

    // Create valid users
    await auth.simple.createUser('alice', 'Pass123!');
    await auth.simple.createUser('bob', 'Pass456!');

    // Inject a malformed record directly into CStore
    await cstore.hset(BASE_ENV.hkey, 'corrupted', 'not-valid-json');
    await cstore.hset(BASE_ENV.hkey, 'invalid-type', JSON.stringify({ type: 'oauth' }));

    const users = await auth.simple.getAllUsers();

    // Should only return valid users (admin, alice, bob)
    expect(users).toHaveLength(3);
    expect(users.map(u => u.username).sort()).toEqual(['admin', 'alice', 'bob']);
  });

  it('preserves metadata types when getting all users', async () => {
    interface CustomMeta {
      email: string;
      verified: boolean;
      age?: number;
    }

    const auth = createAuth();
    await auth.simple.init();

    await auth.simple.createUser<CustomMeta>('alice', 'Pass123!', {
      metadata: { email: 'alice@example.com', verified: true, age: 30 }
    });

    const users = await auth.simple.getAllUsers<CustomMeta>();
    const alice = users.find(u => u.username === 'alice');

    expect(alice?.metadata.email).toBe('alice@example.com');
    expect(alice?.metadata.verified).toBe(true);
    expect(alice?.metadata.age).toBe(30);
  });

  describe('updateUser', () => {
    it('updates user metadata', async () => {
      let time = 0;
      const auth = new CStoreAuth({
        client: cstore,
        now: () => new Date(2024, 0, 1, 0, 0, time++)
      });
      await auth.simple.init();

      const created = await auth.simple.createUser('alice', 'Pass123!', {
        metadata: { email: 'alice@example.com' }
      });

      const updated = await auth.simple.updateUser('alice', {
        metadata: { email: 'newemail@example.com', verified: true }
      });

      expect(updated.username).toBe('alice');
      expect(updated.metadata).toEqual({ email: 'newemail@example.com', verified: true });
      expect(updated.updatedAt).not.toBe(created.updatedAt);
      expect(updated.createdAt).toBe(created.createdAt);
    });

    it('updates user role', async () => {
      const auth = createAuth();
      await auth.simple.init();

      await auth.simple.createUser('alice', 'Pass123!', { role: 'user' });

      const updated = await auth.simple.updateUser('alice', { role: 'admin' });

      expect(updated.role).toBe('admin');
    });

    it('updates both metadata and role', async () => {
      const auth = createAuth();
      await auth.simple.init();

      await auth.simple.createUser('alice', 'Pass123!', {
        metadata: { email: 'old@example.com' },
        role: 'user'
      });

      const updated = await auth.simple.updateUser('alice', {
        metadata: { email: 'new@example.com', department: 'Engineering' },
        role: 'admin'
      });

      expect(updated.role).toBe('admin');
      expect(updated.metadata).toEqual({ email: 'new@example.com', department: 'Engineering' });
    });

    it('preserves fields that are not updated', async () => {
      const auth = createAuth();
      await auth.simple.init();

      const created = await auth.simple.createUser('alice', 'Pass123!', {
        metadata: { email: 'alice@example.com', age: 30 },
        role: 'user'
      });

      // Update only metadata, role should remain unchanged
      const updated = await auth.simple.updateUser('alice', {
        metadata: { email: 'updated@example.com' }
      });

      expect(updated.role).toBe('user'); // Still 'user'
      expect(updated.metadata).toEqual({ email: 'updated@example.com' });
      expect(updated.createdAt).toBe(created.createdAt);
    });

    it('throws UserNotFoundError for non-existent users', async () => {
      const auth = createAuth();
      await auth.simple.init();

      await expect(
        auth.simple.updateUser('nonexistent', { metadata: { email: 'test@example.com' } })
      ).rejects.toBeInstanceOf(UserNotFoundError);
    });

    it('validates role on update', async () => {
      const auth = createAuth();
      await auth.simple.init();

      await auth.simple.createUser('alice', 'Pass123!');

      await expect(
        auth.simple.updateUser('alice', { role: 'superadmin' as 'admin' })
      ).rejects.toBeInstanceOf(InvalidUserRoleError);
    });

    it('handles username case-insensitivity', async () => {
      const auth = createAuth();
      await auth.simple.init();

      await auth.simple.createUser('Alice', 'Pass123!', {
        metadata: { email: 'alice@example.com' }
      });

      const updated = await auth.simple.updateUser('ALICE', {
        metadata: { email: 'updated@example.com' }
      });

      expect(updated.username).toBe('alice');
      expect(updated.metadata).toEqual({ email: 'updated@example.com' });
    });
  });

  describe('changePassword', () => {
    it('changes password with correct current password', async () => {
      const auth = createAuth();
      await auth.simple.init();

      await auth.simple.createUser('alice', 'OldPass123!');

      await auth.simple.changePassword('alice', 'OldPass123!', 'NewPass456!');

      // Verify old password no longer works
      await expect(
        auth.simple.authenticate('alice', 'OldPass123!')
      ).rejects.toBeInstanceOf(InvalidCredentialsError);

      // Verify new password works
      const authenticated = await auth.simple.authenticate('alice', 'NewPass456!');
      expect(authenticated.username).toBe('alice');
    });

    it('rejects password change with incorrect current password', async () => {
      const auth = createAuth();
      await auth.simple.init();

      await auth.simple.createUser('alice', 'CorrectPass123!');

      await expect(
        auth.simple.changePassword('alice', 'WrongPass123!', 'NewPass456!')
      ).rejects.toBeInstanceOf(InvalidCredentialsError);

      // Verify original password still works
      const authenticated = await auth.simple.authenticate('alice', 'CorrectPass123!');
      expect(authenticated.username).toBe('alice');
    });

    it('rejects password change for non-existent user', async () => {
      const auth = createAuth();
      await auth.simple.init();

      await expect(
        auth.simple.changePassword('nonexistent', 'OldPass123!', 'NewPass456!')
      ).rejects.toBeInstanceOf(InvalidCredentialsError);
    });

    it('updates the updatedAt timestamp', async () => {
      let time = 0;
      const auth = new CStoreAuth({
        client: cstore,
        now: () => new Date(2024, 0, 1, 0, 0, time++)
      });
      await auth.simple.init();

      const created = await auth.simple.createUser('alice', 'Pass123!');

      await auth.simple.changePassword('alice', 'Pass123!', 'NewPass456!');

      const user = await auth.simple.getUser('alice');
      expect(user?.updatedAt).not.toBe(created.updatedAt);
      expect(user?.createdAt).toBe(created.createdAt);
    });

    it('handles username case-insensitivity', async () => {
      const auth = createAuth();
      await auth.simple.init();

      await auth.simple.createUser('Alice', 'OldPass123!');

      await auth.simple.changePassword('ALICE', 'OldPass123!', 'NewPass456!');

      const authenticated = await auth.simple.authenticate('alice', 'NewPass456!');
      expect(authenticated.username).toBe('alice');
    });

    it('does not affect user metadata or role', async () => {
      const auth = createAuth();
      await auth.simple.init();

      const created = await auth.simple.createUser('alice', 'Pass123!', {
        metadata: { email: 'alice@example.com' },
        role: 'admin'
      });

      await auth.simple.changePassword('alice', 'Pass123!', 'NewPass456!');

      const user = await auth.simple.getUser('alice');
      expect(user?.metadata).toEqual(created.metadata);
      expect(user?.role).toBe(created.role);
    });
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
