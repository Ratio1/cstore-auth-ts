import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { CStoreAuth } from '../../src/auth';
import {
  InvalidCredentialsError,
  UserExistsError,
  InvalidUsernameError
} from '../../src/util/errors';
import type { CStoreLikeClient } from '../../src/cstore';

/**
 * Integration test suite for CStoreAuth with realistic cleanup patterns.
 * 
 * These tests exercise the full authentication flow including:
 * - User creation and retrieval
 * - Authentication workflows
 * - Batch user operations (getAllUsers)
 * - Error handling and edge cases
 * 
 * Best practices implemented:
 * - Cleanup before AND after each test
 * - Setting values to null before deletion
 * - Isolated test hash keys per test
 * - Proper resource cleanup in afterAll
 */

/**
 * Mock CStore client for integration testing that simulates real behavior
 * including proper cleanup patterns.
 */
class IntegrationCStore implements CStoreLikeClient {
  private readonly store = new Map<string, Map<string, string>>();
  private readonly keysToCleanup = new Set<string>();

  async hget(hkey: string, key: string): Promise<string | null> {
    const hash = this.store.get(hkey);
    if (!hash) {
      return null;
    }
    return hash.get(key) ?? null;
  }

  async hset(hkey: string, key: string, value: string): Promise<void> {
    const hash = this.ensureHash(hkey);
    hash.set(key, value);
    this.keysToCleanup.add(hkey);
  }

  async hgetAll(hkey: string): Promise<Record<string, string>> {
    const hash = this.store.get(hkey);
    if (!hash) {
      return {};
    }
    return Object.fromEntries(hash.entries());
  }

  /**
   * Best practice cleanup: Set all values to null before deletion.
   * This ensures proper cleanup in distributed systems and catches any
   * lingering references.
   */
  async cleanup(): Promise<void> {
    for (const hkey of this.keysToCleanup) {
      const hash = this.store.get(hkey);
      if (hash) {
        // First pass: set all values to null
        for (const key of hash.keys()) {
          await this.hset(hkey, key, '');
        }
        // Second pass: clear the hash
        hash.clear();
      }
      this.store.delete(hkey);
    }
    this.keysToCleanup.clear();
  }

  /**
   * Cleanup a specific hash key following best practices
   */
  async cleanupHash(hkey: string): Promise<void> {
    const hash = this.store.get(hkey);
    if (hash) {
      // Set all values to empty/null before deletion
      for (const key of hash.keys()) {
        hash.set(key, '');
      }
      // Then clear
      hash.clear();
      this.store.delete(hkey);
    }
    this.keysToCleanup.delete(hkey);
  }

  private ensureHash(hkey: string): Map<string, string> {
    let hash = this.store.get(hkey);
    if (!hash) {
      hash = new Map();
      this.store.set(hkey, hash);
    }
    return hash;
  }
}

describe('CStoreAuth Integration Tests', () => {
  let cstore: IntegrationCStore;
  let testCounter = 0;

  const BASE_ENV = {
    secret: 'integration-test-secret-pepper-key',
    bootstrap: 'bootstrap-admin-password-123'
  };

  /**
   * Generate unique hash key for each test to ensure isolation
   */
  function getTestHkey(): string {
    testCounter++;
    return `auth:integration:test:${testCounter}:${Date.now()}`;
  }

  beforeAll(() => {
    // Set base environment variables
    process.env.EE_CSTORE_AUTH_SECRET = BASE_ENV.secret;
    process.env.EE_CSTORE_BOOTSTRAP_ADMIN_PASS = BASE_ENV.bootstrap;
  });

  beforeEach(() => {
    cstore = new IntegrationCStore();
  });

  afterEach(async () => {
    // Cleanup: Set values to null then delete
    await cstore.cleanup();
  });

  afterAll(() => {
    // Clean up environment
    delete process.env.EE_CSTORE_AUTH_SECRET;
    delete process.env.EE_CSTORE_BOOTSTRAP_ADMIN_PASS;
    delete process.env.EE_CSTORE_AUTH_HKEY;
  });

  describe('User Lifecycle', () => {
    it('should complete full user lifecycle: create, authenticate, retrieve, list', async () => {
      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      // Initialize
      await auth.simple.init();

      // Create user
      const created = await auth.simple.createUser('alice', 'SecurePass123!', {
        metadata: { email: 'alice@example.com', role: 'developer' }
      });

      expect(created.username).toBe('alice');
      expect(created.role).toBe('user');
      expect(created.metadata).toEqual({ email: 'alice@example.com', role: 'developer' });

      // Authenticate
      const authenticated = await auth.simple.authenticate('alice', 'SecurePass123!');
      expect(authenticated.username).toBe('alice');
      expect(authenticated.metadata).toEqual(created.metadata);

      // Retrieve single user
      const retrieved = await auth.simple.getUser('alice');
      expect(retrieved).not.toBeNull();
      expect(retrieved?.username).toBe('alice');

      // List all users
      const allUsers = await auth.simple.getAllUsers();
      expect(allUsers.length).toBeGreaterThanOrEqual(2); // admin + alice
      const alice = allUsers.find(u => u.username === 'alice');
      expect(alice).toBeDefined();
      expect(alice?.metadata).toEqual({ email: 'alice@example.com', role: 'developer' });

      // Cleanup this test's data
      await cstore.cleanupHash(hkey);
    });

    it('should handle multiple users correctly', async () => {
      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      await auth.simple.init();

      // Create multiple users
      const users = [
        { username: 'alice', password: 'Pass1!', metadata: { email: 'alice@test.com' } },
        { username: 'bob', password: 'Pass2!', metadata: { email: 'bob@test.com' } },
        { username: 'charlie', password: 'Pass3!', metadata: { email: 'charlie@test.com' } },
        { username: 'diana', password: 'Pass4!', metadata: { email: 'diana@test.com' } }
      ];

      for (const user of users) {
        await auth.simple.createUser(user.username, user.password, {
          metadata: user.metadata
        });
      }

      // Retrieve all users
      const allUsers = await auth.simple.getAllUsers();
      
      // Should have admin + 4 created users
      expect(allUsers).toHaveLength(5);

      // Verify each user
      for (const user of users) {
        const found = allUsers.find(u => u.username === user.username);
        expect(found).toBeDefined();
        expect(found?.metadata).toEqual(user.metadata);
        expect(found?.role).toBe('user');
        expect(found?.type).toBe('simple');
      }

      // Verify admin is present
      const admin = allUsers.find(u => u.username === 'admin');
      expect(admin).toBeDefined();
      expect(admin?.role).toBe('admin');

      // Cleanup
      await cstore.cleanupHash(hkey);
    });
  });

  describe('getAllUsers - Integration Scenarios', () => {
    it('should return all users with correct metadata types', async () => {
      interface UserMeta {
        email: string;
        department: string;
        active: boolean;
      }

      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      await auth.simple.init();

      // Create users with typed metadata
      await auth.simple.createUser<UserMeta>('employee1', 'Pass123!', {
        metadata: { email: 'emp1@company.com', department: 'Engineering', active: true }
      });

      await auth.simple.createUser<UserMeta>('employee2', 'Pass456!', {
        metadata: { email: 'emp2@company.com', department: 'Marketing', active: false }
      });

      const users = await auth.simple.getAllUsers<UserMeta>();
      
      const emp1 = users.find(u => u.username === 'employee1');
      expect(emp1?.metadata.department).toBe('Engineering');
      expect(emp1?.metadata.active).toBe(true);

      const emp2 = users.find(u => u.username === 'employee2');
      expect(emp2?.metadata.department).toBe('Marketing');
      expect(emp2?.metadata.active).toBe(false);

      // Cleanup
      await cstore.cleanupHash(hkey);
    });

    it('should handle empty user list (only bootstrap admin)', async () => {
      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      await auth.simple.init();

      const users = await auth.simple.getAllUsers();
      
      expect(users).toHaveLength(1);
      expect(users[0].username).toBe('admin');
      expect(users[0].role).toBe('admin');

      // Cleanup
      await cstore.cleanupHash(hkey);
    });

    it('should not expose password hashes in user list', async () => {
      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      await auth.simple.init();

      await auth.simple.createUser('alice', 'Secret123!');
      await auth.simple.createUser('bob', 'Secret456!');

      const users = await auth.simple.getAllUsers();

      // Verify no password field in any user
      users.forEach(user => {
        expect(user).not.toHaveProperty('password');
        const userObj = user as unknown as Record<string, unknown>;
        expect(userObj.password).toBeUndefined();
      });

      // Cleanup
      await cstore.cleanupHash(hkey);
    });

    it('should handle users with admin role correctly', async () => {
      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      await auth.simple.init();

      // Create regular users and admin users
      await auth.simple.createUser('user1', 'Pass1!', { role: 'user' });
      await auth.simple.createUser('admin1', 'Pass2!', { role: 'admin' });
      await auth.simple.createUser('user2', 'Pass3!', { role: 'user' });

      const allUsers = await auth.simple.getAllUsers();

      const admins = allUsers.filter(u => u.role === 'admin');
      const regularUsers = allUsers.filter(u => u.role === 'user');

      // Should have 2 admins (bootstrap + admin1)
      expect(admins).toHaveLength(2);
      expect(admins.map(a => a.username).sort()).toEqual(['admin', 'admin1']);

      // Should have 2 regular users
      expect(regularUsers).toHaveLength(2);
      expect(regularUsers.map(u => u.username).sort()).toEqual(['user1', 'user2']);

      // Cleanup
      await cstore.cleanupHash(hkey);
    });
  });

  describe('Error Handling', () => {
    it('should reject duplicate usernames', async () => {
      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      await auth.simple.init();

      await auth.simple.createUser('alice', 'Pass123!');

      await expect(
        auth.simple.createUser('alice', 'DifferentPass456!')
      ).rejects.toThrow(UserExistsError);

      // Cleanup
      await cstore.cleanupHash(hkey);
    });

    it('should reject invalid credentials', async () => {
      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      await auth.simple.init();

      await auth.simple.createUser('alice', 'CorrectPass123!');

      await expect(
        auth.simple.authenticate('alice', 'WrongPass123!')
      ).rejects.toThrow(InvalidCredentialsError);

      await expect(
        auth.simple.authenticate('nonexistent', 'AnyPass123!')
      ).rejects.toThrow(InvalidCredentialsError);

      // Cleanup
      await cstore.cleanupHash(hkey);
    });

    it('should reject invalid usernames', async () => {
      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      await auth.simple.init();

      // Test various invalid username formats
      const invalidUsernames = [
        'ab', // too short
        'a'.repeat(65), // too long
        'user@invalid', // invalid character
        'user name', // space
        'user#123', // special char
        ''
      ];

      for (const username of invalidUsernames) {
        await expect(
          auth.simple.createUser(username, 'ValidPass123!')
        ).rejects.toThrow(InvalidUsernameError);
      }

      // Cleanup
      await cstore.cleanupHash(hkey);
    });
  });

  describe('Data Consistency', () => {
    it('should maintain consistent timestamps across operations', async () => {
      const hkey = getTestHkey();
      const now = new Date('2024-06-15T12:00:00Z');
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => now
      });

      await auth.simple.init();

      const created = await auth.simple.createUser('alice', 'Pass123!');
      
      expect(created.createdAt).toBe('2024-06-15T12:00:00.000Z');
      expect(created.updatedAt).toBe('2024-06-15T12:00:00.000Z');

      // Verify through getAllUsers
      const allUsers = await auth.simple.getAllUsers();
      const alice = allUsers.find(u => u.username === 'alice');
      
      expect(alice?.createdAt).toBe(created.createdAt);
      expect(alice?.updatedAt).toBe(created.updatedAt);

      // Cleanup
      await cstore.cleanupHash(hkey);
    });

    it('should preserve metadata through multiple retrievals', async () => {
      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      await auth.simple.init();

      const originalMetadata = {
        email: 'alice@example.com',
        preferences: {
          theme: 'dark',
          notifications: true
        },
        tags: ['vip', 'developer']
      };

      await auth.simple.createUser('alice', 'Pass123!', {
        metadata: originalMetadata
      });

      // Retrieve via getUser
      const retrieved = await auth.simple.getUser('alice');
      expect(retrieved?.metadata).toEqual(originalMetadata);

      // Retrieve via getAllUsers
      const allUsers = await auth.simple.getAllUsers();
      const alice = allUsers.find(u => u.username === 'alice');
      expect(alice?.metadata).toEqual(originalMetadata);

      // Authenticate and verify
      const authenticated = await auth.simple.authenticate('alice', 'Pass123!');
      expect(authenticated.metadata).toEqual(originalMetadata);

      // Cleanup
      await cstore.cleanupHash(hkey);
    });
  });

  describe('Cleanup Verification', () => {
    it('should properly cleanup test data', async () => {
      const hkey = getTestHkey();
      const auth = new CStoreAuth({
        client: cstore,
        hkey,
        now: () => new Date('2024-01-01T00:00:00Z')
      });

      await auth.simple.init();

      // Create test data
      await auth.simple.createUser('test1', 'Pass1!');
      await auth.simple.createUser('test2', 'Pass2!');
      await auth.simple.createUser('test3', 'Pass3!');

      // Verify data exists
      const users = await auth.simple.getAllUsers();
      expect(users.length).toBeGreaterThanOrEqual(4); // admin + 3 users

      // Cleanup
      await cstore.cleanupHash(hkey);

      // Verify cleanup worked
      const allData = await cstore.hgetAll(hkey);
      expect(Object.keys(allData)).toHaveLength(0);
    });
  });
});

