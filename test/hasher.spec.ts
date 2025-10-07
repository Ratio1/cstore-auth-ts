import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('PasswordHasher', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('hashes and verifies using argon2id when available', async () => {
    const hashRaw = vi
      .fn<(password: string) => Promise<Buffer>>()
      .mockImplementation(async (password) => {
        if (password === 'NotTheSame') {
          return Buffer.from('different-value');
        }
        return Buffer.from('argon-derived');
      });

    vi.doMock('@node-rs/argon2', () => ({
      hashRaw,
      Algorithm: { Argon2id: 2 }
    }));

    const { createPasswordHasher } = await import('../src/hasher');
    const hasher = createPasswordHasher();

    const record = await hasher.hashPassword('SuperSecret', 'pepper');
    expect(record.algo).toBe('argon2id');
    expect(hashRaw).toHaveBeenCalled();

    const verified = await hasher.verifyPassword('SuperSecret', record, 'pepper');
    expect(verified).toBe(true);

    const verifiedWrong = await hasher.verifyPassword('NotTheSame', record, 'pepper');
    expect(verifiedWrong).toBe(false);

    vi.unmock('@node-rs/argon2');
  });

  it('falls back to scrypt when argon2id is unavailable', async () => {
    vi.doMock('@node-rs/argon2', () => {
      throw new Error('native module not available');
    });

    const warn = vi.fn();
    const { createPasswordHasher } = await import('../src/hasher');
    const hasher = createPasswordHasher({ logger: { warn } });

    const record = await hasher.hashPassword('AnotherSecret', 'pepper');
    expect(record.algo).toBe('scrypt');
    expect(warn).toHaveBeenCalledOnce();

    const verified = await hasher.verifyPassword('AnotherSecret', record, 'pepper');
    expect(verified).toBe(true);

    vi.unmock('@node-rs/argon2');
  });
});
