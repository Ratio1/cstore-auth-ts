import type { CStoreLikeClient } from '../../src/cstore';

export class MemoryCStore implements CStoreLikeClient {
  private readonly store = new Map<string, Map<string, string>>();

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
  }

  async hgetAll(hkey: string): Promise<Record<string, string>> {
    const hash = this.store.get(hkey);
    if (!hash) {
      return {};
    }

    return Object.fromEntries(hash.entries());
  }

  clear(): void {
    this.store.clear();
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
