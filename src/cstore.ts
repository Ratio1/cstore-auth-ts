import { Ratio1EdgeNodeClient, type Ratio1EdgeNodeClientOptions } from 'edge-node-client';

type CStoreService = Ratio1EdgeNodeClient['cstore'];

/**
 * Minimal surface we rely on for interacting with CStore hashes. The official client returns
 * strings for existing fields and throws for transport failures.
 */
export interface CStoreLikeClient {
  hget(hkey: string, key: string): Promise<string | null>;
  hset(hkey: string, key: string, value: string): Promise<void>;
  hgetAll(hkey: string): Promise<Record<string, string>>;
}

export function createDefaultCStoreClient(
  options?: Ratio1EdgeNodeClientOptions
): CStoreLikeClient {
  const client = new Ratio1EdgeNodeClient(options);
  return new CStoreClientAdapter(client.cstore);
}

class CStoreClientAdapter implements CStoreLikeClient {
  constructor(private readonly service: CStoreService) {}

  async hget(hkey: string, key: string): Promise<string | null> {
    try {
      // edge-node-client exports hget({ hkey, key })
      const value = await this.service.hget({ hkey, key });
      if (value === undefined || value === null) {
        return null;
      }
      if (typeof value !== 'string') {
        return String(value);
      }
      return value;
    } catch (error) {
      if (isNotFoundError(error)) {
        return null;
      }
      throw error;
    }
  }

  async hset(hkey: string, key: string, value: string): Promise<void> {
    // edge-node-client exports hset({ hkey, key, value }) and resolves to boolean
    await this.service.hset({ hkey, key, value });
  }

  async hgetAll(hkey: string): Promise<Record<string, string>> {
    // edge-node-client exports hgetall({ hkey }) returning either an object map or array pairs
    const raw = await this.service.hgetall({ hkey });
    if (!raw) {
      return {};
    }

    if (isKeyValueArray(raw)) {
      const result: Record<string, string> = {};
      for (let index = 0; index < raw.length; index += 2) {
        const field = raw[index];
        const value = raw[index + 1];
        if (typeof field === 'string' && typeof value === 'string') {
          result[field] = value;
        }
      }
      return result;
    }

    return raw;
  }
}

function isKeyValueArray(value: unknown): value is string[] {
  return Array.isArray(value);
}

function isNotFoundError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }

  const maybeResponseCode = (error as { status?: number }).status;
  return maybeResponseCode === 404;
}

export type { Ratio1EdgeNodeClientOptions };
