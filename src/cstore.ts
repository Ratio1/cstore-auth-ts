import { EdgeSdk, type EdgeSdkOptions } from '@ratio1/edge-sdk-ts';

type CStoreService = EdgeSdk['cstore'];

/**
 * Minimal surface we rely on for interacting with CStore hashes. The official client returns
 * strings for existing fields and throws for transport failures.
 */
export interface CStoreLikeClient {
  hget(hkey: string, key: string): Promise<string | null>;
  hset(hkey: string, key: string, value: string): Promise<void>;
  hgetAll(hkey: string): Promise<Record<string, string>>;
}

export function createDefaultCStoreClient(options?: EdgeSdkOptions): CStoreLikeClient {
  const client = new EdgeSdk(options);
  return new CStoreClientAdapter(client.cstore);
}

class CStoreClientAdapter implements CStoreLikeClient {
  constructor(private readonly service: CStoreService) {}

  async hget(hkey: string, key: string): Promise<string | null> {
    try {
      // @ratio1/edge-sdk-ts exports hget({ hkey, key })
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
    // @ratio1/edge-sdk-ts exports hset({ hkey, key, value }) and resolves to boolean
    await this.service.hset({ hkey, key, value });
  }

  async hgetAll(hkey: string): Promise<Record<string, string>> {
    // @ratio1/edge-sdk-ts exports hgetall({ hkey }) returning an object map
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

    const result: Record<string, string> = {};
    for (const [field, value] of Object.entries(raw)) {
      if (typeof value === 'string') {
        result[field] = value;
        continue;
      }
      if (value !== undefined && value !== null) {
        result[field] = String(value);
      }
    }
    return result;
  }
}

function isKeyValueArray(value: unknown): value is string[] {
  return Array.isArray(value);
}

function isNotFoundError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }

  const maybeStatus = (error as { status?: number }).status;
  if (maybeStatus === 404) {
    return true;
  }

  const maybeResponseStatus = (error as { response?: { status?: number } }).response?.status;
  return maybeResponseStatus === 404;
}

export type { EdgeSdkOptions };
