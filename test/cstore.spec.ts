import { describe, expect, it, vi } from 'vitest';

const sdkOptions = vi.hoisted(() => ({
  calls: [] as unknown[]
}));

vi.mock('@ratio1/ratio1-sdk-ts', () => ({
  Ratio1Sdk: vi.fn().mockImplementation((options: unknown) => {
    sdkOptions.calls.push(options);

    return {
      cstore: {
        hget: vi.fn(),
        hset: vi.fn(),
        hgetall: vi.fn()
      }
    };
  })
}));

import { createDefaultCStoreClient } from '../src/cstore';

describe('createDefaultCStoreClient', () => {
  it('forces no-store cache on SDK HTTP requests', async () => {
    const response = new Response(JSON.stringify({ result: null }));
    const baseFetch = vi.fn(async () => response);

    createDefaultCStoreClient({
      httpAdapter: {
        fetch: baseFetch
      }
    });

    const options = sdkOptions.calls.at(-1) as {
      httpAdapter: {
        fetch(url: string, options?: RequestInit): Promise<Response>;
      };
    };

    await options.httpAdapter.fetch('http://localhost/hgetall?hkey=auth', {
      method: 'GET',
      cache: 'force-cache'
    });

    expect(baseFetch).toHaveBeenCalledWith('http://localhost/hgetall?hkey=auth', {
      method: 'GET',
      cache: 'no-store'
    });
  });
});
