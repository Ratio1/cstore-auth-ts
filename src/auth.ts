import type { CStoreLikeClient } from './cstore';
import { createDefaultCStoreClient } from './cstore';
import { createPasswordHasher, type PasswordHasher } from './hasher';
import type { CStoreAuthOptions, SimpleAuthApi } from './types';
import { resolveAuthEnv } from './util/env';
import { AuthInitError } from './util/errors';
import {
  bootstrapSimpleAdminIfNeeded,
  createSimpleAuthApi,
  type SimpleAuthBootstrapContext,
  type SimpleAuthContext
} from './simple-auth';

interface Config {
  hkey: string;
  secret: string;
}

export class CStoreAuth {
  public readonly simple: SimpleAuthApi;
  private readonly client: CStoreLikeClient;
  private readonly hasher: PasswordHasher;
  private readonly getNow: () => Date;
  private readonly logger?: Pick<Console, 'debug' | 'info' | 'warn' | 'error'>;
  private readonly overrides: Pick<CStoreAuthOptions, 'hkey' | 'secret'>;

  private config: Config | null = null;
  private initPromise: Promise<void> | null = null;

  constructor(options: CStoreAuthOptions = {}) {
    this.client = options.client ?? createDefaultCStoreClient();
    this.hasher = options.hasher ?? createPasswordHasher({ logger: options.logger });
    this.getNow = options.now ?? (() => new Date());
    this.logger = options.logger;
    this.overrides = { hkey: options.hkey, secret: options.secret };
    this.simple = createSimpleAuthApi(this.createSimpleContext());
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.initialize().catch((error: unknown) => {
        this.initPromise = null;
        throw error;
      });
    }

    await this.initPromise;
  }

  private async initialize(): Promise<void> {
    const { hkey, secret } = resolveAuthEnv(this.overrides);
    this.config = { hkey, secret };

    await bootstrapSimpleAdminIfNeeded(this.createSimpleBootstrapContext());
  }

  private requireConfig(): Config {
    if (!this.config) {
      throw new AuthInitError('CStoreAuth is not initialized. Call simple.init() before using it.');
    }
    return this.config;
  }

  private createSimpleContext(): SimpleAuthContext {
    return {
      ensureInitialized: () => this.ensureInitialized(),
      requireConfig: () => this.requireConfig(),
      client: this.client,
      hasher: this.hasher,
      getNow: this.getNow,
      logger: this.logger
    };
  }

  private createSimpleBootstrapContext(): SimpleAuthBootstrapContext {
    return {
      requireConfig: () => this.requireConfig(),
      client: this.client,
      hasher: this.hasher,
      getNow: this.getNow,
      logger: this.logger
    };
  }
}
