import type { CStoreLikeClient } from './cstore';
import { createDefaultCStoreClient } from './cstore';
import { createPasswordHasher, type PasswordHasher } from './hasher';
import type {
  CStoreAuthOptions,
  CreateUserOptions,
  PublicUser,
  SimpleAuthApi,
  UserRecord
} from './types';
import { resolveAuthEnv, readBootstrapAdminPassword, ENV_VARS } from './util/env';
import { canonicalizeUsername } from './util/username';
import {
  AuthInitError,
  EnvVarMissingError,
  InvalidCredentialsError,
  InvalidUserRoleError,
  PasswordHasherUnavailableError,
  UserExistsError,
  UserSerializationError
} from './util/errors';

interface Config {
  hkey: string;
  secret: string;
}

const ADMIN_USERNAME = 'admin';

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
    this.simple = {
      init: () => this.initSimple(),
      createUser: <TMeta = Record<string, unknown>>(
        username: string,
        password: string,
        createOptions?: CreateUserOptions<TMeta>
      ) => this.createSimpleUser<TMeta>(username, password, createOptions),
      authenticate: <TMeta = Record<string, unknown>>(username: string, password: string) =>
        this.authenticateSimple<TMeta>(username, password),
      getUser: <TMeta = Record<string, unknown>>(username: string) =>
        this.getSimpleUser<TMeta>(username)
    };
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

  async initSimple(): Promise<void> {
    await this.ensureInitialized();
  }

  /** @deprecated Use simple.init() */
  async initAuth(): Promise<void> {
    await this.initSimple();
  }

  async createSimpleUser<TMeta = Record<string, unknown>>(
    username: string,
    password: string,
    options: CreateUserOptions<TMeta> = {}
  ): Promise<PublicUser<TMeta>> {
    await this.ensureInitialized();
    const config = this.requireConfig();
    const canonical = canonicalizeUsername(username);

    const existing = await this.client.hget(config.hkey, canonical.canonical);
    if (existing) {
      throw new UserExistsError(canonical.canonical);
    }

    const metadata = cloneJson(options.metadata ?? ({} as TMeta));
    const role = options.role ?? 'user';
    if (role !== 'admin' && role !== 'user') {
      throw new InvalidUserRoleError(String(role));
    }

    const record = await this.buildUserRecord(password, role, metadata, config.secret);
    await this.writeUser(canonical.canonical, record);

    return toPublicUser(canonical.canonical, record);
  }

  /** @deprecated Use simple.createUser() */
  async createUser<TMeta = Record<string, unknown>>(
    username: string,
    password: string,
    options: CreateUserOptions<TMeta> = {}
  ): Promise<PublicUser<TMeta>> {
    return this.createSimpleUser<TMeta>(username, password, options);
  }

  async authenticateSimple<TMeta = Record<string, unknown>>(
    username: string,
    password: string
  ): Promise<PublicUser<TMeta>> {
    await this.ensureInitialized();
    const config = this.requireConfig();
    const canonical = canonicalizeUsername(username);

    const raw = await this.client.hget(config.hkey, canonical.canonical);
    if (!raw) {
      throw new InvalidCredentialsError();
    }

    let record: UserRecord<TMeta>;
    try {
      record = parseUserRecord<TMeta>(canonical.canonical, raw);
    } catch (error: unknown) {
      if (error instanceof UserSerializationError) {
        this.logger?.error?.(error.message);
        throw new InvalidCredentialsError();
      }
      throw error;
    }

    if (!record.password) {
      throw new InvalidCredentialsError();
    }

    let verified: boolean;
    try {
      verified = await this.hasher.verifyPassword(password, record.password, config.secret);
    } catch (error: unknown) {
      if (error instanceof PasswordHasherUnavailableError) {
        this.logger?.error?.(error.message);
        throw new InvalidCredentialsError();
      }
      throw error;
    }

    if (!verified) {
      throw new InvalidCredentialsError();
    }

    return toPublicUser<TMeta>(canonical.canonical, record);
  }

  /** @deprecated Use simple.authenticate() */
  async authenticate<TMeta = Record<string, unknown>>(
    username: string,
    password: string
  ): Promise<PublicUser<TMeta>> {
    return this.authenticateSimple<TMeta>(username, password);
  }

  async getSimpleUser<TMeta = Record<string, unknown>>(
    username: string
  ): Promise<PublicUser<TMeta> | null> {
    await this.ensureInitialized();
    const config = this.requireConfig();
    const canonical = canonicalizeUsername(username);
    const raw = await this.client.hget(config.hkey, canonical.canonical);

    if (!raw) {
      return null;
    }

    const record = parseUserRecord<TMeta>(canonical.canonical, raw);
    return toPublicUser<TMeta>(canonical.canonical, record);
  }

  /** @deprecated Use simple.getUser() */
  async getUser<TMeta = Record<string, unknown>>(
    username: string
  ): Promise<PublicUser<TMeta> | null> {
    return this.getSimpleUser<TMeta>(username);
  }

  private async initialize(): Promise<void> {
    const { hkey, secret } = resolveAuthEnv(this.overrides);
    this.config = { hkey, secret };

    await this.bootstrapAdminIfNeeded();
  }

  private requireConfig(): Config {
    if (!this.config) {
      throw new AuthInitError('CStoreAuth is not initialized. Call simple.init() before using it.');
    }
    return this.config;
  }

  private async bootstrapAdminIfNeeded(): Promise<void> {
    const config = this.requireConfig();
    const existing = await this.client.hget(config.hkey, ADMIN_USERNAME);
    if (existing) {
      return;
    }

    const bootstrapPassword = readBootstrapAdminPassword();
    if (!bootstrapPassword) {
      throw new EnvVarMissingError(ENV_VARS.BOOTSTRAP_ADMIN_PASS);
    }

    this.logger?.info?.('Bootstrapping default admin user.');
    const record = await this.buildUserRecord(bootstrapPassword, 'admin', {} as Record<string, never>, config.secret);
    await this.writeUser<Record<string, never>>(ADMIN_USERNAME, record);
  }

  private async buildUserRecord<TMeta>(
    password: string,
    role: 'admin' | 'user',
    metadata: TMeta,
    secret: string
  ): Promise<UserRecord<TMeta>> {
    const nowIso = this.getNow().toISOString();
    const passwordRecord = await this.hasher.hashPassword(password, secret);
    return {
      type: 'simple',
      password: passwordRecord,
      role,
      metadata,
      createdAt: nowIso,
      updatedAt: nowIso
    };
  }

  private async writeUser<TMeta>(username: string, record: UserRecord<TMeta>): Promise<void> {
    const config = this.requireConfig();
    const value = stringifyUserRecord(username, record);
    await this.client.hset(config.hkey, username, value);
  }
}

function stringifyUserRecord<TMeta>(username: string, record: UserRecord<TMeta>): string {
  try {
    return JSON.stringify(record);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'unknown serialization error';
    throw new UserSerializationError(username, message);
  }
}

function parseUserRecord<TMeta>(username: string, raw: string): UserRecord<TMeta> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new UserSerializationError(username, 'value is not valid JSON');
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new UserSerializationError(username, 'value must be an object');
  }

  const record = parsed as Partial<UserRecord<TMeta>>;

  if (record.type !== 'simple') {
    throw new UserSerializationError(username, `unsupported user type "${String(record.type)}"`);
  }

  if (record.role !== 'admin' && record.role !== 'user') {
    throw new UserSerializationError(username, 'role must be "admin" or "user"');
  }

  if (typeof record.createdAt !== 'string' || typeof record.updatedAt !== 'string') {
    throw new UserSerializationError(username, 'timestamps are missing or invalid');
  }

  if (typeof record.metadata === 'undefined' || record.metadata === null) {
    record.metadata = {} as TMeta;
  }

  if (typeof record.metadata !== 'object') {
    throw new UserSerializationError(username, 'metadata must be an object');
  }

  if (record.password !== null && record.password !== undefined) {
    validatePasswordRecord(username, record.password);
  }

  return record as UserRecord<TMeta>;
}

function validatePasswordRecord(username: string, password: unknown): void {
  if (!password || typeof password !== 'object') {
    throw new UserSerializationError(username, 'password must be an object when present');
  }

  const candidate = password as Record<string, unknown>;

  const requiredFields: Array<[string, string]> = [
    ['algo', 'string'],
    ['hash', 'string'],
    ['salt', 'string'],
    ['version', 'number'],
    ['params', 'object']
  ];

  for (const [field, type] of requiredFields) {
    const value = candidate[field];
    if (typeof value !== type || value === null) {
      throw new UserSerializationError(username, `password.${field} is missing or invalid`);
    }
  }
}

function toPublicUser<TMeta>(username: string, record: UserRecord<TMeta>): PublicUser<TMeta> {
  return {
    username,
    role: record.role,
    metadata: cloneJson(record.metadata),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    type: record.type
  };
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
