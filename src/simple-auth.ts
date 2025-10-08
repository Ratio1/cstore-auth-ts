import type { CStoreLikeClient } from './cstore';
import type { PasswordHasher } from './hasher';
import type {
  CreateUserOptions,
  PublicUser,
  SimpleAuthApi,
  UserRecord
} from './types';
import { readBootstrapAdminPassword, ENV_VARS } from './util/env';
import { canonicalizeUsername } from './util/username';
import {
  EnvVarMissingError,
  InvalidCredentialsError,
  InvalidUserRoleError,
  PasswordHasherUnavailableError,
  UserExistsError,
  UserSerializationError
} from './util/errors';

export interface SimpleAuthBootstrapContext {
  requireConfig(): { hkey: string; secret: string };
  client: CStoreLikeClient;
  hasher: PasswordHasher;
  getNow: () => Date;
  logger?: Pick<Console, 'debug' | 'info' | 'warn' | 'error'>;
}

export interface SimpleAuthContext extends SimpleAuthBootstrapContext {
  ensureInitialized(): Promise<void>;
}

const ADMIN_USERNAME = 'admin';

export function createSimpleAuthApi(context: SimpleAuthContext): SimpleAuthApi {
  return {
    init: () => context.ensureInitialized(),
    createUser: <TMeta = Record<string, unknown>>(
      username: string,
      password: string,
      options?: CreateUserOptions<TMeta>
    ) => createSimpleUser<TMeta>(context, username, password, options),
    authenticate: <TMeta = Record<string, unknown>>(username: string, password: string) =>
      authenticateSimpleUser<TMeta>(context, username, password),
    getUser: <TMeta = Record<string, unknown>>(username: string) =>
      getSimpleUser<TMeta>(context, username)
  };
}

export async function bootstrapSimpleAdminIfNeeded(
  context: SimpleAuthBootstrapContext
): Promise<void> {
  const config = context.requireConfig();
  const existing = await context.client.hget(config.hkey, ADMIN_USERNAME);
  if (existing) {
    return;
  }

  const bootstrapPassword = readBootstrapAdminPassword();
  if (!bootstrapPassword) {
    throw new EnvVarMissingError(ENV_VARS.BOOTSTRAP_ADMIN_PASS);
  }

  context.logger?.info?.('Bootstrapping default admin user.');
  const record = await buildUserRecord<Record<string, never>>(
    context,
    bootstrapPassword,
    'admin',
    {} as Record<string, never>,
    config.secret
  );
  await writeUser(context, config.hkey, ADMIN_USERNAME, record);
}

async function createSimpleUser<TMeta>(
  context: SimpleAuthContext,
  username: string,
  password: string,
  options: CreateUserOptions<TMeta> = {}
): Promise<PublicUser<TMeta>> {
  await context.ensureInitialized();
  const config = context.requireConfig();
  const canonical = canonicalizeUsername(username);

  const existing = await context.client.hget(config.hkey, canonical.canonical);
  if (existing) {
    throw new UserExistsError(canonical.canonical);
  }

  const metadata = cloneJson(options.metadata ?? ({} as TMeta));
  const role = options.role ?? 'user';
  if (role !== 'admin' && role !== 'user') {
    throw new InvalidUserRoleError(String(role));
  }

  const record = await buildUserRecord(context, password, role, metadata, config.secret);
  await writeUser(context, config.hkey, canonical.canonical, record);

  return toPublicUser(canonical.canonical, record);
}

async function authenticateSimpleUser<TMeta>(
  context: SimpleAuthContext,
  username: string,
  password: string
): Promise<PublicUser<TMeta>> {
  await context.ensureInitialized();
  const config = context.requireConfig();
  const canonical = canonicalizeUsername(username);

  const raw = await context.client.hget(config.hkey, canonical.canonical);
  if (!raw) {
    throw new InvalidCredentialsError();
  }

  let record: UserRecord<TMeta>;
  try {
    record = parseUserRecord<TMeta>(canonical.canonical, raw);
  } catch (error: unknown) {
    if (error instanceof UserSerializationError) {
      context.logger?.error?.(error.message);
      throw new InvalidCredentialsError();
    }
    throw error;
  }

  if (!record.password) {
    throw new InvalidCredentialsError();
  }

  let verified: boolean;
  try {
    verified = await context.hasher.verifyPassword(password, record.password, config.secret);
  } catch (error: unknown) {
    if (error instanceof PasswordHasherUnavailableError) {
      context.logger?.error?.(error.message);
      throw new InvalidCredentialsError();
    }
    throw error;
  }

  if (!verified) {
    throw new InvalidCredentialsError();
  }

  return toPublicUser<TMeta>(canonical.canonical, record);
}

async function getSimpleUser<TMeta>(
  context: SimpleAuthContext,
  username: string
): Promise<PublicUser<TMeta> | null> {
  await context.ensureInitialized();
  const config = context.requireConfig();
  const canonical = canonicalizeUsername(username);
  const raw = await context.client.hget(config.hkey, canonical.canonical);

  if (!raw) {
    return null;
  }

  const record = parseUserRecord<TMeta>(canonical.canonical, raw);
  return toPublicUser<TMeta>(canonical.canonical, record);
}

async function buildUserRecord<TMeta>(
  context: SimpleAuthBootstrapContext,
  password: string,
  role: 'admin' | 'user',
  metadata: TMeta,
  secret: string
): Promise<UserRecord<TMeta>> {
  const nowIso = context.getNow().toISOString();
  const passwordRecord = await context.hasher.hashPassword(password, secret);
  return {
    type: 'simple',
    password: passwordRecord,
    role,
    metadata,
    createdAt: nowIso,
    updatedAt: nowIso
  };
}

async function writeUser<TMeta>(
  context: SimpleAuthBootstrapContext,
  hkey: string,
  username: string,
  record: UserRecord<TMeta>
): Promise<void> {
  const value = stringifyUserRecord(username, record);
  await context.client.hset(hkey, username, value);
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
