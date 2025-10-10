import type { PasswordHasher } from './hasher';
import type { CStoreLikeClient } from './cstore';

export type UserRole = 'admin' | 'user';

export type SupportedPasswordAlgo = 'argon2id' | 'scrypt';

export interface Argon2idParams {
  timeCost: number;
  memoryCost: number;
  parallelism: number;
  outputLen: number;
}

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
  keyLength: number;
}

export interface PasswordRecord<TParams extends object = Record<string, unknown>> {
  algo: SupportedPasswordAlgo;
  hash: string;
  salt: string;
  version: number;
  params: TParams;
}

export type AnyPasswordRecord = PasswordRecord<Argon2idParams | ScryptParams>;

export interface UserRecord<TMeta = Record<string, unknown>> {
  type: 'simple';
  password: AnyPasswordRecord | null;
  role: UserRole;
  metadata: TMeta;
  createdAt: string;
  updatedAt: string;
}

export interface PublicUser<TMeta = Record<string, unknown>> {
  username: string;
  role: UserRole;
  metadata: TMeta;
  createdAt: string;
  updatedAt: string;
  type: 'simple';
}

export interface CStoreAuthOptions {
  hkey?: string;
  secret?: string;
  client?: CStoreLikeClient;
  hasher?: PasswordHasher;
  now?: () => Date;
  logger?: Pick<Console, 'debug' | 'info' | 'warn' | 'error'>;
}

export interface CreateUserOptions<TMeta = Record<string, unknown>> {
  role?: UserRole;
  metadata?: TMeta;
}

export interface SimpleAuthApi {
  init(): Promise<void>;
  createUser<TMeta = Record<string, unknown>>(
    username: string,
    password: string,
    options?: CreateUserOptions<TMeta>
  ): Promise<PublicUser<TMeta>>;
  authenticate<TMeta = Record<string, unknown>>(
    username: string,
    password: string
  ): Promise<PublicUser<TMeta>>;
  getUser<TMeta = Record<string, unknown>>(username: string): Promise<PublicUser<TMeta> | null>;
  getAllUsers<TMeta = Record<string, unknown>>(): Promise<PublicUser<TMeta>[]>;
}
