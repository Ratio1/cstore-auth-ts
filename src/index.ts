export { CStoreAuth } from './auth';
export type {
  CStoreAuthOptions,
  CreateUserOptions,
  UpdateUserOptions,
  PublicUser,
  UserRecord,
  UserRole,
  PasswordRecord,
  AnyPasswordRecord,
  SupportedPasswordAlgo,
  Argon2idParams,
  ScryptParams,
  SimpleAuthApi
} from './types';
export type { CStoreLikeClient, Ratio1EdgeNodeClientOptions } from './cstore';
export { createDefaultCStoreClient } from './cstore';
export type { PasswordHasher } from './hasher';
export { createPasswordHasher } from './hasher';
export { resolveAuthEnv, readBootstrapAdminPassword, ENV_VARS } from './util/env';
export {
  AuthError,
  AuthInitError,
  EnvVarMissingError,
  InvalidCredentialsError,
  InvalidPasswordError,
  InvalidUserRoleError,
  InvalidUsernameError,
  PasswordHasherUnavailableError,
  UserExistsError,
  UserNotFoundError,
  UserSerializationError
} from './util/errors';
