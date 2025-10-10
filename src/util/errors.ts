export type AuthErrorCode =
  | 'ENV_VAR_MISSING'
  | 'AUTH_INIT_FAILED'
  | 'USER_EXISTS'
  | 'USER_NOT_FOUND'
  | 'INVALID_USERNAME'
  | 'INVALID_PASSWORD'
  | 'INVALID_USER_ROLE'
  | 'INVALID_CREDENTIALS'
  | 'PASSWORD_HASHER_UNAVAILABLE'
  | 'USER_SERIALIZATION';

export class AuthError extends Error {
  public readonly code: AuthErrorCode;

  constructor(message: string, code: AuthErrorCode) {
    super(message);
    this.code = code;
    this.name = this.constructor.name;
  }
}

export class EnvVarMissingError extends AuthError {
  constructor(variableName: string) {
    super(`Environment variable ${variableName} is required but was not provided.`, 'ENV_VAR_MISSING');
  }
}

export class AuthInitError extends AuthError {
  constructor(message: string) {
    super(message, 'AUTH_INIT_FAILED');
  }
}

export class UserExistsError extends AuthError {
  constructor(username: string) {
    super(`User "${username}" already exists.`, 'USER_EXISTS');
  }
}

export class UserNotFoundError extends AuthError {
  constructor(username: string) {
    super(`User "${username}" not found.`, 'USER_NOT_FOUND');
  }
}

export class InvalidUsernameError extends AuthError {
  constructor(details: string) {
    super(`Invalid username: ${details}`, 'INVALID_USERNAME');
  }
}

export class InvalidPasswordError extends AuthError {
  constructor(details: string) {
    super(`Invalid password: ${details}`, 'INVALID_PASSWORD');
  }
}

export class InvalidUserRoleError extends AuthError {
  constructor(role: string) {
    super(`Invalid user role "${role}". Expected "admin" or "user".`, 'INVALID_USER_ROLE');
  }
}

export class InvalidCredentialsError extends AuthError {
  constructor() {
    super('Invalid username or password.', 'INVALID_CREDENTIALS');
  }
}

export class PasswordHasherUnavailableError extends AuthError {
  constructor(algo: string) {
    super(
      `Password hasher for algorithm "${algo}" is unavailable in this runtime. Ensure the necessary dependencies are installed.`,
      'PASSWORD_HASHER_UNAVAILABLE'
    );
  }
}

export class UserSerializationError extends AuthError {
  constructor(username: string, details: string) {
    super(`Failed to parse user record for "${username}": ${details}`, 'USER_SERIALIZATION');
  }
}
