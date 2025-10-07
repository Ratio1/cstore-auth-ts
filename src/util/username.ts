import { InvalidUsernameError } from './errors';

export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 64;
const USERNAME_PATTERN = /^[a-z0-9._-]+$/;

export interface CanonicalUsername {
  readonly original: string;
  readonly canonical: string;
}

export function canonicalizeUsername(username: string): CanonicalUsername {
  if (typeof username !== 'string') {
    throw new InvalidUsernameError('value must be a string');
  }

  const trimmed = username.trim();
  if (trimmed.length === 0) {
    throw new InvalidUsernameError('value must not be empty');
  }

  const canonical = trimmed.toLowerCase();
  validateCanonicalUsername(canonical);

  return { original: trimmed, canonical };
}

export function validateCanonicalUsername(username: string): void {
  if (username.length < USERNAME_MIN_LENGTH || username.length > USERNAME_MAX_LENGTH) {
    throw new InvalidUsernameError(
      `length must be between ${USERNAME_MIN_LENGTH} and ${USERNAME_MAX_LENGTH} characters`
    );
  }

  if (!USERNAME_PATTERN.test(username)) {
    throw new InvalidUsernameError(
      'only lowercase letters, numbers, ".", "-", and "_" are allowed after canonicalization'
    );
  }
}
