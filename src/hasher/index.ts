import { InvalidPasswordError, PasswordHasherUnavailableError } from '../util/errors';
import type { AnyPasswordRecord, PasswordRecord, Argon2idParams, ScryptParams } from '../types';
import { hashWithArgon2id, isArgon2idAvailable, verifyWithArgon2id } from './argon2id';
import { hashWithScrypt, verifyWithScrypt } from './scrypt';

export interface PasswordHasher {
  hashPassword(password: string, pepper: string): Promise<AnyPasswordRecord>;
  verifyPassword(password: string, record: AnyPasswordRecord, pepper: string): Promise<boolean>;
}

export interface PasswordHasherOptions {
  logger?: Pick<Console, 'warn'>;
}

export function createPasswordHasher(options: PasswordHasherOptions = {}): PasswordHasher {
  return new DefaultPasswordHasher(options.logger);
}

class DefaultPasswordHasher implements PasswordHasher {
  private fallbackAnnounced = false;

  constructor(private readonly logger?: Pick<Console, 'warn'>) {}

  async hashPassword(password: string, pepper: string): Promise<AnyPasswordRecord> {
    ensurePassword(password);

    if (await isArgon2idAvailable()) {
      try {
        return await hashWithArgon2id(password, pepper);
      } catch (error) {
        if (!(error instanceof PasswordHasherUnavailableError)) {
          throw error;
        }
        this.warnFallbackOnce(
          'Falling back to scrypt password hashing because Argon2id is unavailable at runtime.'
        );
      }
    } else {
      this.warnFallbackOnce(
        'Argon2id native module could not be loaded. Falling back to scrypt password hashing.'
      );
    }

    return hashWithScrypt(password, pepper);
  }

  async verifyPassword(password: string, record: AnyPasswordRecord, pepper: string): Promise<boolean> {
    switch (record.algo) {
      case 'argon2id':
        try {
          return await verifyWithArgon2id(password, record as PasswordRecord<Argon2idParams>, pepper);
        } catch (error) {
          if (error instanceof PasswordHasherUnavailableError) {
            this.warnFallbackOnce(
              'Argon2id verification requested but the native module is unavailable.'
            );
          }
          throw error;
        }
      case 'scrypt':
        return verifyWithScrypt(password, record as PasswordRecord<ScryptParams>, pepper);
      default:
        throw new PasswordHasherUnavailableError(record.algo);
    }
  }

  private warnFallbackOnce(message: string): void {
    if (this.fallbackAnnounced) {
      return;
    }

    this.fallbackAnnounced = true;
    this.logger?.warn?.(message);
  }
}

function ensurePassword(password: string): void {
  if (typeof password !== 'string' || password.length === 0) {
    throw new InvalidPasswordError('value must be a non-empty string');
  }
}
