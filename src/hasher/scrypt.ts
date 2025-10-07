import {
  randomBytes,
  scrypt as nodeScrypt,
  timingSafeEqual,
  type BinaryLike,
  type ScryptOptions
} from 'node:crypto';
import { promisify } from 'node:util';

import type { PasswordRecord, ScryptParams } from '../types';

const scryptAsync = promisify(nodeScrypt) as (
  password: BinaryLike,
  salt: BinaryLike,
  keylen: number,
  options: ScryptOptions
) => Promise<Buffer>;

const SCRYPT_SALT_LENGTH = 16;
const DEFAULT_PARAMS: ScryptParams = {
  N: 2 ** 15,
  r: 8,
  p: 1,
  keyLength: 32
};

export async function hashWithScrypt(password: string, pepper: string): Promise<PasswordRecord<ScryptParams>> {
  const params = { ...DEFAULT_PARAMS };
  const salt = randomBytes(SCRYPT_SALT_LENGTH);
  const derived = (await scryptAsync(
    password,
    createSaltWithPepper(salt, pepper),
    params.keyLength,
    {
      N: params.N,
      r: params.r,
      p: params.p,
      maxmem: calculateMaxMem(params)
    }
  )) as Buffer;

  return {
    algo: 'scrypt',
    hash: derived.toString('base64'),
    salt: salt.toString('base64'),
    version: 1,
    params
  };
}

export async function verifyWithScrypt(
  password: string,
  record: PasswordRecord<ScryptParams>,
  pepper: string
): Promise<boolean> {
  const salt = Buffer.from(record.salt, 'base64');
  const expected = Buffer.from(record.hash, 'base64');

  const derived = (await scryptAsync(
    password,
    createSaltWithPepper(salt, pepper),
    record.params.keyLength,
    {
      N: record.params.N,
      r: record.params.r,
      p: record.params.p,
      maxmem: calculateMaxMem(record.params)
    }
  )) as Buffer;

  if (derived.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(derived, expected);
}

function createSaltWithPepper(salt: Buffer, pepper: string): Buffer {
  const pepperBuffer = Buffer.from(pepper, 'utf8');
  return Buffer.concat([salt, pepperBuffer]);
}

function calculateMaxMem(params: ScryptParams): number {
  const base = 128 * params.N * params.r;
  const minimum = 32 * 1024 * 1024;
  return Math.max(minimum, base * 2);
}
