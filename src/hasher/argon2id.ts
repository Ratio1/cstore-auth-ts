import { randomBytes, timingSafeEqual } from 'node:crypto';

import type { Argon2idParams, PasswordRecord } from '../types';
import { PasswordHasherUnavailableError } from '../util/errors';

const ARGON2_SALT_LENGTH = 16;
const DEFAULT_PARAMS: Argon2idParams = {
  timeCost: 3,
  memoryCost: 65536,
  parallelism: 1,
  outputLen: 32
};

let modulePromise:
  | Promise<typeof import('@node-rs/argon2') | null>
  | null = null;

export async function isArgon2idAvailable(): Promise<boolean> {
  const mod = await loadModule();
  return Boolean(mod);
}

export async function hashWithArgon2id(password: string, pepper: string): Promise<PasswordRecord<Argon2idParams>> {
  const mod = await loadModule();
  if (!mod) {
    throw new PasswordHasherUnavailableError('argon2id');
  }

  const salt = randomBytes(ARGON2_SALT_LENGTH);
  const params = { ...DEFAULT_PARAMS };
  const derived = await mod.hashRaw(password, {
    algorithm: mod.Algorithm.Argon2id,
    ...params,
    salt,
    secret: Buffer.from(pepper, 'utf8'),
    outputLen: params.outputLen
  });

  return encodeRecord(derived, salt, params);
}

export async function verifyWithArgon2id(
  password: string,
  record: PasswordRecord<Argon2idParams>,
  pepper: string
): Promise<boolean> {
  const mod = await loadModule();
  if (!mod) {
    throw new PasswordHasherUnavailableError('argon2id');
  }

  const salt = Buffer.from(record.salt, 'base64');
  const expected = Buffer.from(record.hash, 'base64');
  const derived = await mod.hashRaw(password, {
    algorithm: mod.Algorithm.Argon2id,
    timeCost: record.params.timeCost,
    memoryCost: record.params.memoryCost,
    parallelism: record.params.parallelism,
    salt,
    secret: Buffer.from(pepper, 'utf8'),
    outputLen: record.params.outputLen
  });

  if (derived.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(derived, expected);
}

function encodeRecord(
  hash: Buffer,
  salt: Buffer,
  params: Argon2idParams
): PasswordRecord<Argon2idParams> {
  return {
    algo: 'argon2id',
    hash: hash.toString('base64'),
    salt: salt.toString('base64'),
    version: 1,
    params
  };
}

async function loadModule(): Promise<typeof import('@node-rs/argon2') | null> {
  if (!modulePromise) {
    modulePromise = import('@node-rs/argon2')
      .then((mod) => mod)
      .catch(() => null);
  }

  return modulePromise;
}
