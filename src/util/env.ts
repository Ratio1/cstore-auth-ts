import { EnvVarMissingError } from './errors';

export const ENV_VARS = {
  HKEY: 'EE_CSTORE_AUTH_HKEY',
  SECRET: 'EE_CSTORE_AUTH_SECRET',
  BOOTSTRAP_ADMIN_PASS: 'EE_CSTORE_AUTH_BOOTSTRAP_ADMIN_PW'
} as const;

export interface AuthEnvConfig {
  hkey: string;
  secret: string;
}

export function resolveAuthEnv(
  overrides: Partial<Record<'hkey' | 'secret', string>> = {},
  env: NodeJS.ProcessEnv = process.env
): AuthEnvConfig {
  const hkey = overrides.hkey ?? env[ENV_VARS.HKEY];
  const secret = overrides.secret ?? env[ENV_VARS.SECRET];

  if (!hkey) {
    throw new EnvVarMissingError(ENV_VARS.HKEY);
  }

  if (!secret) {
    throw new EnvVarMissingError(ENV_VARS.SECRET);
  }

  return { hkey, secret };
}

export function readBootstrapAdminPassword(env: NodeJS.ProcessEnv = process.env): string | null {
  const value = env[ENV_VARS.BOOTSTRAP_ADMIN_PASS];
  if (typeof value !== 'string' || value.trim() === '') {
    return null;
  }
  return value;
}
