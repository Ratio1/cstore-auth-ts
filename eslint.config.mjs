import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

const tsConfigs = tseslint.configs.recommended.map((config) => ({
  ...config,
  files: ['src/**/*.ts', 'test/**/*.ts']
}));

export default tseslint.config(
  {
    ignores: ['dist/**', 'docs/**', 'coverage/**', 'eslint.config.mjs', 'tsup.config.ts']
  },
  js.configs.recommended,
  ...tsConfigs,
  {
    files: ['src/**/*.ts', 'test/**/*.ts'],
    rules: {
      '@typescript-eslint/consistent-type-definitions': ['error', 'interface'],
      '@typescript-eslint/no-explicit-any': 'error'
    }
  },
  {
    files: ['test/**/*.ts'],
    rules: {
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off'
    }
  },
  prettier
);
