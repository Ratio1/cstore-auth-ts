import { defineConfig } from 'vitest/config';

/**
 * Vitest configuration for unit tests
 * 
 * Unit tests are fast, isolated tests that mock external dependencies.
 * For integration tests, see vitest.integration.config.ts
 */
export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      reporter: ['text', 'lcov'],
      provider: 'v8',
      include: ['src/**/*.ts']
    },
    // Exclude integration tests from unit test runs
    include: ['test/**/*.spec.ts'],
    exclude: ['test/integration/**/*.integration.spec.ts', 'node_modules/**']
  }
});
