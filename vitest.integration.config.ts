import { defineConfig } from 'vitest/config';

/**
 * Vitest configuration for integration tests
 * 
 * Integration tests are kept separate from unit tests because they:
 * - May take longer to run
 * - Test full system integration rather than isolated units
 * - Require proper cleanup and setup
 * - Are run less frequently in CI/CD pipelines
 */
export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      reporter: ['text', 'lcov'],
      provider: 'v8',
      include: ['src/**/*.ts']
    },
    include: ['test/integration/**/*.integration.spec.ts'],
    // Integration tests may need more time
    testTimeout: 30000,
    // Run tests serially to avoid race conditions with shared resources
    poolOptions: {
      threads: {
        singleThread: true
      }
    }
  }
});

