import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      reporter: ['text', 'lcov'],
      provider: 'v8'
    },
    include: ['test/**/*.spec.ts']
  }
});
