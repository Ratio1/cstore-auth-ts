import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  outExtension({ format }) {
    return {
      js: format === 'esm' ? '.mjs' : '.cjs'
    };
  },
  dts: true,
  sourcemap: true,
  clean: true,
  minify: false,
  target: 'node18',
  splitting: false,
  treeshake: true
});
