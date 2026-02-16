import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    globals: true,
    include: ['test/**/*.spec.js'],
    testTimeout: 30000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      include: ['src/esm/**/*.js'],
      exclude: [
        'src/esm/index.js',
        'src/esm/quantum/index.js',
        'src/esm/quantum/types.js',
      ],
      thresholds: { branches: 80, functions: 90 },
    },
  },
});
