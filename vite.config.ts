import { defineConfig } from 'vite';
import { resolve } from 'path';
import dts from 'vite-plugin-dts';

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  build: {
    lib: {
      entry: {
        index: resolve(__dirname, 'src/index.ts'),
      },
      name: 'nobleCurvesExtended',
      fileName: (format, entryName) =>
        `${entryName}.${format === 'es' ? 'mjs' : 'cjs'}`,
      formats: ['es', 'cjs'],
    },
    rollupOptions: {
      external: [/^@noble\/curves($|\/)/, /^@noble\/hashes($|\/)/, 'u8a-utils'],
      output: {
        globals: {
          '@noble/curves': 'nobleCurves',
          '@noble/hashes': 'nobleHashes',
        },
      },
    },
  },
  plugins: [
    dts({
      rollupTypes: true,
    }),
  ],
});
