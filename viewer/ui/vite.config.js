import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// `npm run build` writes dist/, which the Rust viewer serves.
// `npm run dev` serves the UI itself and forwards /api to the Rust viewer.
export default defineConfig({
  plugins: [svelte()],
  base: './',
  server: {
    proxy: { '/api': 'http://127.0.0.1:8080' },
  },
});
