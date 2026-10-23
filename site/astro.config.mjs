import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://howdah.org',
  output: 'static',
  compressHTML: true,
  build: { inlineStylesheets: 'auto' },
  devToolbar: { enabled: false },
});
