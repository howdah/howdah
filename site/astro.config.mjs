import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://howdah.org',
  output: 'static',
  compressHTML: true,
  build: { inlineStylesheets: 'auto' },
  devToolbar: { enabled: false },
  // English only at launch, but routed so translations drop in without moving
  // files: the default locale is not prefixed, so pages stay at `/`, `/install/`
  // etc. Adding e.g. `fr` later serves it under `/fr/` and leaves these intact.
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
    routing: { prefixDefaultLocale: false },
  },
});
