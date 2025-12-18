import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  use: {
    baseURL: 'http://127.0.0.1:8090', // ⚠️ change si ton dashboard est sur un autre port
    headless: false,
  },
});
