import { test, expect } from '@playwright/test';

test('minimal: login -> token stored', async ({ page }) => {
  // ✅ ICI seulement : page existe
  page.on('console', msg => console.log('BROWSER:', msg.type(), msg.text()));
  page.on('pageerror', err => console.log('PAGEERROR:', err));

  await page.goto('/dashboard.html');

  await page.fill('#email', 'test@example.com');
  await page.fill('#password', 'Test1234!');
  await page.click('#btnLogin');

  const out = page.locator('#out');

  // Attend que le login réponde (HTTP xxx)
  await expect(out).toContainText('HTTP', { timeout: 15000 });

  // Attend le token
  await page.waitForFunction(() => {
    const t = localStorage.getItem('js_token');
    return t && t.length > 10;
  }, { timeout: 15000 });

  await expect(page.locator('#token')).not.toHaveValue('');
});
