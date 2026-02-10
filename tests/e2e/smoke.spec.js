import { test, expect } from '@playwright/test';

test('landing page loads', async ({ page }) => {
  await page.goto('/landing.html');
  await expect(page).toHaveTitle(/./);
  await expect(page.locator('body')).toBeVisible();
});

test('login page loads', async ({ page }) => {
  await page.goto('/login.html');
  await expect(page.locator('body')).toBeVisible();
});
