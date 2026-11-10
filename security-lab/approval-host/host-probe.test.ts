/** A synthetic MCP Apps bridge checks card behavior, not ChatGPT isolation. */
import { readFileSync } from 'node:fs';
import { test, expect, type Page } from '@playwright/test';

const html = readFileSync(new URL('../../ui/dist/host-probe.html', import.meta.url), 'utf8');
async function setup(page: Page, invalidMetadata = false, rejectDecision = false): Promise<void> {
  page.on('pageerror', error => { throw error; });
  await page.setContent('<pre id="calls">[]</pre><pre id="initialization"></pre><iframe title="probe"></iframe>');
  await page.evaluate(({ html, invalidMetadata, rejectDecision }) => {
    const iframe = document.querySelector('iframe');
    const callsNode = document.querySelector('#calls');
    if (!iframe || !callsNode) throw new Error('Missing fixture elements');
    const request = { id: 'test-request', command: '/usr/bin/printf test', digest: 'd'.repeat(64), expires_at: Math.floor(Date.now() / 1000) + 300, state: 'pending', share_output: false };
    const calls: unknown[] = [];
    window.addEventListener('message', (event: MessageEvent<unknown>) => {
      if (event.source !== iframe.contentWindow || typeof event.data !== 'object' || event.data === null) return;
      const message = event.data as Record<string, unknown>;
      const send = (value: unknown): void => iframe.contentWindow?.postMessage(value, '*');
      if (message.method === 'ui/initialize') {
        const initialization = document.querySelector('#initialization');
        if (!initialization) throw new Error('Missing initialization recorder');
        initialization.textContent = JSON.stringify(message.params);
        send({ jsonrpc: '2.0', id: message.id, result: { protocolVersion: '2026-01-26', hostInfo: { name: 'synthetic-test-host', version: '1' }, hostCapabilities: { serverTools: {} }, hostContext: { theme: 'dark', styles: { variables: { '--color-background-primary': '#212121' } } } } });
      }
      if (message.method === 'ui/notifications/initialized') send({ jsonrpc: '2.0', method: 'ui/notifications/tool-result', params: { content: [], structuredContent: { instance: 'test-instance', request, receipt_count: 0 }, _meta: { probe: { id: request.id, number: '47', canary: 'a'.repeat(32), capability: invalidMetadata ? 'bad' : 'b'.repeat(64) } } } });
      if (message.method === 'tools/call') {
        const params = message.params as Record<string, unknown>;
        calls.push({ name: params.name, arguments: params.arguments }); callsNode.textContent = JSON.stringify(calls);
        send({ jsonrpc: '2.0', id: message.id, result: rejectDecision ? { content: [{ type: 'text', text: 'Rejected' }], isError: true } : { content: [], structuredContent: { instance: 'test-instance', request: { ...request, state: params.name === 'cancel_probe' ? 'denied' : 'approved' }, receipt_count: params.name === 'cancel_probe' ? 0 : 1 } } });
      }
    });
    iframe.srcdoc = html;
  }, { html, invalidMetadata, rejectDecision });
}
test('Host probe: Enter sends one decision and shows Approved', async ({ page }) => {
  await setup(page);
  const card = page.frameLocator('iframe');
  await expect(card.getByRole('status')).toHaveText('Ready. This records a receipt only.');
  expect(JSON.parse(await page.locator('#initialization').innerText())).toMatchObject({ appCapabilities: { availableDisplayModes: ['inline'] } });
  await card.getByLabel('Type 47 to confirm').fill('46');
  await expect(card.getByRole('button', { name: 'Approve once' })).toBeDisabled();
  await card.getByLabel('Type 47 to confirm').fill('47');
  await expect(card.locator('#digit-first')).toHaveText('4');
  await expect(card.locator('#digit-second')).toHaveText('7');
  await card.getByLabel('Type 47 to confirm').press('Enter');
  await expect(card.getByRole('button', { name: 'Approved', exact: true })).toBeDisabled();
  await expect(card.getByRole('button', { name: 'Deny', exact: true })).toBeHidden();
  expect(JSON.parse(await page.locator('#calls').innerText())).toEqual([{ name: 'record_probe_approval', arguments: { id: 'test-request', number: '47', capability: 'b'.repeat(64) } }]);
});
test('Host probe: denial hides approval and sends no capability', async ({ page }) => {
  await setup(page);
  const card = page.frameLocator('iframe');
  await card.getByRole('button', { name: 'Deny', exact: true }).click();
  await expect(card.getByRole('button', { name: 'Denied', exact: true })).toBeDisabled();
  await expect(card.getByRole('button', { name: 'Approved', exact: true })).toBeHidden();
  expect(JSON.parse(await page.locator('#calls').innerText())).toEqual([{ name: 'cancel_probe', arguments: { id: 'test-request' } }]);
});
test('Host probe: malformed UI metadata fails closed', async ({ page }) => {
  await setup(page, true);
  const card = page.frameLocator('iframe');
  await expect(card.getByRole('status')).toHaveText('Invalid pending probe');
  await expect(card.getByRole('button', { name: 'Approve once' })).toBeDisabled();
  expect(await page.locator('#calls').innerText()).toBe('[]');
});
test('Host probe: server rejection does not display Approved or retry', async ({ page }) => {
  await setup(page, false, true);
  const card = page.frameLocator('iframe');
  await card.getByLabel('Type 47 to confirm').fill('47');
  await card.getByLabel('Type 47 to confirm').press('Enter');
  await expect(card.getByRole('status')).toContainText('Server rejected');
  await expect(card.getByRole('button', { name: 'Approve once' })).toBeVisible();
  expect(JSON.parse(await page.locator('#calls').innerText())).toHaveLength(1);
});

test('Host probe: host theme and narrow layout keep the command and controls visible', async ({ page }) => {
  await setup(page);
  await page.locator('iframe').evaluate(frame => { frame.style.width = '320px'; frame.style.height = '1000px'; });
  const card = page.frameLocator('iframe');
  await expect(card.getByRole('status')).toContainText('Ready.');
  await expect(card.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await card.locator('main').evaluate(node => getComputedStyle(node).backgroundColor)).toBe('rgb(33, 33, 33)');
  await card.locator('#command').evaluate(node => { node.textContent = '/usr/bin/printf ' + 'long-argument'.repeat(40); });
  expect(await card.locator('html').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
  await expect(card.getByLabel('Type 47 to confirm')).toBeEnabled();
  await page.evaluate(() => document.querySelector('iframe')?.contentWindow?.postMessage({ jsonrpc: '2.0', method: 'ui/notifications/host-context-changed', params: { theme: 'light', styles: { variables: { '--color-background-primary': '#ffffff' } } } }, '*'));
  await expect(card.locator('html')).toHaveAttribute('data-theme', 'light');
  expect(await card.locator('main').evaluate(node => getComputedStyle(node).backgroundColor)).toBe('rgb(255, 255, 255)');
});
test('Host probe: countdown expiry disables both decisions without sending a receipt', async ({ page }) => {
  await page.clock.install();
  await setup(page);
  const card = page.frameLocator('iframe');
  await expect(card.getByRole('status')).toContainText('Ready.');
  await card.getByLabel('Type 47 to confirm').fill('47');
  await expect(card.getByRole('button', { name: 'Approve once' })).toBeEnabled();
  await page.clock.fastForward(301_000);
  await expect(card.locator('#expiry')).toHaveText('Expired');
  await expect(card.getByRole('button', { name: 'Approve once' })).toBeDisabled();
  await expect(card.getByRole('button', { name: 'Deny' })).toBeDisabled();
  expect(await page.locator('#calls').innerText()).toBe('[]');
});
