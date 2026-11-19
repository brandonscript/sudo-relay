import { expect, test as base, type Page } from '@playwright/test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { approvalPayload, parsePending } from '../../ui/src/protocol.js';
import { startLab } from './server.js';
import { decisionSchema, finishSchema, stateSchema, type Mode } from './schema.js';

type Lab = Awaited<ReturnType<typeof startLab>>;
const test = base.extend<{ mode: Mode; clock: { value: number }; lab: Lab }>({
  mode: ['passkey', { option: true }],
  clock: async ({}, use) => { await use({ value: Math.floor(Date.now() / 1000) }); },
  lab: async ({ mode, clock }, use) => {
    const lab = await startLab({ mode, now: () => clock.value });
    try { await use(lab); } finally { await lab.close(); }
  },
});
async function state(page: Page, lab: Lab) { return stateSchema.parse(await (await page.request.get(`${lab.origin}/state`)).json()); }
async function post(page: Page, lab: Lab, path: string, body: unknown) {
  const current = await state(page, lab);
  return page.request.post(`${lab.origin}${path}`, { data: body, headers: { Origin: lab.origin, 'X-Approval-CSRF': current.csrf } });
}
async function open(page: Page, lab: Lab) {
  await page.goto(lab.setupURL);
  await expect(page.locator('#mode')).not.toHaveText('');
}
async function enroll(page: Page, lab: Lab) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const result: unknown = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true,
  } });
  if (typeof result !== 'object' || result === null || !('authenticatorId' in result) || typeof result.authenticatorId !== 'string') throw new Error('No test authenticator');
  await open(page, lab);
  await page.getByRole('button', { name: 'Set up test passkey' }).click();
  await expect(page.locator('#message')).toContainText('enrolled');
  return { cdp, authenticatorId: result.authenticatorId };
}
async function request(page: Page, lab: Lab) {
  await page.getByRole('button', { name: 'New test request' }).click();
  await expect(page.locator('#request')).toBeVisible();
  const pending = parsePending((await state(page, lab)).pending);
  return { id: pending.envelope.id, number: pending.envelope.number, share_output: false };
}
async function capture(page: Page, number: string) {
  const assertion = new Promise<ReturnType<typeof finishSchema.parse>>(resolve => {
    void page.route('**/approve/finish', async route => {
      const value: unknown = route.request().postDataJSON();
      resolve(finishSchema.parse(value));
      await route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ error: 'Held by test harness' }) });
    });
  });
  await page.getByLabel('Confirmation number').fill(number);
  await page.getByRole('button', { name: 'Approve once' }).click();
  const result = await assertion;
  await expect(page.locator('#message')).toContainText('Held by test harness');
  await page.unroute('**/approve/finish');
  return result;
}

test('G1: a fresh browser without the setup session shows no enrollment or request controls', async ({ page, lab }) => {
  await page.goto(lab.origin);
  await expect(page.locator('#message')).toContainText('Open the setup link');
  await expect(page.getByRole('button', { name: 'Set up test passkey' })).toBeHidden();
  await expect(page.getByRole('button', { name: 'New test request' })).toBeHidden();
  expect((await page.request.get(`${lab.origin}/state`)).status()).toBe(403);
});

test('G2: controls stay hidden until the authenticated mode is known', async ({ page, lab }) => {
  let release: () => void = () => {};
  const hold = new Promise<void>(resolve => { release = resolve; });
  let requested: () => void = () => {};
  const ready = new Promise<void>(resolve => { requested = resolve; });
  await page.route('**/state', async route => { requested(); await hold; await route.continue(); });
  try {
    await page.goto(lab.setupURL); await ready;
    await expect(page.getByRole('button', { name: 'Set up test passkey' })).toBeHidden();
    await expect(page.getByRole('button', { name: 'New test request' })).toBeHidden();
  } finally { release(); }
  await expect(page.getByRole('button', { name: 'Set up test passkey' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'New test request' })).toBeDisabled();
  expect((await state(page, lab)).enrolled).toBe(false);
});

test('G3: waiting for an authenticator is explicit and creates no receipt', async ({ page, lab }) => {
  const { cdp, authenticatorId } = await enroll(page, lab); const input = await request(page, lab);
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
  await page.getByLabel('Confirmation number').fill(input.number);
  await page.getByRole('button', { name: 'Approve once' }).click();
  await expect(page.locator('#message')).toContainText('Waiting for your passkey');
  await expect(page.getByRole('button', { name: 'Waiting for passkey…', exact: true })).toBeDisabled();
  expect((await state(page, lab)).state).toBe('pending');
  expect((await state(page, lab)).receipts).toBe(0);
  await page.reload();
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
  await page.getByLabel('Confirmation number').fill(input.number);
  await page.getByRole('button', { name: 'Approve once' }).click();
  await expect(page.getByRole('button', { name: 'Approved', exact: true })).toBeDisabled();
  expect((await state(page, lab)).receipts).toBe(1);
});

test('P1: passkey approval through Enter binds output choice and renders Approved', async ({ page, lab }) => {
  await enroll(page, lab); const input = await request(page, lab);
  await page.getByLabel('Share command output with the agent').check();
  await page.getByLabel('Confirmation number').fill(input.number);
  await page.getByLabel('Confirmation number').press('Enter');
  await expect(page.getByRole('button', { name: 'Approved', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Deny', exact: true })).toBeHidden();
  const result = await state(page, lab);
  expect(result.receipt?.share_output).toBe(true); expect(result.receipts).toBe(1);
  await page.reload();
  await expect(page.getByLabel('Share command output with the agent')).toBeChecked();
});

test('P2: matching number, missing assertion, and session downgrade cannot approve', async ({ page, lab }) => {
  await enroll(page, lab); const input = await request(page, lab);
  expect((await post(page, lab, '/approve/session', input)).ok()).toBe(false);
  expect((await post(page, lab, '/approve/finish', input)).ok()).toBe(false);
  expect((await post(page, lab, '/approve/options', { ...input, mode: 'session' })).ok()).toBe(false);
  expect((await state(page, lab)).receipts).toBe(0);
});

test('P3: one proof cannot change output, request ID, or command; original still succeeds', async ({ page, lab }) => {
  await enroll(page, lab); const input = await request(page, lab); const proof = await capture(page, input.number);
  for (const changed of [{ ...proof, share_output: true }, { ...proof, id: crypto.randomUUID() }, { ...proof, spec: { command: '/bin/other' } }]) {
    expect((await post(page, lab, '/approve/finish', changed)).ok()).toBe(false);
  }
  expect((await state(page, lab)).receipts).toBe(0);
  expect((await post(page, lab, '/approve/finish', proof)).ok()).toBe(true);
});

test('P4: altered signature, origin, challenge, RP, credential and cross-origin context fail', async ({ page, lab }) => {
  await enroll(page, lab); const input = await request(page, lab); const proof = await capture(page, input.number);
  const changed = structuredClone(proof); changed.response.response.signature = Buffer.alloc(70, 1).toString('base64url');
  const wrongKey = structuredClone(proof); wrongKey.response.id = wrongKey.response.rawId = Buffer.from('different-key').toString('base64url');
  const wrongRP = structuredClone(proof);
  const authData = Buffer.from(wrongRP.response.response.authenticatorData, 'base64url'); authData[0] = authData[0]! ^ 1;
  wrongRP.response.response.authenticatorData = authData.toString('base64url');
  const variants = [changed, wrongKey, wrongRP];
  for (const fields of [{ origin: 'https://attacker.invalid' }, { challenge: 'different' }, { crossOrigin: true }]) {
    const altered = structuredClone(proof);
    const client: unknown = JSON.parse(Buffer.from(proof.response.response.clientDataJSON, 'base64url').toString('utf8'));
    if (typeof client !== 'object' || client === null) throw new Error('Invalid test data');
    altered.response.response.clientDataJSON = Buffer.from(JSON.stringify({ ...client, ...fields })).toString('base64url'); variants.push(altered);
  }
  for (const value of variants) expect((await post(page, lab, '/approve/finish', value)).ok()).toBe(false);
  expect((await state(page, lab)).receipts).toBe(0);
  expect((await post(page, lab, '/approve/finish', proof)).ok()).toBe(true);
});

test('P5: concurrent replay creates exactly one receipt', async ({ page, lab }) => {
  await enroll(page, lab); const input = await request(page, lab); const proof = await capture(page, input.number);
  const results = await Promise.all(Array.from({ length: 8 }, () => post(page, lab, '/approve/finish', proof)));
  expect(results.filter(result => result.ok())).toHaveLength(1);
  expect((await state(page, lab)).receipts).toBe(1);
  expect((await post(page, lab, '/approve/finish', proof)).ok()).toBe(false);
});

test('P6: a superseded challenge fails, then a fresh ceremony succeeds', async ({ page, lab }) => {
  await enroll(page, lab); const input = await request(page, lab); const proof = await capture(page, input.number);
  expect((await post(page, lab, '/approve/options', input)).ok()).toBe(true);
  expect((await post(page, lab, '/approve/finish', proof)).ok()).toBe(false);
  await page.getByRole('button', { name: 'Approve once' }).click();
  await expect(page.locator('#message')).toContainText('Test receipt created');
});

test('P7: expiry while an assertion is in flight denies approval', async ({ page, lab, clock }) => {
  await enroll(page, lab); const input = await request(page, lab); const proof = await capture(page, input.number);
  clock.value += 301;
  expect((await post(page, lab, '/approve/finish', proof)).ok()).toBe(false);
  expect((await state(page, lab)).state).toBe('expired'); expect((await state(page, lab)).receipts).toBe(0);
});

test('P8: denial is terminal and a fresh request cannot reuse the old assertion', async ({ page, lab }) => {
  await enroll(page, lab); const input = await request(page, lab); const proof = await capture(page, input.number);
  await page.getByRole('button', { name: 'Deny', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Denied', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Approve once' })).toBeHidden();
  expect((await post(page, lab, '/approve/finish', proof)).ok()).toBe(false);
  const fresh = await request(page, lab);
  await post(page, lab, '/approve/options', fresh);
  expect((await post(page, lab, '/approve/finish', { ...proof, ...fresh })).ok()).toBe(false);
  expect((await state(page, lab)).receipts).toBe(0);
});

test('P9: three wrong numbers cancel a pending request', async ({ page, lab }) => {
  await enroll(page, lab); const input = await request(page, lab);
  for (let attempt = 0; attempt < 3; attempt++) expect((await post(page, lab, '/approve/options', { ...input, number: '00' })).ok()).toBe(false);
  expect((await post(page, lab, '/approve/options', input)).ok()).toBe(false);
  expect((await state(page, lab)).state).toBe('denied');
});

for (const flag of ['isBadUV', 'isBadUP'] as const) {
  test(`P10: authenticator response with ${flag} is rejected`, async ({ page, lab }) => {
    const { cdp, authenticatorId } = await enroll(page, lab); const input = await request(page, lab);
    await cdp.send('WebAuthn.setResponseOverrideBits', { authenticatorId, [flag]: true });
    const proof = await capture(page, input.number);
    expect((await post(page, lab, '/approve/finish', proof)).ok()).toBe(false);
    expect((await state(page, lab)).receipts).toBe(0);
    await cdp.send('WebAuthn.setResponseOverrideBits', { authenticatorId, isBadUV: false, isBadUP: false });
    await page.getByRole('button', { name: 'Approve once' }).click();
    await expect(page.locator('#message')).toContainText('Test receipt created');
  });
}

test('C1: a compromised review DOM can mislead despite valid passkey verification', async ({ page, lab }) => {
  await enroll(page, lab); const input = await request(page, lab);
  const authoritative = parsePending((await state(page, lab)).pending);
  await page.locator('#command').evaluate(element => { element.textContent = '/usr/bin/printf misleading-preview'; });
  await expect(page.locator('#command')).toHaveText('/usr/bin/printf misleading-preview');
  await page.getByLabel('Confirmation number').fill(input.number);
  await page.getByRole('button', { name: 'Approve once' }).click();
  await expect(page.locator('#message')).toContainText('Test receipt created');
  const expected = createHash('sha256').update(approvalPayload(authoritative, false)).digest('hex');
  expect((await state(page, lab)).receipt?.digest).toBe(expected);
});

test.describe('session mode', () => {
  test.use({ mode: 'session' });
  test('S1: automation with the authenticated session can approve without a human', async ({ page, lab }) => {
    await open(page, lab); const input = await request(page, lab);
    const results = await Promise.all(Array.from({ length: 8 }, () => post(page, lab, '/approve/session', input)));
    expect(results.filter(result => result.ok())).toHaveLength(1);
    expect((await state(page, lab)).receipt?.mode).toBe('session');
    expect((await post(page, lab, '/approve/session', input)).ok()).toBe(false);
    await page.reload(); await expect(page.getByRole('button', { name: 'Approved', exact: true })).toBeDisabled();
  });
  test('S2: anonymous, wrong-origin, missing-CSRF and oversized requests are rejected', async ({ page, lab, request: anonymous }) => {
    expect((await anonymous.get(`${lab.origin}/state`)).status()).toBe(403);
    await open(page, lab); const input = await request(page, lab); const current = await state(page, lab);
    for (const headers of [{ Origin: 'https://attacker.invalid', 'X-Approval-CSRF': current.csrf }, { Origin: lab.origin }]) {
      expect((await page.request.post(`${lab.origin}/approve/session`, { data: input, headers })).status()).toBe(403);
    }
    expect((await post(page, lab, '/approve/session', { ...input, padding: 'x'.repeat(70000) })).ok()).toBe(false);
    expect((await state(page, lab)).receipts).toBe(0);
    expect((await post(page, lab, '/approve/session', input)).ok()).toBe(true);
  });
  test('S3: phone-width layout, Enter and remembered output choice work in a desktop browser', async ({ page, lab }) => {
    await page.setViewportSize({ width: 390, height: 844 }); await open(page, lab);
    const input = await request(page, lab);
    await page.getByLabel('Share command output with the agent').check(); await page.reload();
    await expect(page.getByLabel('Share command output with the agent')).toBeChecked();
    await page.getByLabel('Confirmation number').fill(input.number); await page.getByLabel('Confirmation number').press('Enter');
    await expect(page.locator('#message')).toContainText('Test receipt created');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
});

test('R1: restart retains receipts, cancels pending work and invalidates the old session', async ({ page }) => {
  const directory = mkdtempSync(join(tmpdir(), 'approval-restart-')), database = join(directory, 'receipts.sqlite');
  let lab = await startLab({ mode: 'session', database });
  try {
    await open(page, lab); const approved = await request(page, lab);
    expect((await post(page, lab, '/approve/session', approved)).ok()).toBe(true);
    await page.reload(); const pending = await request(page, lab);
    const oldSession = await page.context().cookies();
    await lab.close(); lab = await startLab({ mode: 'session', database });
    await page.context().addCookies(oldSession);
    expect((await page.request.get(`${lab.origin}/state`)).status()).toBe(403);
    await open(page, lab);
    expect((await state(page, lab)).receipts).toBe(1);
    expect((await post(page, lab, '/approve/session', approved)).ok()).toBe(false);
    expect((await post(page, lab, '/approve/session', decisionSchema.parse(pending))).ok()).toBe(false);
  } finally { await lab.close(); rmSync(directory, { recursive: true, force: true }); }
});
