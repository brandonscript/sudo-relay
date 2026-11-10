import test from 'node:test';
import assert from 'node:assert/strict';
import { isTrustedRequest } from '../src/transport.js';

test('reference host rejects wrong host, foreign origin, missing CSRF, and non-JSON approval', () => {
  const host = '127.0.0.1:7351', origin = `http://${host}`, csrf = 'secret';
  const valid = { host, origin, 'x-approval-csrf': csrf, 'content-type': 'application/json' };
  assert.equal(isTrustedRequest(valid, host, origin, csrf, true), true);
  for (const invalid of [{ ...valid, host: 'evil.example' }, { ...valid, origin: 'https://evil.example' }, { ...valid, 'x-approval-csrf': '' }, { ...valid, 'content-type': 'text/plain' }]) assert.equal(isTrustedRequest(invalid, host, origin, csrf, true), false);
  assert.equal(isTrustedRequest({ host }, host, origin, csrf, false), true);
});
