import test from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { hex, payload, approvalPayload, parsePending, verifyPending, type Envelope, type Pending, type Approval } from '../src/protocol.js';
import { approveOnce, type TrustedHost } from '../src/adapter.js';

const now = Math.floor(Date.now() / 1000);
function pending(): Pending {
  const envelope: Envelope = { version: 2, machine_id: 'test-machine', id: 'test-request', nonce: 'test-nonce', created_at: now - 1, expires_at: now + 299, number: '42', spec: { command: { kind: 'argv', argv: ['/usr/bin/printf', '<script>alert(1)</script>'] }, env: { TZ: 'UTC', LANG: 'C' }, reason: 'Print a literal string', timeout_secs: 300, output_needed: false } };
  const bytes = payload(envelope);
  return { envelope, signing_payload: hex(bytes), digest: createHash('sha256').update(bytes).digest('hex') };
}

test('typed payload is deterministic and sorted by environment key', () => {
  const first = pending();
  const second = structuredClone(first.envelope); second.spec.env = { LANG: 'C', TZ: 'UTC' };
  assert.equal(hex(payload(second)), first.signing_payload);
  assert.equal(parsePending(first).envelope.number, '42');
});
test('invalid incoming data, altered payload, digest, and expiry fail closed', async () => {
  for (const value of [null, {}, { envelope: {} }, { ...pending(), signing_payload: '00' }]) assert.throws(() => parsePending(value));
  await assert.rejects(verifyPending({ ...pending(), digest: '0'.repeat(64) }), /digest/);
  await assert.rejects(verifyPending(pending(), now + 300), /expired/);
  const changed = pending(); changed.envelope.spec.reason = 'changed';
  await assert.rejects(verifyPending(changed), /payload/);
});
test('only matching request is signed once and signature binds all bytes', async () => {
  const keys = generateKeyPairSync('ed25519'); let calls = 0; let approval: Approval | undefined;
  const host: TrustedHost = { signatureAlgorithm: 'ed25519', keyId: 'host', machineId: 'test-machine', signHumanApproval: async bytes => { calls++; return sign(null, bytes, keys.privateKey); }, submitApproval: async value => { approval = value; return { state: 'consumed' }; } };
  await assert.rejects(approveOnce(pending(), '41', true, host), /number/);
  await assert.rejects(approveOnce(pending(), '42', true, { ...host, machineId: 'other' }), /unpaired/);
  assert.equal(calls, 0);
  await approveOnce(pending(), '42', true, host);
  assert.equal(calls, 1); assert.ok(approval);
  assert.equal(verify(null, approvalPayload(pending(), true), keys.publicKey, Buffer.from(approval.signature, 'hex')), true);
  const altered = pending().envelope; altered.spec.timeout_secs = 1;
  assert.equal(verify(null, approvalPayload({ ...pending(), signing_payload: hex(payload(altered)) }, true), keys.publicKey, Buffer.from(approval.signature, 'hex')), false);
});

test('sharing choice is signed, cannot flip, and must be a runtime boolean', async()=>{
  const keys=generateKeyPairSync('ed25519');
  for(const shareOutput of [false,true]) {
    let captured: Approval|undefined;
    const host:TrustedHost={signatureAlgorithm:'ed25519',keyId:'host',machineId:'test-machine',signHumanApproval:async bytes=>sign(null,bytes,keys.privateKey),submitApproval:async approval=>{captured=approval;}};
    await approveOnce(pending(),'42',shareOutput,host);
    assert.ok(captured);assert.equal(captured.share_output,shareOutput);
    assert.equal(verify(null,approvalPayload(pending(),shareOutput),keys.publicKey,Buffer.from(captured.signature,'hex')),true);
    assert.equal(verify(null,approvalPayload(pending(),!shareOutput),keys.publicKey,Buffer.from(captured.signature,'hex')),false);
    await assert.rejects(approveOnce(pending(),'42','true' as unknown as boolean,host),/boolean/);
  }
});
test('Rust fixture matches request and both signed decisions',()=>{
  const fixture=JSON.parse(readFileSync(new URL('./fixture.json',import.meta.url),'utf8')) as Record<string,unknown>;
  const parsed=parsePending(fixture);
  assert.equal(hex(approvalPayload(parsed,true)),fixture['approval_payload_shared']);
  assert.equal(hex(approvalPayload(parsed,false)),fixture['approval_payload_withheld']);
  const changed=pending();changed.envelope.spec.output_needed=true;
  assert.throws(()=>parsePending(changed),/payload/);
  for(const invalid of ['true',undefined,1]) {
    const invalidHint=structuredClone(fixture) as {envelope:{spec:{output_needed:unknown}}};
    invalidHint.envelope.spec.output_needed=invalid;
    assert.throws(()=>parsePending(invalidHint),/boolean/);
  }
});

test('long execution limits remain bounded, signed and separate from approval expiry', async () => {
  for (const timeout of [1, 300, 3600, 86400]) {
    const value = pending();
    value.envelope.spec.timeout_secs = timeout;
    value.signing_payload = hex(payload(value.envelope));
    value.digest = createHash('sha256').update(payload(value.envelope)).digest('hex');
    assert.equal((await verifyPending(value, now)).envelope.spec.timeout_secs, timeout);
    await assert.rejects(verifyPending(value, now + 300), /expired/);
    value.envelope.spec.timeout_secs += 1;
    assert.throws(() => parsePending(value), /payload|limits/);
  }
  for (const timeout of [0, 86401, Number.MAX_SAFE_INTEGER]) {
    const value = pending();
    value.envelope.spec.timeout_secs = timeout;
    value.signing_payload = hex(payload(value.envelope));
    assert.throws(() => parsePending(value), /limits/);
  }
});

test('CryptoKit P-256 DER signatures cover the existing CBOR decisions', () => {
  const vector = JSON.parse(readFileSync(new URL('./p256-fixture.json', import.meta.url), 'utf8')) as Record<string, string>;
  const pending = parsePending(JSON.parse(readFileSync(new URL('./fixture.json', import.meta.url), 'utf8')) as unknown);
  const point = Buffer.from(vector['public_key_sec1']!, 'hex');
  assert.equal(point.length, 65); assert.equal(point[0], 4);
  const key = createPublicKey({format: 'jwk', key: {kty: 'EC', crv: 'P-256',
    x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url')}});
  for (const [share, suffix] of [[true, 'shared'], [false, 'withheld']] as const) {
    const bytes = approvalPayload(pending, share);
    assert.equal(hex(bytes), vector[`payload_${suffix}`]);
    const signature = Buffer.from(vector[`signature_der_${suffix}`]!, 'hex');
    assert.equal(verify('sha256', bytes, key, signature), true);
    assert.equal(verify('sha256', approvalPayload(pending, !share), key, signature), false);
  }
});

test('P-256 host signs the reviewed decision with no algorithm selector on the wire', async () => {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  for (const share of [false, true]) {
    const request = pending();
    let captured: Approval | undefined;
    const host: TrustedHost = {
      signatureAlgorithm: 'p256-sha256', keyId: 'native', machineId: 'test-machine',
      signHumanApproval: async bytes => sign('sha256', bytes, keys.privateKey),
      submitApproval: async value => { captured = value; },
    };
    await approveOnce(request, '42', share, host);
    assert.ok(captured);
    assert.equal(captured.key_id, 'native');
    assert.equal('signatureAlgorithm' in captured, false);
    assert.equal(verify('sha256', approvalPayload(request, share), keys.publicKey, Buffer.from(captured.signature, 'hex')), true);
    assert.equal(verify('sha256', approvalPayload(request, !share), keys.publicKey, Buffer.from(captured.signature, 'hex')), false);
    const altered = structuredClone(request);
    altered.envelope.spec.command = { kind: 'argv', argv: ['/bin/echo', 'different'] };
    altered.signing_payload = hex(payload(altered.envelope));
    assert.equal(verify('sha256', approvalPayload(altered, share), keys.publicKey, Buffer.from(captured.signature, 'hex')), false);
  }
});

test('unknown host algorithms and invalid signature bounds never submit or fall back', async () => {
  let signs = 0, submissions = 0;
  const host: TrustedHost = {
    signatureAlgorithm: 'p256-sha256', keyId: 'native', machineId: 'test-machine',
    signHumanApproval: async () => { signs++; return new Uint8Array(73); },
    submitApproval: async () => { submissions++; },
  };
  for (const invalid of [undefined, 'auto', 'rsa']) {
    await assert.rejects(approveOnce(pending(), '42', true,
      { ...host, signatureAlgorithm: invalid } as unknown as TrustedHost), /algorithm/);
  }
  assert.equal(signs, 0);
  await assert.rejects(approveOnce(pending(), '42', true, host), /DER/);
  await assert.rejects(approveOnce(pending(), '42', true,
    { ...host, signHumanApproval: async () => new Uint8Array() }), /DER/);
  await assert.rejects(approveOnce(pending(), '42', true,
    { ...host, signatureAlgorithm: 'ed25519' }), /Ed25519/);
  assert.equal(signs, 2);
  assert.equal(submissions, 0);
});

test('expiry or rollback before creation during human signing prevents submission', async () => {
  const request = pending();
  let submissions = 0;
  const originalNow = Date.now;
  for (const changedTime of [request.envelope.created_at - 1, request.envelope.expires_at]) {
    const host: TrustedHost = {
      signatureAlgorithm: 'ed25519', keyId: 'host', machineId: 'test-machine',
      signHumanApproval: async () => {
        Date.now = () => changedTime * 1000;
        return new Uint8Array(64);
      },
      submitApproval: async () => { submissions++; },
    };
    try { await assert.rejects(approveOnce(request, '42', false, host), /expired/); }
    finally { Date.now = originalNow; }
  }
  assert.equal(submissions, 0);
});
