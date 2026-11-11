import test from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
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
  const host: TrustedHost = { keyId: 'host', machineId: 'test-machine', signHumanApproval: async bytes => { calls++; return sign(null, bytes, keys.privateKey); }, submitApproval: async value => { approval = value; return { state: 'consumed' }; } };
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
    const host:TrustedHost={keyId:'host',machineId:'test-machine',signHumanApproval:async bytes=>sign(null,bytes,keys.privateKey),submitApproval:async approval=>{captured=approval;}};
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
