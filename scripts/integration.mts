/** Safe integration: development broker executes only as this unprivileged user. */
import assert from 'node:assert/strict';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { createInterface } from 'node:readline';
import { approveOnce, type TrustedHost } from '../ui/src/adapter.js';
import { brokerCall } from '../ui/src/broker.js';
import { parsePending } from '../ui/src/protocol.js';

if (process.getuid?.() === 0) throw new Error('Integration test requires non-root');
const root = resolve(import.meta.dirname, '..');
const temp = mkdtempSync(join(tmpdir(), 'sudo-relay-'));
const config = join(temp, 'config.json'), socket = join(temp, 'run/broker.sock');
const broker = join(root, 'target/debug/broker');
const children: ChildProcess[] = [];
const pause = async (): Promise<void> => new Promise(r => setTimeout(r, 20));
function object(value: unknown): Record<string, unknown> { assert.ok(typeof value === 'object' && value !== null); return value as Record<string, unknown>; }
function launch(): ChildProcess { const child = spawn(broker, ['--development', 'serve', config], { stdio: ['ignore', 'ignore', 'inherit'] }); children.push(child); return child; }
async function waitReady(): Promise<void> { const end = Date.now() + 5000; while (!existsSync(socket)) { assert.ok(Date.now() < end); await pause(); } }
try {
  execFileSync(broker, ['--development', 'init', config, join(temp, 'state'), socket, String(process.getuid?.()), String(process.getuid?.()), String(process.getgid?.())]);
  const keys = generateKeyPairSync('ed25519');
  const der = keys.publicKey.export({ type: 'spki', format: 'der' });
  execFileSync(broker, ['--development', 'pair', config, 'integration', der.subarray(-32).toString('hex')]);
  launch(); await waitReady();
  const mcp = spawn(join(root, 'target/debug/mcp-server'), [socket, join(root, 'ui/dist/card.html')], { stdio: ['pipe', 'pipe', 'inherit'] });
  children.push(mcp);
  let sequence = 0;
  const awaiting = new Map<number, { resolve(value: Record<string, unknown>): void; reject(error: Error): void }>();
  const lines = createInterface({ input: mcp.stdout });
  lines.on('line', line => { const message = object(JSON.parse(line)); if (typeof message['id'] !== 'number') return; const entry = awaiting.get(message['id']); if (!entry) return; awaiting.delete(message['id']); if ('error' in message) entry.reject(new Error(JSON.stringify(message['error']))); else { const result = object(message['result']); if (result['isError'] === true) entry.reject(new Error(JSON.stringify(result))); else entry.resolve(result); } });
  const rpc = async (method: string, params: unknown = {}): Promise<Record<string, unknown>> => {
    const id = ++sequence;
    return new Promise((resolve, reject) => { const timer = setTimeout(() => { awaiting.delete(id); reject(new Error(`MCP timeout: ${method}`)); }, 10000); awaiting.set(id, { resolve: value => { clearTimeout(timer); resolve(value); }, reject: e => { clearTimeout(timer); reject(e); } }); mcp.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`); });
  };
  await rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'integration', version: '1' } });
  mcp.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  const tools = await rpc('tools/list');
  const names = (tools['tools'] as { name: string }[]).map(t => t.name).sort();
  assert.deepEqual(names, ['cancel_execution', 'execution_status', 'request_execution']);
  const resource = await rpc('resources/read', { uri: 'ui://sudo-relay/approval.html' });
  assert.ok(JSON.stringify(resource).includes('Approve once'));
  const requested = await rpc('tools/call', { name: 'request_execution', arguments: { spec: { command: { kind: 'argv', argv: ['/usr/bin/printf', 'hello signed world'] }, env: {}, reason: 'Safe integration', timeout_secs: 1 } } });
  const pending = parsePending(requested['structuredContent']);
  const machine = object(JSON.parse(readFileSync(config, 'utf8')))['machine_id']; assert.equal(typeof machine, 'string');
  let lastApproval: unknown;
  const host: TrustedHost = { keyId: 'integration', machineId: machine as string,
    signHumanApproval: async bytes => sign(null, bytes, keys.privateKey),
    submitApproval: approval => { lastApproval = approval; return brokerCall(socket, approval); } };
  await assert.rejects(approveOnce(pending, '00', true, host));
  const status = object(await brokerCall(socket, { method: 'execution_status', id: pending.envelope.id }));
  assert.equal(status['state'], 'pending');
  await approveOnce(pending, pending.envelope.number, true, host);
  await assert.rejects(brokerCall(socket, lastApproval), /not pending/);
  console.log('Replay of the exact signed approval rejected: request is not pending.');
  const end = Date.now() + 5000;
  while (true) {
    const state = object(await brokerCall(socket, { method: 'execution_status', id: pending.envelope.id }));
    if (state['state'] === 'complete') { assert.equal(object(state['outcome'])['stdout'], 'hello signed world'); break; }
    assert.ok(Date.now() < end); await pause();
  }
  const repeated = await rpc('tools/call', { name: 'request_execution', arguments: { spec: pending.envelope.spec } });
  const repeatedPending = parsePending(repeated['structuredContent']);
  assert.notEqual(repeatedPending.envelope.id,pending.envelope.id);
  assert.equal(object(await brokerCall(socket,{method:'execution_status',id:repeatedPending.envelope.id}))['state'],'pending');
  await assert.rejects(brokerCall(socket,{...object(lastApproval),id:repeatedPending.envelope.id}),/invalid approval signature/);
  await brokerCall(socket,{method:'cancel_execution',id:repeatedPending.envelope.id});
  console.log('Identical command resubmitted: new request remains pending; old signature cannot approve it.');
  const privateRequest = parsePending(await brokerCall(socket, { method: 'request_execution', spec: {
    command: { kind: 'script', interpreter: '/bin/sh', script: 'printf PRIVATE_STDOUT; printf PRIVATE_STDERR >&2; exit 7' },
    output_needed: true,
  } }));
  await approveOnce(privateRequest, privateRequest.envelope.number, false, host);
  const privateEnd = Date.now() + 5000;
  while (true) {
    const reply = await rpc('tools/call', { name: 'execution_status', arguments: { id: privateRequest.envelope.id } });
    assert.ok(reply['structuredContent'], JSON.stringify(reply));
    const state = object(reply['structuredContent']);
    if (state['state'] === 'complete') {
      assert.equal(state['output_shared'], false);
      assert.equal(object(state['outcome'])['exit_code'], 7);
      assert.equal(object(state['outcome'])['stdout'], '');
      assert.equal(object(state['outcome'])['stderr'], '');
      assert.ok(!JSON.stringify(reply).includes('PRIVATE_'));
      break;
    }
    assert.ok(Date.now() < privateEnd); await pause();
  }
  const cancelled = await rpc('tools/call', { name: 'request_execution', arguments: { spec: { command: { kind: 'argv', argv: ['/usr/bin/printf', 'never execute'] } } } });
  const second = parsePending(cancelled['structuredContent']);
  await rpc('tools/call', { name: 'cancel_execution', arguments: { id: second.envelope.id } });
  await assert.rejects(approveOnce(second, second.envelope.number, true, host));
  const keyPath = join(temp, 'host.pem');
  writeFileSync(keyPath, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const demo = spawn(process.execPath, ['--import', join(root, 'ui/node_modules/tsx/dist/loader.mjs'), join(root, 'ui/src/demo.ts')],
    { env: { ...process.env, BROKER_SOCKET: socket, APPROVAL_KEY: keyPath, APPROVAL_KEY_ID: 'integration', APPROVAL_MACHINE_ID: machine as string }, stdio: ['ignore', 'ignore', 'inherit'] });
  children.push(demo);
  const origin = 'http://127.0.0.1:7351';
  const readyEnd = Date.now()+5000;
  let hostScript = '';
  while (!hostScript) {
    try { hostScript = await (await fetch(origin+'/host.js')).text(); } catch { assert.ok(Date.now()<readyEnd); await pause(); }
  }
  const csrf = /csrf="([a-f0-9]{64})"/.exec(hostScript)?.[1]; assert.ok(csrf);
  const third = parsePending(await brokerCall(socket, { method: 'request_execution', spec: { command: { kind: 'argv', argv: ['/usr/bin/printf', 'cancel through host'] } } }));
  const body = JSON.stringify({ id: third.envelope.id });
  const foreign = await fetch(origin+'/cancel', { method: 'POST', headers: { Origin: 'https://foreign.invalid', 'Content-Type': 'application/json', 'X-Approval-CSRF': csrf }, body });
  assert.equal(foreign.status,403);
  const cancelledByHost = await fetch(origin+'/cancel', { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json', 'X-Approval-CSRF': csrf }, body });
  assert.equal(cancelledByHost.status,200);
  assert.equal(object(await brokerCall(socket, { method: 'execution_status', id: third.envelope.id }))['state'],'cancelled');
  mcp.stdin.end();
  console.log('Integration passed: real MCP stdio → broker → TypeScript CBOR verification/signing → one execution; replay, cancellation, and unsupported approval denied.');
} finally {
  for (const child of children) { child.kill(); await new Promise<void>(r => { if (child.exitCode !== null || child.signalCode !== null) r(); else child.once('exit', () => r()); }); }
  rmSync(temp, { recursive: true, force: true });
}
