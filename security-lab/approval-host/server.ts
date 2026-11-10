import { createHash, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse,
  type WebAuthnCredential,
} from '@simplewebauthn/server';
import { z } from 'zod';
import { approvalPayload, hex, payload, parsePending, type Envelope, type Pending } from '../../ui/src/protocol.js';
import { isTrustedRequest } from '../../ui/src/transport.js';
import { decisionSchema, emptySchema, finishSchema, idSchema, registrationSchema, type Mode, type State } from './schema.js';

const rowSchema = z.object({
  id: z.string(), pending: z.string(), state: z.enum(['pending', 'approved', 'denied', 'expired']),
  challenge: z.string().nullable(), decision: z.string().nullable(), share: z.number().nullable(),
  digest: z.string().nullable(), mode: z.enum(['passkey', 'session']), attempts: z.number(),
});
const hash = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const equal = (a: string, b: string): boolean => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
function requireTopLevel(data: string): void {
  z.object({ crossOrigin: z.literal(false).optional(), topOrigin: z.never().optional() })
    .parse(JSON.parse(Buffer.from(data, 'base64url').toString('utf8')) as unknown);
}

async function readBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    size += bytes.length;
    if (size > 65536) throw new Error('Request too large');
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}

export async function startLab(options: { mode: Mode; database?: string; now?: () => number; port?: number }) {
  if (process.getuid?.() === 0) throw new Error('Run this experiment as an ordinary user');
  const directory = options.database ? undefined : mkdtempSync(join(tmpdir(), 'sudo-relay-approval-'));
  const db = new DatabaseSync(options.database ?? join(directory!, 'receipts.sqlite'));
  db.exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
    CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, pending TEXT NOT NULL, state TEXT NOT NULL,
      challenge TEXT, decision TEXT, share INTEGER, digest TEXT, mode TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
    UPDATE requests SET state='denied', challenge=NULL WHERE state='pending';`);
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const bootstrap = randomBytes(32).toString('hex'), session = randomBytes(32).toString('hex'), csrf = randomBytes(32).toString('hex');
  const machine = `experiment-${randomUUID()}`;
  let bootstrapped = false, currentId: string | undefined;
  let credential: WebAuthnCredential | undefined;
  let registration: { challenge: string; expires: number } | undefined;
  let origin = '', host = '';
  const row = (id: string) => rowSchema.parse(db.prepare('SELECT * FROM requests WHERE id=?').get(id));
  function pendingRow(id: string) {
    const record = row(id), pending = parsePending(JSON.parse(record.pending) as unknown);
    if (record.state === 'pending' && now() >= pending.envelope.expires_at) {
      db.prepare("UPDATE requests SET state='expired', challenge=NULL WHERE id=? AND state='pending'").run(id);
      throw new Error('Request expired');
    }
    if (record.state !== 'pending') throw new Error('Request is no longer pending');
    return { record, pending };
  }
  function decision(body: unknown) {
    const input = decisionSchema.parse(body);
    const { record, pending } = pendingRow(input.id);
    if (input.number !== pending.envelope.number) {
      db.prepare("UPDATE requests SET attempts=attempts+1, state=CASE WHEN attempts>=2 THEN 'denied' ELSE state END, challenge=NULL WHERE id=?").run(input.id);
      throw new Error('Confirmation number does not match');
    }
    return { input, record, pending, bytes: hex(approvalPayload(pending, input.share_output)) };
  }
  function consume(id: string, challenge: string | null, bytes: string, share: boolean) {
    pendingRow(id);
    const digest = hash(Buffer.from(bytes, 'hex'));
    const result = db.prepare("UPDATE requests SET state='approved', digest=?, share=?, decision=?, challenge=NULL WHERE id=? AND state='pending' AND challenge IS ?")
      .run(digest, Number(share), bytes, id, challenge);
    if (result.changes !== 1) throw new Error('Approval already used or superseded');
    return { id, digest, mode: options.mode, share_output: share };
  }
  function state(): State {
    if (currentId) { try { pendingRow(currentId); } catch { /* Reading terminal state is allowed. */ } }
    const record = currentId ? row(currentId) : undefined;
    const count = z.object({ count: z.number() }).parse(db.prepare("SELECT COUNT(*) AS count FROM requests WHERE state='approved'").get());
    return { mode: options.mode, csrf, enrolled: !!credential, pending: record ? JSON.parse(record.pending) as unknown : null,
      state: record?.state ?? 'none', receipts: count.count,
      receipt: record?.state === 'approved' ? { id: record.id, digest: record.digest!, mode: record.mode, share_output: record.share === 1 } : null };
  }
  const server = createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store'); response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    const reply = (code: number, value: unknown) => { response.writeHead(code, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value)); };
    try {
      const path = new URL(request.url ?? '/', origin).pathname;
      const mutation = request.method === 'POST';
      const expectedCSRF = path === '/session' ? bootstrap : csrf;
      if (!isTrustedRequest(request.headers, host, origin, expectedCSRF, mutation)) { reply(403, { error: 'Untrusted request origin' }); return; }
      if (request.method === 'GET' && (path === '/' || path === '/client.js')) {
        response.writeHead(200, { 'Content-Type': path === '/' ? 'text/html' : 'text/javascript' });
        response.end(readFileSync(new URL(path === '/' ? './index.html' : './dist/client.js', import.meta.url))); return;
      }
      if (mutation && path === '/session') {
        emptySchema.parse(await readBody(request));
        if (bootstrapped) { reply(403, { error: 'Setup link already used' }); return; }
        bootstrapped = true;
        // shortcut: loopback HTTP only; remote use needs HTTPS, Secure cookies and real account enrollment.
        response.setHeader('Set-Cookie', `approval_lab=${session}; HttpOnly; SameSite=Strict; Path=/`);
        reply(200, {}); return;
      }
      const cookie = request.headers.cookie?.split(';').map(value => value.trim()).find(value => value.startsWith('approval_lab='))?.slice(13) ?? '';
      if (!bootstrapped || !equal(cookie, session)) { reply(403, { error: 'Open the setup link from this experiment' }); return; }
      if (request.method === 'GET' && path === '/state') { reply(200, state()); return; }
      if (!mutation) { reply(404, { error: 'Not found' }); return; }
      const body = await readBody(request);
      if (path === '/new') {
        emptySchema.parse(body);
        if (currentId && state().state === 'pending') throw new Error('Finish the pending request first');
        const count = z.object({ count: z.number() }).parse(db.prepare('SELECT COUNT(*) AS count FROM requests').get());
        if (count.count >= 100) throw new Error('Experiment limit reached; restart with a fresh ledger');
        const envelope: Envelope = { version: 2, machine_id: machine, id: randomUUID(), nonce: randomBytes(32).toString('hex'),
          created_at: now(), expires_at: now() + 300, number: String(randomInt(10, 100)),
          spec: { command: { kind: 'argv', argv: ['/usr/bin/printf', 'Approval experiment only'] }, env: {},
            reason: 'Create a test receipt. This command will not execute.', timeout_secs: 30, output_needed: false } };
        const bytes = payload(envelope);
        const pending: Pending = { envelope, signing_payload: hex(bytes), digest: hash(bytes) };
        db.prepare("INSERT INTO requests(id,pending,state,mode) VALUES(?,?,'pending',?)").run(envelope.id, JSON.stringify(pending), options.mode);
        currentId = envelope.id; reply(200, state());
      } else if (path === '/deny') {
        const { id } = idSchema.parse(body); pendingRow(id);
        db.prepare("UPDATE requests SET state='denied', challenge=NULL WHERE id=? AND state='pending'").run(id);
        reply(200, state());
      } else if (path === '/register/options') {
        emptySchema.parse(body);
        if (options.mode !== 'passkey' || credential || registration) throw new Error('Enrollment unavailable; restart to retry setup');
        const generated = await generateRegistrationOptions({ rpName: 'sudo-relay experiment', rpID: 'localhost', userName: 'experiment',
          userID: randomBytes(32), attestationType: 'none', supportedAlgorithmIDs: [-7],
          authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' } });
        if (credential || registration) throw new Error('Enrollment already started');
        registration = { challenge: generated.challenge, expires: now() + 300 }; reply(200, generated);
      } else if (path === '/register/finish') {
        const input = registrationSchema.parse(body), attempt = registration;
        if (options.mode !== 'passkey' || credential || !attempt || now() >= attempt.expires) throw new Error('Enrollment unavailable');
        requireTopLevel(input.response.clientDataJSON);
        if (input.id !== input.rawId) throw new Error('Credential ID mismatch');
        const verified = await verifyRegistrationResponse({ response: { id: input.id, rawId: input.rawId, type: input.type,
          clientExtensionResults: input.clientExtensionResults, response: { clientDataJSON: input.response.clientDataJSON, attestationObject: input.response.attestationObject } }, expectedChallenge: attempt.challenge,
          expectedOrigin: origin, expectedRPID: 'localhost', requireUserVerification: true });
        if (!verified.verified || !verified.registrationInfo || credential || registration !== attempt || now() >= attempt.expires) throw new Error('Registration rejected');
        credential = verified.registrationInfo.credential; registration = undefined; reply(200, state());
      } else if (path === '/approve/session') {
        if (options.mode !== 'session') throw new Error('This experiment requires a passkey');
        const { input, bytes } = decision(body);
        reply(200, consume(input.id, null, bytes, input.share_output));
      } else if (path === '/approve/options') {
        if (options.mode !== 'passkey' || !credential) throw new Error('Enroll a passkey first');
        const { input, bytes } = decision(body);
        const generated = await generateAuthenticationOptions({ rpID: 'localhost', userVerification: 'required',
          allowCredentials: [{ id: credential.id }] });
        pendingRow(input.id);
        db.prepare("UPDATE requests SET challenge=?, decision=?, share=? WHERE id=? AND state='pending'")
          .run(generated.challenge, bytes, Number(input.share_output), input.id);
        reply(200, generated);
      } else if (path === '/approve/finish') {
        const { response: assertion, ...fields } = finishSchema.parse(body);
        const { input, record, bytes } = decision(fields);
        const key = credential;
        if (options.mode !== 'passkey' || !key || !record.challenge || record.decision !== bytes || assertion.id !== key.id) throw new Error('Decision or credential changed');
        requireTopLevel(assertion.response.clientDataJSON);
        if (assertion.id !== assertion.rawId) throw new Error('Credential ID mismatch');
        const verified = await verifyAuthenticationResponse({ response: { id: assertion.id, rawId: assertion.rawId, type: assertion.type,
          clientExtensionResults: assertion.clientExtensionResults, response: { clientDataJSON: assertion.response.clientDataJSON,
            authenticatorData: assertion.response.authenticatorData, signature: assertion.response.signature } }, expectedChallenge: record.challenge,
          expectedOrigin: origin, expectedRPID: 'localhost', credential: key, requireUserVerification: true });
        if (!verified.verified || credential !== key) throw new Error('Passkey verification failed');
        const receipt = consume(input.id, record.challenge, bytes, input.share_output);
        key.counter = verified.authenticationInfo.newCounter; reply(200, receipt);
      } else reply(404, { error: 'Not found' });
    } catch (error: unknown) { reply(400, { error: error instanceof Error ? error.message : 'Request rejected' }); }
  });
  server.requestTimeout = 5000; server.headersTimeout = 5000; server.maxConnections = 16;
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(options.port ?? 0, '127.0.0.1', resolve); });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing local listener');
  host = `localhost:${address.port}`; origin = `http://${host}`;
  return { origin, setupURL: `${origin}/#${bootstrap}`, close: async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    db.close(); if (directory) rmSync(directory, { recursive: true, force: true });
  } };
}
