import { encode } from 'cborg';

export type Command = { kind: 'argv'; argv: string[] } | { kind: 'script'; interpreter: '/bin/sh' | '/bin/bash'; script: string };
export interface ExecutionSpec { command: Command; env: Record<string, string>; reason: string; timeout_secs: number; output_needed: boolean }
export interface Envelope { version: 2; machine_id: string; id: string; nonce: string; created_at: number; expires_at: number; number: string; spec: ExecutionSpec }
export interface Pending { envelope: Envelope; signing_payload: string; digest: string }
export interface Approval { method: 'approve'; id: string; key_id: string; number: string; signature: string; share_output: boolean }

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('Expected an object');
  return value as Record<string, unknown>;
}
function string(value: unknown): string {
  if (typeof value !== 'string') throw new Error('Expected text');
  return value;
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new Error('Expected a boolean');
  return value;
}
function integer(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error('Expected a nonnegative safe integer');
  return value;
}
export function hex(bytes: Uint8Array): string { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
export function unhex(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) throw new Error('Invalid hexadecimal value');
  return Uint8Array.from(value.match(/../g) ?? [], byte => Number.parseInt(byte, 16));
}
export function payload(envelope: Envelope): Uint8Array {
  const spec = envelope.spec;
  const command = spec.command.kind === 'argv' ? ['argv', spec.command.argv] : ['script', spec.command.interpreter, spec.command.script];
  return encode(['sudo-relay/request/v2', envelope.machine_id, envelope.id, envelope.nonce,
    envelope.created_at, envelope.expires_at, envelope.number, command,
    Object.entries(spec.env).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0), spec.reason, spec.timeout_secs, spec.output_needed]);
}
export function approvalPayload(pending: Pending, shareOutput: boolean): Uint8Array {
  return encode(['sudo-relay/decision/v2', unhex(pending.signing_payload), boolean(shareOutput)]);
}
export function parsePending(value: unknown): Pending {
  const pending = object(value), raw = object(pending.envelope), spec = object(raw.spec), command = object(spec.command);
  let parsedCommand: Command;
  if (command.kind === 'argv' && Array.isArray(command.argv) && command.argv.length > 0) {
    parsedCommand = { kind: 'argv', argv: command.argv.map(string) };
    if (!parsedCommand.argv[0]?.startsWith('/')) throw new Error('Executable must be an absolute path');
  } else if (command.kind === 'script' && (command.interpreter === '/bin/sh' || command.interpreter === '/bin/bash')) {
    parsedCommand = { kind: 'script', interpreter: command.interpreter, script: string(command.script) };
  } else throw new Error('Invalid command');
  const env: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [key, val] of Object.entries(object(spec.env))) env[key] = string(val);
  if (raw.version !== 2) throw new Error('Unsupported protocol version');
  const envelope: Envelope = { version: 2, machine_id: string(raw.machine_id), id: string(raw.id), nonce: string(raw.nonce),
    created_at: integer(raw.created_at), expires_at: integer(raw.expires_at), number: string(raw.number),
    spec: { command: parsedCommand, env, reason: string(spec.reason), timeout_secs: integer(spec.timeout_secs), output_needed: boolean(spec.output_needed) } };
  if (!/^[1-9][0-9]$/.test(envelope.number)) throw new Error('Invalid confirmation number');
  if (envelope.expires_at <= envelope.created_at || envelope.spec.timeout_secs < 1 || envelope.spec.timeout_secs > 86400) throw new Error('Invalid request limits');
  const result = { envelope, signing_payload: string(pending.signing_payload), digest: string(pending.digest) };
  if (result.signing_payload !== hex(payload(envelope))) throw new Error('Signing payload does not match displayed request');
  if (!/^[0-9a-f]{64}$/.test(result.digest)) throw new Error('Invalid request digest');
  return result;
}
export async function verifyPending(value: unknown, now = Math.floor(Date.now() / 1000)): Promise<Pending> {
  const pending = parsePending(value);
  const bytes = payload(pending.envelope);
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(bytes));
  if (hex(new Uint8Array(digest)) !== pending.digest) throw new Error('Request digest mismatch');
  if (now >= pending.envelope.expires_at || now < pending.envelope.created_at) throw new Error('Request expired or not yet valid');
  return pending;
}
export function validateDecision(pending: Pending, number: string, now = Math.floor(Date.now() / 1000)): void {
  if (number !== pending.envelope.number) throw new Error('Confirmation number does not match');
  if (now < pending.envelope.created_at || now >= pending.envelope.expires_at) throw new Error('Request expired or not yet valid');
}
