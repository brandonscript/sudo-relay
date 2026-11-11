import { type Approval, type Pending, verifyPending, validateDecision, approvalPayload } from './protocol.js';

/** Supplied by the trusted chat host, never by an MCP tool or model message. */
export interface TrustedHost {
  readonly keyId: string;
  readonly machineId: string;
  readonly signatureAlgorithm: 'ed25519' | 'p256-sha256';
  signHumanApproval(bytes: Uint8Array): Promise<Uint8Array>;
  submitApproval(approval: Approval): Promise<unknown>;
}
export async function approveOnce(value: unknown, number: string, shareOutput: boolean, host: TrustedHost): Promise<unknown> {
  const { keyId, machineId, signatureAlgorithm } = host;
  if (signatureAlgorithm !== 'ed25519' && signatureAlgorithm !== 'p256-sha256') throw new Error('Unsupported enrolled signature algorithm');
  const pending: Pending = await verifyPending(value);
  if (pending.envelope.machine_id !== machineId) throw new Error('Request targets an unpaired machine');
  validateDecision(pending, number);
  const { hex } = await import('./protocol.js');
  const signature = await host.signHumanApproval(approvalPayload(pending, shareOutput));
  if (signatureAlgorithm === 'ed25519' && signature.length !== 64) throw new Error('Expected a 64-byte Ed25519 signature');
  // The broker parses and verifies DER using its enrolled key; this is only a transport bound.
  if (signatureAlgorithm === 'p256-sha256' && (signature.length === 0 || signature.length > 72)) throw new Error('Expected a bounded P-256 DER signature');
  validateDecision(pending, number);
  return host.submitApproval({ method: 'approve', id: pending.envelope.id, key_id: keyId, number, share_output: shareOutput, signature: hex(signature) });
}
