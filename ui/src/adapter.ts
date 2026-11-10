import { type Approval, type Pending, verifyPending, validateDecision, approvalPayload } from './protocol.js';

/** Supplied by the trusted chat host, never by an MCP tool or model message. */
export interface TrustedHost {
  readonly keyId: string;
  readonly machineId: string;
  signHumanApproval(bytes: Uint8Array): Promise<Uint8Array>;
  submitApproval(approval: Approval): Promise<unknown>;
}
export async function approveOnce(value: unknown, number: string, shareOutput: boolean, host: TrustedHost): Promise<unknown> {
  const pending: Pending = await verifyPending(value);
  if (pending.envelope.machine_id !== host.machineId) throw new Error('Request targets an unpaired machine');
  validateDecision(pending, number);
  const { hex } = await import('./protocol.js');
  const signature = await host.signHumanApproval(approvalPayload(pending, shareOutput));
  if (signature.length !== 64) throw new Error('Expected an Ed25519 signature');
  return host.submitApproval({ method: 'approve', id: pending.envelope.id, key_id: host.keyId, number, share_output: shareOutput, signature: hex(signature) });
}
