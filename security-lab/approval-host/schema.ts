import { z } from 'zod';

export const modeSchema = z.enum(['passkey', 'session']);
export type Mode = z.infer<typeof modeSchema>;
const encoded = z.string().min(1).max(32768).regex(/^[A-Za-z0-9_-]+$/);
const credentialBase = {
  id: encoded, rawId: encoded, type: z.literal('public-key'),
  clientExtensionResults: z.object({}).strict(),
  authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
};
export const registrationSchema = z.object({
  ...credentialBase,
  response: z.object({
    clientDataJSON: encoded, attestationObject: encoded,
    transports: z.array(z.enum(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'])).max(8).optional(),
    publicKey: encoded.optional(), publicKeyAlgorithm: z.number().int().optional(), authenticatorData: encoded.optional(),
  }).strict(),
}).strict();
export const authenticationSchema = z.object({
  ...credentialBase,
  response: z.object({
    clientDataJSON: encoded, authenticatorData: encoded, signature: encoded,
    userHandle: encoded.optional(),
  }).strict(),
}).strict();
export const decisionSchema = z.object({ id: z.string().uuid(), number: z.string().regex(/^\d{2}$/), share_output: z.boolean() }).strict();
export const finishSchema = decisionSchema.extend({ response: authenticationSchema }).strict();
export const idSchema = z.object({ id: z.string().uuid() }).strict();
export const emptySchema = z.object({}).strict();
export const stateSchema = z.object({
  mode: modeSchema, csrf: z.string(), enrolled: z.boolean(),
  pending: z.unknown().nullable(), state: z.enum(['none', 'pending', 'approved', 'denied', 'expired']),
  receipt: z.object({ id: z.string(), digest: z.string(), mode: modeSchema, share_output: z.boolean() }).nullable(),
  receipts: z.number().int().nonnegative(),
}).strict();
export type State = z.infer<typeof stateSchema>;
export const registrationOptionsSchema = z.object({
  challenge: encoded, rp: z.object({ id: z.string(), name: z.string() }),
  user: z.object({ id: encoded, name: z.string(), displayName: z.string() }),
  pubKeyCredParams: z.array(z.object({ type: z.literal('public-key'), alg: z.number().int() })),
  timeout: z.number(), attestation: z.literal('none'),
  authenticatorSelection: z.object({ userVerification: z.literal('required'), residentKey: z.enum(['preferred', 'required', 'discouraged']) }),
});
export const authenticationOptionsSchema = z.object({
  challenge: encoded, rpId: z.string(), userVerification: z.literal('required'), timeout: z.number(),
  allowCredentials: z.array(z.object({ id: encoded, type: z.literal('public-key') })),
});
