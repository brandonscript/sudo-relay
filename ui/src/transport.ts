import type { IncomingHttpHeaders } from 'node:http';

export function isTrustedRequest(headers: IncomingHttpHeaders, expectedHost: string, expectedOrigin: string, csrf: string, mutation: boolean): boolean {
  return headers.host === expectedHost && (!mutation || headers.origin === expectedOrigin && headers['x-approval-csrf'] === csrf && headers['content-type'] === 'application/json');
}
