import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { parsePending, verifyPending, type Pending } from '../../ui/src/protocol.js';
import { commandPreview, remainingTime } from '../../ui/src/presentation.js';
import { authenticationOptionsSchema, registrationOptionsSchema, stateSchema, type State } from './schema.js';

function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const found = document.getElementById(id); if (!found) throw new Error(`Missing ${id}`); return found as T;
}
const share = element<HTMLInputElement>('share'), number = element<HTMLInputElement>('number');
let state: State | undefined, pending: Pending | undefined, busy = false;
try { share.checked = localStorage.getItem('approval.shareOutput') === 'true'; } catch { share.checked = false; }
share.addEventListener('change', () => { try { localStorage.setItem('approval.shareOutput', String(share.checked)); } catch { /* Preference storage is optional. */ } });
async function api(path: string, body?: unknown, token = state?.csrf): Promise<unknown> {
  const response = await fetch(path, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Approval-CSRF': token ?? '' }, body: JSON.stringify(body) });
  const value: unknown = await response.json();
  if (!response.ok) {
    const message = typeof value === 'object' && value !== null && 'error' in value && typeof value.error === 'string' ? value.error : 'Request failed';
    throw new Error(message);
  }
  return value;
}
function render(): void {
  const active = !!pending && state?.state === 'pending' && Date.now() < pending.envelope.expires_at * 1000;
  element<HTMLButtonElement>('new').disabled = busy || !state || active || (state.mode === 'passkey' && !state.enrolled);
  element<HTMLButtonElement>('enroll').disabled = busy || !state || state.enrolled;
  element('enroll').hidden = state?.mode !== 'passkey';
  element<HTMLButtonElement>('approve').disabled = busy || !active;
  element<HTMLButtonElement>('deny').disabled = busy || !active;
  share.disabled = busy || !active; number.disabled = busy || !active;
  element('approve').hidden = state?.state === 'denied';
  element('deny').hidden = state?.state === 'approved';
  element('approve').textContent = state?.state === 'approved' ? 'Approved' : 'Approve once';
  element('deny').textContent = state?.state === 'denied' ? 'Denied' : 'Deny';
  if (pending) element('expiry').textContent = state?.state === 'pending' ? remainingTime(pending.envelope.expires_at) : state?.state ?? '';
}
async function refresh(): Promise<void> {
  state = stateSchema.parse(await api('/state'));
  if (state.pending !== null) {
    const parsed = parsePending(state.pending);
    pending = await verifyPending(state.pending, parsed.envelope.created_at);
    element('request').hidden = false;
    element('machine').textContent = pending.envelope.machine_id;
    element('command').textContent = commandPreview(pending.envelope.spec.command);
    element('reason').textContent = pending.envelope.spec.reason;
    element('challenge').textContent = pending.envelope.number;
    element('request-id').textContent = `Request: ${pending.envelope.id}`;
  }
  element('mode').textContent = state.mode === 'passkey' ? 'Passkey approval' : 'Session approval · no passkey';
  element('warning').textContent = state.mode === 'passkey'
    ? 'Each approval requires your enrolled authenticator. You still need a review page and device the agent cannot control.'
    : 'Anyone controlling this browser session can approve. The number and button do not prove a human was involved.';
  element('receipt').textContent = state.receipt ? `Test receipt ${state.receipt.digest} · output sharing ${state.receipt.share_output ? 'on' : 'off'} · total receipts ${state.receipts}` : '';
  render();
}
async function perform(action: () => Promise<void>): Promise<void> {
  if (busy) return; busy = true; render(); element('message').textContent = '';
  try { await action(); }
  catch (error: unknown) { element('message').textContent = error instanceof Error ? error.message : 'Approval failed'; }
  finally { try { await refresh(); } catch { /* Keep the original failure visible. */ } busy = false; render(); }
}
element('enroll').addEventListener('click', () => void perform(async () => {
  const optionsJSON = registrationOptionsSchema.parse(await api('/register/options', {}));
  const response = await startRegistration({ optionsJSON });
  await api('/register/finish', response);
  element('message').textContent = 'Test passkey enrolled for this run.';
}));
element('new').addEventListener('click', () => void perform(async () => { await api('/new', {}); number.value = ''; }));
element('deny').addEventListener('click', () => void perform(async () => {
  if (!pending) return; await api('/deny', { id: pending.envelope.id }); element('message').textContent = 'Denied. No receipt created.';
}));
element('approval').addEventListener('submit', event => {
  event.preventDefault();
  void perform(async () => {
    if (!pending || !state) throw new Error('No pending request');
    const decision = { id: pending.envelope.id, number: number.value, share_output: share.checked };
    if (state.mode === 'passkey') {
      const optionsJSON = authenticationOptionsSchema.parse(await api('/approve/options', decision));
      const response = await startAuthentication({ optionsJSON });
      await api('/approve/finish', { ...decision, response });
    } else await api('/approve/session', decision);
    element('message').textContent = 'Approved. Test receipt created; nothing executed.';
  });
});
setInterval(render, 1000);
void (async () => {
  const token = location.hash.slice(1); history.replaceState(null, '', '/');
  try { if (token) await api('/session', {}, token); await refresh(); }
  catch (error: unknown) { element('message').textContent = error instanceof Error ? error.message : 'Unable to open experiment'; }
})();
