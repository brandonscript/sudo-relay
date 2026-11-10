import { App } from '@modelcontextprotocol/ext-apps';
import { type Pending, verifyPending, validateDecision } from './protocol.js';
import { commandPreview, remainingTime } from './presentation.js';

function element<T extends HTMLElement>(id: string): T {
  const value = document.querySelector<T>(`#${id}`);
  if (!value) throw new Error(`Missing approval element: ${id}`);
  return value;
}
const app = new App({ name: 'sudo-relay', version: '0.1.0' });
const number = element<HTMLInputElement>('number');
const shareOutput = element<HTMLInputElement>('share-output');
let outputPreference = false;
const approve = element<HTMLButtonElement>('approve');
const cancel = element<HTMLButtonElement>('cancel');
const result = element<HTMLParagraphElement>('result');
let current: Pending | undefined;
let busy = false;
let decision: 'approve' | 'deny' | undefined;
let hostOrigin: string | undefined;

function update(): void {
  const expired = !!current && Date.now() >= current.envelope.expires_at * 1000;
  cancel.disabled = busy || !current || expired;
  approve.disabled = busy || !hostOrigin || !current || expired || number.value !== current.envelope.number;
  number.disabled = busy || !current || expired;
  shareOutput.disabled = busy || !current || expired;
  element('digit-first').textContent = number.value[0] ?? '·';
  element('digit-second').textContent = number.value[1] ?? '·';
  if (current) element('expiry').textContent = remainingTime(current.envelope.expires_at);
}
number.addEventListener('input', () => { number.value = number.value.replace(/[^0-9]/g, '').slice(0, 2); update(); });
shareOutput.addEventListener('change', () => {
  if (!current || !hostOrigin || busy) { shareOutput.checked = outputPreference; return; }
  outputPreference = shareOutput.checked;
  window.parent.postMessage({ type: 'approval-output-preference', share_output: outputPreference }, hostOrigin);
});
setInterval(update, 1000);
async function show(value: unknown): Promise<void> {
  try {
    current = await verifyPending(value);
    shareOutput.checked = outputPreference;
    element('output-needed').hidden = !current.envelope.spec.output_needed;
    number.value = ''; busy = false; decision = undefined;
    approve.textContent = 'Approve once'; cancel.textContent = 'Deny'; approve.hidden = false; cancel.hidden = false;
    const { command, env } = current.envelope.spec;
    element('command-label').textContent = command.kind === 'script' ? `Script · ${command.interpreter} · run as root` : 'Command · run as root';
    element('command').textContent = commandPreview(command);
    element('machine').textContent = current.envelope.machine_id;
    element('reason').textContent = current.envelope.spec.reason || 'No explanation supplied.';
    element('request-details').textContent = JSON.stringify({ machine_id: current.envelope.machine_id, request_id: current.envelope.id, working_directory: '/', environment: env, timeout_secs: current.envelope.spec.timeout_secs, expires_at: new Date(current.envelope.expires_at * 1000).toISOString() }, null, 2);
    element('challenge').textContent = current.envelope.number;
    result.textContent = hostOrigin ? '' : 'This chat host needs a trusted signing adapter before approval.';
    update();
  } catch (error: unknown) {
    current = undefined;
    element('command').textContent = ''; element('request-details').textContent = '';
    element('machine').textContent = ''; element('reason').textContent = ''; element('challenge').textContent = '—'; element('expiry').textContent = 'Unavailable';
    result.textContent = error instanceof Error ? error.message : 'Invalid request'; update();
  }
}
app.ontoolresult = params => { void show(params.structuredContent); };

// Host capability is delivered through a separate channel, never a model tool result.
window.addEventListener('message', (event: MessageEvent<unknown>) => {
  if (event.source !== window.parent || typeof event.data !== 'object' || event.data === null) return;
  const data = event.data as Record<string, unknown>;
  if (data.type === 'approval-host-init' && event.origin === location.origin && typeof data.origin === 'string' && data.origin === event.origin) {
    hostOrigin = event.origin;
    if (typeof data.share_output_preference === 'boolean') outputPreference = data.share_output_preference;
    if ('pending' in data) void show(data.pending);
  }
  if (data.type === 'approval-host-result' && event.origin === hostOrigin && typeof data.message === 'string' && current && data.id === current.envelope.id && decision) {
    result.textContent = data.message;
    if (data.ok === true) {
      const approved = decision === 'approve';
      approve.textContent = approved ? 'Approved' : 'Approve once';
      cancel.textContent = approved ? 'Deny' : 'Denied';
      approve.hidden = !approved; cancel.hidden = approved;
      current = undefined; element('expiry').textContent = approved ? 'Approved' : 'Denied';
    }
    decision = undefined;
    busy = false; update();
  }
});
cancel.addEventListener('click', () => {
  if (!current || !hostOrigin || busy) { result.textContent = 'This host cannot cancel requests. Ask the chat to cancel the request ID.'; return; }
  decision = 'deny'; busy = true; update();
  window.parent.postMessage({ type: 'approval-human-cancel', id: current.envelope.id }, hostOrigin);
});
element<HTMLFormElement>('confirmation-form').addEventListener('submit', event => {
  event.preventDefault();
  if (!current || !hostOrigin || busy) { result.textContent = 'No trusted approval adapter is available. Nothing was approved.'; return; }
  try { validateDecision(current, number.value); }
  catch (error: unknown) { result.textContent = error instanceof Error ? error.message : 'Approval rejected'; return; }
  decision = 'approve'; busy = true; update();
  window.parent.postMessage({ type: 'approval-human-decision', id: current.envelope.id, number: number.value, share_output: shareOutput.checked }, hostOrigin);
});
if (window.parent !== window && !new URLSearchParams(location.search).has('reference')) {
  void app.connect().catch(() => { result.textContent = 'Unable to connect to chat host. Nothing was approved.'; });
}
update();
