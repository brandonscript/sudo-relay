import { App, applyDocumentTheme, applyHostStyleVariables, type McpUiHostContext } from '@modelcontextprotocol/ext-apps';
import { remainingTime } from './presentation.js';

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('Invalid probe response');
  return value as Record<string, unknown>;
}
function string(value: unknown): string {
  if (typeof value !== 'string') throw new Error('Missing probe field');
  return value;
}
function element<T extends HTMLElement>(id: string): T {
  const value = document.querySelector<T>(`#${id}`);
  if (!value) throw new Error(`Missing element: ${id}`);
  return value;
}
const app = new App({ name: 'sudo-relay-host-probe', version: '0.1.7' }, { availableDisplayModes: ['inline'] });
const input = element<HTMLInputElement>('number');
const approve = element<HTMLButtonElement>('approve');
const deny = element<HTMLButtonElement>('deny');
const status = element('status');
let pending: { id: string; capability: string; number: string; expires: number } | undefined;
let busy = false;
function applyHostContext(context: McpUiHostContext): void {
  if (context.theme) applyDocumentTheme(context.theme);
  if (context.styles?.variables) applyHostStyleVariables(context.styles.variables);
}
app.onhostcontextchanged = applyHostContext;
function update(): void {
  element('digit-first').textContent = input.value[0] || '·';
  element('digit-second').textContent = input.value[1] || '·';
  if (pending) element('expiry').textContent = remainingTime(pending.expires);
  const available = !!pending && Date.now() < pending.expires * 1000 && !busy;
  approve.disabled = !available || input.value !== pending?.number;
  deny.disabled = !available;
  input.disabled = !available;
  if (pending && Date.now() >= pending.expires * 1000) status.textContent = 'Expired. Ask for a new test request.';
}
function show(value: unknown, metadata: unknown): void {
  const response = object(value);
  const request = object(response.request);
  const hidden = object(object(metadata).probe);
  const id = string(request.id);
  if (hidden.id !== id || request.state !== 'pending' || request.share_output !== false ||
      typeof request.expires_at !== 'number' || !Number.isSafeInteger(request.expires_at) ||
      !/^[0-9]{2}$/.test(string(hidden.number)) || !/^[a-f0-9]{64}$/.test(string(hidden.capability)) ||
      !/^[a-f0-9]{32}$/.test(string(hidden.canary))) throw new Error('Invalid pending probe');
  element('machine').textContent = `${string(request.machine)} · ${string(request.operating_system)} · ${string(request.account)}`;
  element('command').textContent = string(request.command);
  element('digest').textContent = string(request.digest);
  element('request-id').textContent = id;
  element('instance').textContent = string(response.instance);
  element('canary').textContent = string(hidden.canary);
  element('challenge').textContent = string(hidden.number);
  pending = { id, capability: string(hidden.capability), number: string(hidden.number), expires: request.expires_at };
  approve.textContent = 'Approve once'; deny.textContent = 'Deny'; approve.hidden = false; deny.hidden = false;
  delete approve.dataset.decided; delete deny.dataset.decided;
  input.value = ''; busy = false; status.textContent = 'Ready. This records a receipt only.'; update();
}
app.ontoolresult = params => {
  // Decision responses also arrive here on some hosts; only initialize from a creation result.
  if (!params._meta || !('probe' in params._meta)) return;
  try { show(params.structuredContent, params._meta); }
  catch (error: unknown) { pending = undefined; status.textContent = error instanceof Error ? error.message : 'Invalid probe'; update(); }
};
async function decide(approved: boolean): Promise<void> {
  if (!pending || busy || Date.now() >= pending.expires * 1000 || (approved && input.value !== pending.number)) return;
  const request = pending;
  busy = true; status.textContent = 'Waiting for the test server…'; update();
  try {
    const response = await app.callServerTool({
      name: approved ? 'record_probe_approval' : 'cancel_probe',
      arguments: approved ? { id: request.id, number: input.value, capability: request.capability } : { id: request.id },
    });
    if (response.isError) throw new Error('Server rejected the test decision. Check probe_status; no automatic retry.');
    const result = object(response.structuredContent);
    const record = object(result.request);
    if (record.id !== request.id || record.state !== (approved ? 'approved' : 'denied')) throw new Error('Unexpected receipt; inspect probe_status.');
    if (pending !== request) return;
    pending = undefined;
    element('expiry').textContent = approved ? 'Approved' : 'Denied';
    (approved ? approve : deny).dataset.decided = '';
    approve.textContent = 'Approved'; deny.textContent = 'Denied'; approve.hidden = !approved; deny.hidden = approved;
    status.textContent = approved ? 'Receipt recorded. Nothing executed.' : 'Denied. Nothing executed.';
  } catch (error: unknown) {
    status.textContent = error instanceof Error ? error.message : 'Unable to reach test server';
  } finally { busy = false; update(); }
}
input.addEventListener('input', () => { input.value = input.value.replace(/[^0-9]/g, '').slice(0, 2); update(); });
element<HTMLFormElement>('form').addEventListener('submit', event => { event.preventDefault(); void decide(true); });
deny.addEventListener('click', () => { void decide(false); });
setInterval(update, 1000);
update();
void app.connect().then(() => {
  const context = app.getHostContext();
  if (context) applyHostContext(context);
}).catch(() => { pending = undefined; status.textContent = 'This host did not connect the MCP Apps bridge.'; update(); });
