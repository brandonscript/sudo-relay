import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { brokerCall } from './broker.js';
import { verifyPending } from './protocol.js';
import { isTrustedRequest } from './transport.js';

const socketPath = process.env['BROKER_SOCKET'];
if (!socketPath) throw new Error('Set BROKER_SOCKET');
const port = 7351, origin = `http://127.0.0.1:${port}`, csrf = randomBytes(32).toString('hex');
const card = readFileSync(fileURLToPath(new URL('../card.html', import.meta.url)), 'utf8')
  .replace('<!-- APPROVAL_SCRIPT -->', '<script type="module" src="/card.js"></script>');
const index = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reference chat host</title><style>body{font:16px system-ui;margin:1rem}iframe{width:100%;height:85vh;border:1px solid #aaa}input,button{font:inherit;min-height:44px}</style><h1>Reference chat host</h1><p>Preview only. This host cannot approve or execute commands. Enter a broker request ID.</p><form id="load"><label>Request ID <input id="id" required></label><button>Load request</button></form><p id="status" role="status"></p><iframe id="card" title="Root approval card" src="/card?reference"></iframe><script type="module" src="/host.js"></script></html>`;
const hostJs = `let outputPreference=false;try{outputPreference=localStorage.getItem('approval.shareOutput')==='true'}catch{};const origin=location.origin, csrf=${JSON.stringify(csrf)},frame=document.querySelector('#card'),status=document.querySelector('#status');let pending;document.querySelector('#load').addEventListener('submit',async event=>{event.preventDefault();try{const r=await fetch('/pending?id='+encodeURIComponent(document.querySelector('#id').value));const data=await r.json();if(!r.ok)throw Error(data.error);pending=data;frame.contentWindow.postMessage({type:'approval-host-init',origin,pending,share_output_preference:outputPreference},origin);}catch(e){status.textContent=String(e)}});window.addEventListener('message',async event=>{if(event.origin!==origin||event.source!==frame.contentWindow||!['approval-human-decision','approval-human-cancel','approval-output-preference'].includes(event.data?.type))return;if(event.data.type==='approval-output-preference'){if(typeof event.data.share_output==='boolean'){outputPreference=event.data.share_output;try{localStorage.setItem('approval.shareOutput',String(outputPreference))}catch{}}return;}try{if(!pending||event.data.id!==pending.envelope.id)throw Error('Request changed');const r=await fetch(event.data.type==='approval-human-cancel'?'/cancel':'/approve',{method:'POST',headers:{'Content-Type':'application/json','X-Approval-CSRF':csrf},body:JSON.stringify(event.data)});const data=await r.json();frame.contentWindow.postMessage({type:'approval-host-result',id:event.data.id,ok:r.ok,message:r.ok?(event.data.type==='approval-human-cancel'?'Request cancelled. Nothing was approved.':'Approval submitted. Check execution status in chat.'):data.error},origin);}catch(e){frame.contentWindow.postMessage({type:'approval-host-result',id:event.data.id,ok:false,message:String(e)},origin)}});`;
createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store'); response.setHeader('X-Content-Type-Options', 'nosniff'); response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'`);
  const reply = (code: number, value: unknown): void => { response.writeHead(code, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value)); };
  try {
    const mutation = request.method === 'POST';
    if (!isTrustedRequest(request.headers, `127.0.0.1:${port}`, origin, csrf, mutation)) { reply(403, { error: 'Untrusted request origin' }); return; }
    const url = new URL(request.url ?? '/', origin);
    if (request.method === 'GET' && url.pathname === '/') { response.writeHead(200, { 'Content-Type': 'text/html' }); response.end(index); }
    else if (request.method === 'GET' && url.pathname === '/card') { response.writeHead(200, { 'Content-Type': 'text/html' }); response.end(card); }
    else if (request.method === 'GET' && url.pathname === '/host.js') { response.writeHead(200, { 'Content-Type': 'text/javascript' }); response.end(hostJs); }
    else if (request.method === 'GET' && url.pathname === '/card.js') { response.writeHead(200, { 'Content-Type': 'text/javascript' }); response.end(readFileSync(fileURLToPath(new URL('../dist/card.js', import.meta.url)))); }
    else if (request.method === 'GET' && url.pathname === '/pending') {
      const id = url.searchParams.get('id'); if (!id) throw new Error('Request ID required');
      const state = await brokerCall(socketPath, { method: 'execution_status', id });
      if (typeof state !== 'object' || state === null || !('pending' in state)) throw new Error('Request is not pending');
      reply(200, await verifyPending(state.pending));
    } else if (mutation && url.pathname === '/cancel') {
      let body = ''; request.setEncoding('utf8');
      for await (const chunk of request) { body += String(chunk); if (body.length > 4096) throw new Error('Request too large'); }
      const value: unknown = JSON.parse(body);
      if (typeof value !== 'object' || value === null || !('id' in value) || typeof value.id !== 'string') throw new Error('Invalid cancellation');
      reply(200, await brokerCall(socketPath, { method: 'cancel_execution', id: value.id }));
    } else if (mutation && url.pathname === '/approve') {
      reply(403, { error: 'Preview only. Approval requires a protected human-authorized signer.' });
    } else reply(404, { error: 'Not found' });
  } catch (error: unknown) { reply(400, { error: error instanceof Error ? error.message : 'Request failed' }); }
}).listen(port, '127.0.0.1', () => console.log(`Preview host: ${origin}. Signing is disabled.`));
