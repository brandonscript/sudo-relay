import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import ts from 'typescript';
import * as protocol from '../src/protocol.js';
import * as presentation from '../src/presentation.js';

class Element {
  textContent = ''; value = ''; disabled = false; hidden = false; checked = false;
  listeners = new Map<string, (event?: { preventDefault(): void }) => void>();
  addEventListener(type: string, handler: (event?: { preventDefault(): void }) => void): void { this.listeners.set(type,handler); }
}
async function card(preference?: boolean, outputNeeded = false) {
  const html = readFileSync(new URL('../card.html',import.meta.url),'utf8');
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(match=>[match[1] as string,new Element()]));
  const get = (id:string):Element => { const element=elements.get(id); assert.ok(element,id); return element; };
  const parent = { postMessage: (value:unknown) => sent.push(value) };
  const sent: unknown[] = [];
  let message: ((event:Record<string,unknown>)=>void)|undefined;
  const context = {
    exports:{}, document:{querySelector:(selector:string)=>get(selector.slice(1))},
    window:{parent,addEventListener:(_type:string,handler:typeof message)=>{message=handler;}},
    location:{origin:'http://127.0.0.1:7351',search:'?reference'},setInterval:()=>0,Date,URLSearchParams,
    require:(name:string):unknown=>{
      if(name==='@modelcontextprotocol/ext-apps')return {App:class {connect(){return Promise.resolve();}}};
      if(name==='./protocol.js')return protocol;
      if(name==='./presentation.js')return presentation;
      throw new Error(name);
    },
  };
  const source=readFileSync(new URL('../src/card.ts',import.meta.url),'utf8');
  vm.runInNewContext(ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText,context);
  const now=Math.floor(Date.now()/1000);
  const envelope:protocol.Envelope={version:2,machine_id:'test-machine',id:'test-request',nonce:'test-nonce',created_at:now-1,expires_at:now+300,number:'42',spec:{command:{kind:'argv',argv:['/usr/bin/printf','hello']},env:{},reason:'Test',timeout_secs:1,output_needed:outputNeeded}};
  const payload=protocol.payload(envelope);
  const pending={envelope,signing_payload:protocol.hex(payload),digest:createHash('sha256').update(payload).digest('hex'),share_output:true,share_output_preference:true};
  const receive=(data:unknown)=>{ assert.ok(message);message({source:parent,origin:context.location.origin,data}); };
  receive({type:'approval-host-init',origin:context.location.origin,pending,share_output_preference:preference});
  const deadline=Date.now()+1000;
  while(get('challenge').textContent!=='42'){assert.ok(Date.now()<deadline);await new Promise(resolve=>setTimeout(resolve,5));}
  return {get,sent,receive,pending};
}
test('successful approval keeps only a disabled Approved button; failed or stale replies do not close the card',async()=>{
  const {get,sent,receive}=await card();
  get('number').value='42';get('number').listeners.get('input')?.();
  assert.equal(get('approve').disabled,false);
  get('confirmation-form').listeners.get('submit')?.({preventDefault(){}});
  assert.equal(sent.length,1);
  assert.equal(get('approve').textContent,'Approve once');
  receive({type:'approval-host-result',id:'different-request',ok:true,message:'Stale'});
  assert.equal(get('cancel').hidden,false);
  receive({type:'approval-host-result',id:'test-request',ok:false,message:'Signature rejected'});
  assert.equal(get('approve').disabled,false);assert.equal(get('cancel').hidden,false);
  get('confirmation-form').listeners.get('submit')?.({preventDefault(){}});
  receive({type:'approval-host-result',id:'test-request',ok:true,message:'Approved'});
  assert.equal(get('approve').textContent,'Approved');assert.equal(get('approve').hidden,false);
  assert.equal(get('approve').disabled,true);assert.equal(get('cancel').hidden,true);
});
test('successful denial keeps only a disabled Denied button',async()=>{
  const {get,receive}=await card();
  get('cancel').listeners.get('click')?.();
  assert.equal(get('cancel').textContent,'Deny');
  receive({type:'approval-host-result',id:'test-request',ok:true,message:'Denied'});
  assert.equal(get('cancel').textContent,'Denied');assert.equal(get('cancel').hidden,false);
  assert.equal(get('cancel').disabled,true);assert.equal(get('approve').hidden,true);
});

test('Enter/form submission requires the correct code and cannot submit twice while pending',async()=>{
  const {get,sent}=await card();
  let prevented=0;
  const submit=()=>get('confirmation-form').listeners.get('submit')?.({preventDefault(){prevented++;}});
  for(const code of ['', '4', '24']) {get('number').value=code;submit();}
  assert.equal(sent.length,0);
  get('number').value='42';submit();
  assert.equal(sent.length,1);
  submit();assert.equal(sent.length,1);
  assert.equal(prevented,5);
});

test('sharing defaults off, uses host preference, and agent need never forces it on', async()=>{
  for(const preference of [undefined,false,true]) {
    const {get,sent}=await card(preference,true);
    assert.equal(get('share-output').checked,preference===true);
    assert.equal(get('share-output').disabled,false);
    assert.equal(get('output-needed').hidden,false);
    get('share-output').checked=false;get('share-output').listeners.get('change')?.();
    get('number').value='42';get('confirmation-form').listeners.get('submit')?.({preventDefault(){}});
    const decision=sent.at(-1) as Record<string,unknown>;
    assert.equal(decision['share_output'],false);
    assert.equal(decision['type'],'approval-human-decision');
    assert.equal(get('share-output').disabled,true);
  }
});
test('checked sharing is sent explicitly and denial never grants it', async()=>{
  const {get,sent}=await card(false);
  assert.equal(get('output-needed').hidden,true);
  get('share-output').checked=true;get('share-output').listeners.get('change')?.();
  const preference=sent.at(-1) as Record<string,unknown>;
  assert.equal(preference['type'],'approval-output-preference');assert.equal(preference['share_output'],true);
  get('number').value='42';get('confirmation-form').listeners.get('submit')?.({preventDefault(){}});
  assert.equal((sent.at(-1) as Record<string,unknown>)['share_output'],true);
  const denied=await card(true,true);denied.get('cancel').listeners.get('click')?.();
  assert.equal((denied.sent.at(-1) as Record<string,unknown>)['type'],'approval-human-cancel');
});
