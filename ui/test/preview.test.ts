import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import vm from 'node:vm';

test('preview rejects approvals and remembers only trusted human output preferences', async () => {
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/demo.ts'], {
    env: { ...process.env, BROKER_SOCKET: '/nonexistent.sock', APPROVAL_KEY: '/nonexistent.pem' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    await Promise.race([
      once(child.stdout, 'data'),
      once(child, 'exit').then(() => { throw new Error('Preview failed to start'); }),
      new Promise<never>((_, reject) => { setTimeout(() => reject(new Error('Startup timed out')), 5000).unref(); }),
    ]);
    const origin = 'http://127.0.0.1:7351';
    const script = await (await fetch(`${origin}/host.js`)).text();
    const csrf = /csrf="([a-f0-9]+)"/.exec(script)?.[1];
    assert.ok(csrf);
    const saved = new Map<string,string>();
    function host(blocked = false) {
      const messages: Record<string,unknown>[] = [];
      const frame = { contentWindow: { postMessage(value: Record<string,unknown>) { messages.push(value); } } };
      let load: ((event:{preventDefault():void})=>Promise<void>)|undefined;
      let receive: ((event:{origin:string;source:unknown;data:unknown})=>Promise<void>)|undefined;
      const elements: Record<string,unknown> = {
        '#card':frame,'#status':{textContent:''},'#id':{value:'fixture'},
        '#load':{addEventListener(_type:string,handler:typeof load){load=handler;}},
      };
      vm.runInNewContext(script,{
        location:{origin},document:{querySelector:(selector:string)=>elements[selector]},
        window:{addEventListener(_type:string,handler:typeof receive){receive=handler;}},
        localStorage:{getItem(key:string){if(blocked)throw Error('Blocked');return saved.get(key)??null;},setItem(key:string,value:string){if(blocked)throw Error('Blocked');saved.set(key,value);}},
        fetch:async()=>({ok:true,json:async()=>({envelope:{id:'fixture'}})}),
      });
      return {
        async preference(){assert.ok(load);await load({preventDefault(){}});return messages.at(-1)?.['share_output_preference'];},
        async change(value:unknown,source:unknown=frame.contentWindow){assert.ok(receive);await receive({origin,source,data:{type:'approval-output-preference',share_output:value}});},
      };
    }
    const first=host();assert.equal(await first.preference(),false);
    await first.change(true);assert.equal(await host().preference(),true);
    const next=host();await next.change(false);assert.equal(await host().preference(),false);
    await next.change(true,{});await next.change('true');assert.equal(await host().preference(),false);
    const unavailable=host(true);assert.equal(await unavailable.preference(),false);
    await unavailable.change(true);assert.equal(await host(true).preference(),false);
    const response = await fetch(`${origin}/approve`, {
      method: 'POST', headers: { Origin: origin, 'X-Approval-CSRF': csrf, 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 'pending-request', number: '42' }),
    });
    assert.equal(response.status, 403);
    assert.match((await response.json() as { error: string }).error, /Preview only/);
  } finally {
    if (child.exitCode === null) { const exited = once(child, 'exit'); child.kill(); await exited; }
  }
});
