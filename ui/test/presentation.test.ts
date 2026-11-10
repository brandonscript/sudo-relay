import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { commandPreview,quoteArgument,remainingTime } from '../src/presentation.js';

test('readable command preserves literal argument boundaries including shell syntax',()=>{
  const args=['simple','two words','','a\'b','|','$(printf injected)','semi;colon','quote"inside','\\path','雪'];
  const script = `printf '%s\\0' ${args.map(quoteArgument).join(' ')}`;
  const result=execFileSync('/bin/sh',['-c',script]).toString().split('\0');result.pop();
  assert.deepEqual(result,args);
  assert.equal(commandPreview({kind:'argv',argv:['/usr/bin/systemctl','restart','nginx']}),'/usr/bin/systemctl restart nginx');
  assert.notEqual(commandPreview({kind:'argv',argv:['/bin/echo','a b']}),commandPreview({kind:'argv',argv:['/bin/echo','a','b']}));
  assert.notEqual(commandPreview({kind:'argv',argv:['/bin/echo','x','|','id']}),'/bin/echo x | id');
  assert.equal(commandPreview({kind:'script',interpreter:'/bin/sh',script:'printf hello\nprintf world'}),'printf hello\nprintf world');
});
test('expiry display reflects signed expiry rather than assuming five minutes',()=>{
  assert.equal(remainingTime(400,100),'5:00 remaining');
  assert.equal(remainingTime(1000,100),'15:00 remaining');
  assert.equal(remainingTime(3700,100),'1h 0m remaining');
  assert.equal(remainingTime(101,100),'0:01 remaining');
  assert.equal(remainingTime(100,100),'Expired');
  assert.equal(remainingTime(90,100),'Expired');
});
