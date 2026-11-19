import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

test('native review card initializes the Apps bridge without an approval route', async () => {
  let connected = 0;
  let mode: unknown;
  let theme: unknown;
  const source = readFileSync(new URL('../src/native-review.ts', import.meta.url), 'utf8');
  const html = readFileSync(new URL('../native-review.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /<(?:button|input|form)\b/);
  vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText, {
    exports: {},
    require: () => ({
      App: class {
        constructor(_identity: unknown, options: unknown) { mode = options; }
        connect() { connected++; return Promise.resolve(); }
        getHostContext() { return { theme: 'dark' }; }
      },
      applyDocumentTheme: (value: unknown) => { theme = value; },
      applyHostStyleVariables: () => {},
    }),
    document: { querySelector: () => { throw new Error('unexpected failure'); } },
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(connected, 1);
  assert.equal(JSON.stringify(mode), JSON.stringify({ availableDisplayModes: ['inline'] }));
  assert.equal(theme, 'dark');
});
