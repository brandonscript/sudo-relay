import { build } from 'esbuild';
import { readFileSync, writeFileSync } from 'node:fs';
for (const name of ['card', 'host-probe', 'native-review']) {
  await build({ entryPoints: [`src/${name}.ts`], bundle: true, format: 'esm', minify: true, outfile: `dist/${name}.js` });
  const script = readFileSync(`dist/${name}.js`, 'utf8').replaceAll('</script', '<\\/script');
  const html = readFileSync(`${name}.html`, 'utf8').replace('<!-- APPROVAL_SCRIPT -->', () => `<script type="module">${script}</script>`);
  writeFileSync(`dist/${name}.html`, html);
  if (name === 'native-review') writeFileSync('../preview/approval.html', html);
}
