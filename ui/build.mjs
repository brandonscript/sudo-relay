import { build } from 'esbuild';
import { readFileSync, writeFileSync } from 'node:fs';
await build({ entryPoints: ['src/card.ts'], bundle: true, format: 'esm', minify: true, outfile: 'dist/card.js' });
const script = readFileSync('dist/card.js', 'utf8').replaceAll('</script', '<\\/script');
const html = readFileSync('card.html', 'utf8').replace('<!-- APPROVAL_SCRIPT -->', `<script type="module">${script}</script>`);
writeFileSync('dist/card.html', html);
