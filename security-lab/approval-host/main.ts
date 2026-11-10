import { startLab } from './server.js';
import { modeSchema } from './schema.js';

const mode = modeSchema.parse(process.env['APPROVAL_MODE'] ?? 'passkey');
const lab = await startLab({ mode });
console.log(`Approval experiment (${mode}). Creates receipts only; no commands execute.\nOpen this one-use setup link in your browser:\n${lab.setupURL}`);
let closing = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  if (!closing) { closing = true; void lab.close().then(() => process.exit(0)); }
});
