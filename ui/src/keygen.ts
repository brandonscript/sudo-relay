import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const destination = process.argv[2];
if (!destination) throw new Error('Usage: npm run keygen -- /protected/path/host-key.pem');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
writeFileSync(destination, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
const der = publicKey.export({ type: 'spki', format: 'der' });
console.log(`Public key (hex): ${der.subarray(-32).toString('hex')}`);
