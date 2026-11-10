import { createConnection } from 'node:net';

export async function brokerCall(socketPath: string, request: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    const decoder = new TextDecoder();
    let data = '';
    socket.setTimeout(10_000, () => socket.destroy(new Error('Broker connection timed out')));
    socket.on('connect', () => socket.write(`${JSON.stringify(request)}\n`));
    socket.on('error', reject);
    socket.on('end', () => { if (!data.includes('\n')) reject(new Error('Incomplete broker response')); });
    socket.on('data', (chunk: Buffer) => {
      data += decoder.decode(chunk, { stream: true });
      if (data.length > 16_777_216) { socket.destroy(new Error('Broker response too large')); return; }
      const end = data.indexOf('\n');
      if (end < 0) return;
      socket.end();
      try {
        const value: unknown = JSON.parse(data.slice(0, end));
        if (typeof value !== 'object' || value === null || !('ok' in value)) throw new Error('Invalid broker reply');
        if (value.ok === true && 'value' in value) resolve(value.value);
        else throw new Error('error' in value && typeof value.error === 'string' ? value.error : 'Broker request failed');
      } catch (error: unknown) { reject(error); }
    });
  });
}
