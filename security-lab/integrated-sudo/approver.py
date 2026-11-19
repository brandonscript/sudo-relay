"""Software test approver or raw socket client, always running as its real UID."""
from __future__ import annotations
import json
import socket
import struct
import subprocess
import sys
import tempfile
from typing import Any


def call(path: str, request: dict[str, Any], disconnect: bool = False) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(path)
        _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0:
            raise RuntimeError('test approver requires root broker peer')
        connection.sendall(json.dumps(request).encode() + b'\n')
        if disconnect:
            return {'disconnected': True}
        with connection.makefile('rb') as stream:
            line = stream.readline(4 * 1024 * 1024)
            if not line.endswith(b'\n'):
                raise RuntimeError('missing bounded reply')
            return json.loads(line)


def main() -> None:
    path, operation = sys.argv[1:3]
    data = json.loads(sys.stdin.buffer.read(65537))
    if operation in ('submit', 'disconnect'):
        print(json.dumps(call(path, data, operation == 'disconnect')))
        return
    if operation != 'sign':
        raise RuntimeError('unsupported fixture operation')
    status = call(path, {'method': 'execution_status', 'id': data['id']})
    if not status['ok'] or status['value']['state'] != 'pending':
        raise RuntimeError('no pending broker request')
    envelope = status['value']['pending']['envelope']
    # Deliberate negative controls alter only the signed copy, never the broker request.
    if data.get('alter_command'):
        envelope['spec']['command']['argv'] = ['/usr/bin/touch', '/lab/effect_b']
    decision = {'envelope': envelope, 'share_output': data['share_output'], 'receipt': data.get('receipt', False)}
    payload = subprocess.check_output(['/usr/local/bin/integrated-sudo-lab', 'decision-payload'],
                                      input=json.dumps(decision).encode(), timeout=5)
    with tempfile.NamedTemporaryFile(dir='/lab/human') as source:
        source.write(bytes.fromhex(payload.decode())); source.flush()
        signature = subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey',
                                             '/lab/human/key.pem', '-in', source.name], timeout=5)
    print(json.dumps({'method': 'approve', 'id': data['id'], 'key_id': 'human',
                      'number': envelope['number'], 'signature': signature.hex(), 'share_output': data['share_output']}))


if __name__ == '__main__':
    main()
