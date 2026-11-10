"""Send one broker request as the current container UID; no signing or retries."""
from __future__ import annotations

import json
import socket
import sys


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python /fixture/rpc.py \'{"method":"execution_status","id":"example"}\'')
    request: object = json.loads(sys.argv[1])
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect('/lab/run/broker.sock')
        connection.sendall(json.dumps(request).encode() + b'\n')
        with connection.makefile('rb') as response:
            line = response.readline(16 * 1024 * 1024 + 1)
        if not line.endswith(b'\n') or len(line) > 16 * 1024 * 1024:
            raise RuntimeError('Incomplete or oversized response')
        print(json.dumps(json.loads(line), indent=2))


if __name__ == '__main__':
    main()
