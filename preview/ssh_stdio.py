"""Unprivileged stdin/stdout carrier to the container's loopback SSH daemon."""
import socket
import sys
import threading

if len(sys.argv)!=2 or not sys.argv[1].isdigit() or not 1<=int(sys.argv[1])<=65535:raise ValueError('one loopback port required')
with socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=5) as connection:
    connection.settimeout(None)
    def upload() -> None:
        try:
            while data := sys.stdin.buffer.read1(16384):
                connection.sendall(data)
        except (OSError, ValueError):
            pass
        finally:
            try: connection.shutdown(socket.SHUT_WR)
            except OSError: pass
    threading.Thread(target=upload,daemon=True).start()
    try:
        while data := connection.recv(16384):
            sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
    except (OSError, ValueError):
        pass
