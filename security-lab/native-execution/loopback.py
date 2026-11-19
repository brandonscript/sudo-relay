"""Local byte carrier only. Native SSH authenticates the container over this channel."""
from __future__ import annotations
import re
import socket
import socketserver
import subprocess
import threading
from typing import Any


class LoopbackRelay:
    def __init__(self, docker: str, container: str, command: list[str] | None = None, port: int = 0, connections: int = 1, idle_timeout: float | None = 15) -> None:
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}',container):
            raise ValueError('invalid container identifier')
        if type(port) is not int or not 0<=port<=65535 or type(connections) is not int or not 1<=connections<=4:
            raise ValueError('invalid relay bounds')
        carrier=command or [docker,'exec','-i','--user','11003:11003',container,
            'python3','-I','/integration/ssh_stdio.py']
        self.children: set[subprocess.Popen[bytes]] = set()
        self.lock = threading.Lock()
        self.slot = threading.BoundedSemaphore(connections)
        relay = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                if not relay.slot.acquire(timeout=2):
                    return
                try:
                    self.transfer()
                finally:
                    relay.slot.release()

            def transfer(self) -> None:
                child = subprocess.Popen(carrier,stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                with relay.lock: relay.children.add(child)
                connection: socket.socket = self.request
                connection.settimeout(idle_timeout)
                def upload() -> None:
                    assert child.stdin
                    try:
                        while data := connection.recv(16384):
                            child.stdin.write(data);child.stdin.flush()
                    except (OSError, ValueError):
                        pass
                    finally:
                        try: child.stdin.close()
                        except OSError: pass
                thread = threading.Thread(target=upload,daemon=True);thread.start()
                try:
                    assert child.stdout
                    while data := child.stdout.read1(16384):
                        connection.sendall(data)
                except (OSError, ValueError):
                    pass
                finally:
                    try: connection.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                    if child.poll() is None: child.kill()
                    child.wait(timeout=5)
                    thread.join(timeout=1)
                    if child.stdout: child.stdout.close()
                    with relay.lock: relay.children.discard(child)
        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            block_on_close = False
        self.server = Server(('127.0.0.1',port),Handler)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)

    def __enter__(self) -> LoopbackRelay:
        self.thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
        with self.lock:
            children = list(self.children)
        for child in children:
            if child.poll() is None: child.kill()
            child.wait(timeout=5)
