"""Four real MCP processes, inert Unix backends: routing only, no signer or executor."""
from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import selectors
import socketserver
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
assert os.geteuid() != 0, "Run as an ordinary user"


def object_value(value: object) -> dict[str, object]:
    assert isinstance(value, dict), "Expected a JSON object"
    return value


class Backend(socketserver.UnixStreamServer):
    label: str
    state: str = "absent"
    calls: int = 0


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server = self.server
        assert isinstance(server, Backend)
        request = object_value(json.loads(self.rfile.readline(65537)))
        server.calls += 1
        method = request["method"]
        if method == "request_execution":
            assert server.state == "absent"
            server.state = "pending"
        elif method == "cancel_execution":
            assert request["id"] == "colliding-request" and server.state == "pending"
            server.state = "cancelled"
        else:
            assert method == "execution_status" and request["id"] == "colliding-request"
        reply = {"ok": True, "value": {"id": "colliding-request", "state": server.state,
                 "fixture_target": server.label}}
        self.wfile.write(json.dumps(reply).encode() + b"\n")


class Client:
    def __init__(self, socket: Path, html: Path) -> None:
        self.process = subprocess.Popen([str(ROOT / "target/debug/mcp-server"), str(socket), str(html)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        assert self.process.stdin and self.process.stdout
        self.sequence = 0
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)

    def rpc(self, method: str, params: dict[str, object]) -> dict[str, object]:
        self.sequence += 1
        assert self.process.stdin and self.process.stdout
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.sequence,
                                            "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        assert self.selector.select(10), "MCP response timed out"
        response = object_value(json.loads(self.process.stdout.readline()))
        assert response["id"] == self.sequence and "error" not in response
        return object_value(response["result"])

    def call(self, name: str, arguments: dict[str, object]) -> dict[str, object]:
        return self.rpc("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        self.selector.close()
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


def stop(server: Backend, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
    assert not thread.is_alive()


with tempfile.TemporaryDirectory(prefix="sr-target-", dir="/tmp") as scratch, ExitStack() as cleanup:
    root = Path(scratch)
    clients: dict[str, Client] = {}
    servers: dict[str, tuple[Backend, threading.Thread]] = {}
    for alias in ["home", "build", "backup", "test"]:
        socket = root / f"{alias}.sock"
        server = Backend(str(socket), Handler)
        server.label = alias
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        cleanup.callback(stop, server, thread)
        servers[alias] = (server, thread)
        html = root / f"{alias}.html"
        html.write_text(f"<p>Inert resource fixture: {alias}</p>")
        client = Client(socket, html)
        cleanup.callback(client.close)
        clients[alias] = client
        version = "2025-11-25" if alias in ("home", "backup") else "2025-06-18"
        initialized = client.rpc("initialize", {"protocolVersion": version, "capabilities": {},
                                  "clientInfo": {"name": f"routing-{alias}", "version": "1"}})
        assert initialized["protocolVersion"] == version
        assert client.process.stdin
        client.process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        client.process.stdin.flush()
        tools = client.rpc("tools/list", {})["tools"]
        assert isinstance(tools, list)
        assert sorted(object_value(tool)["name"] for tool in tools) == ["cancel_execution", "execution_status", "request_execution"]
        listed = client.rpc("resources/list", {})
        resources = listed["resources"]
        assert isinstance(resources, list) and len(resources) == 1
        assert object_value(resources[0])["uri"] == "ui://sudo-relay/approval.html"
        assert object_value(resources[0])["mimeType"] == "text/html;profile=mcp-app"
        resource = client.rpc("resources/read", {"uri": "ui://sudo-relay/approval.html"})
        assert f"Inert resource fixture: {alias}" in json.dumps(resource)
        assert "resultType" not in resource
        result = client.call("request_execution", {"spec": {"command": {"kind": "argv", "argv": ["/usr/bin/printf", "never run"]},
                                                              "reason": "Routing fixture only", "timeout_secs": 1}})
        assert object_value(result["structuredContent"])["fixture_target"] == alias

    for alias, client in clients.items():
        result = object_value(client.call("execution_status", {"id": "colliding-request"})["structuredContent"])
        assert result["fixture_target"] == alias and result["state"] == "pending"
    clients["home"].call("cancel_execution", {"id": "colliding-request"})
    for alias, client in clients.items():
        result = object_value(client.call("execution_status", {"id": "colliding-request"})["structuredContent"])
        assert result["state"] == ("cancelled" if alias == "home" else "pending")
    stop(*servers["home"])
    counts = {alias: server.calls for alias, (server, _) in servers.items()}
    assert clients["home"].call("execution_status", {"id": "colliding-request"})["isError"] is True
    assert counts == {alias: server.calls for alias, (server, _) in servers.items()}, "Offline target fell back to another backend"
    for alias in ["build", "backup", "test"]:
        result = object_value(clients[alias].call("execution_status", {"id": "colliding-request"})["structuredContent"])
        assert result["fixture_target"] == alias and result["state"] == "pending"
    print("Four MCP instances: resource/request routing, colliding IDs, cancellation isolation and offline/no-fallback passed. No signer or executor.")
