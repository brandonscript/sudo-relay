"""Read-only Codex loader check after installing the receipt-only plugin."""
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading

assert len(sys.argv) == 2, "Usage: python3 check-loader.py MARKETPLACE_DIRECTORY"
marketplace = Path(sys.argv[1]).resolve() / ".agents/plugins/marketplace.json"
assert marketplace.is_file(), "Missing marketplace catalogue"
process = subprocess.Popen(
    ["codex", "app-server", "--stdio"], stdin=subprocess.PIPE,
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
)
assert process.stdin is not None and process.stdout is not None
responses: queue.Queue[object] = queue.Queue()
sequence = 0


def read() -> None:
    try:
        for line in process.stdout:
            responses.put(json.loads(line))
    finally:
        responses.put(None)


def object_value(value: object) -> dict[str, object]:
    assert isinstance(value, dict), "Unexpected loader response"
    return value


def rpc(method: str, params: dict[str, object]) -> dict[str, object]:
    global sequence
    sequence += 1
    process.stdin.write(json.dumps({"id": sequence, "method": method, "params": params}) + "\n")
    process.stdin.flush()
    for _ in range(200):
        try:
            value = responses.get(timeout=25)
        except queue.Empty:
            raise RuntimeError(f"Loader timed out during {method}; this is not a security pass") from None
        assert value is not None, "Loader exited before responding"
        response = object_value(value)
        if response.get("id") == sequence:
            assert "error" not in response, f"Loader rejected {method}: {response.get('error')}"
            return object_value(response["result"])
    raise RuntimeError("Too many unrelated loader notifications")


threading.Thread(target=read, daemon=True).start()
try:
    rpc("initialize", {"clientInfo": {"name": "sudo-relay-loader-check", "version": "1"}, "capabilities": {"experimentalApi": True}})
    process.stdin.write('{"method":"initialized"}\n')
    process.stdin.flush()
    plugin = object_value(rpc("plugin/read", {"pluginName": "sudo-relay-host-probe", "marketplacePath": str(marketplace)})["plugin"])
    assert plugin["mcpServers"] == ["host-probe"], "Installed plugin does not expose its MCP server"
    status = rpc("mcpServerStatus/list", {"serverName": "host-probe", "detail": "toolsAndAuthOnly"})
    servers = status["data"]
    assert isinstance(servers, list) and len(servers) == 1, "Expected exactly the probe server"
    server = object_value(servers[0])
    assert server["name"] == "host-probe"
    assert server["pluginId"] == "sudo-relay-host-probe@sudo-relay-lab"
    assert server["toolsError"] is None, f"Probe startup failed: {server['toolsError']}"
    tools = object_value(server["tools"])
    assert set(tools) == {"new_probe", "probe_status", "cancel_probe", "record_probe_approval"}
    print(json.dumps({"loader": "passed", "server": "host-probe", "tools": sorted(tools), "requests_created": 0, "desktop_conversation": "not tested"}))
finally:
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
