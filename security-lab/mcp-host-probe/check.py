"""Exercise the real stdio probe as an operator, never as evidence of host isolation."""
import json
import os
from pathlib import Path
import selectors
import subprocess

ROOT = Path(__file__).resolve().parents[2]
assert os.geteuid() != 0, "Run as an ordinary user"
process = subprocess.Popen(
    [str(ROOT / "target/debug/mcp-host-probe"), str(ROOT / "ui/dist/host-probe.html")],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
)
assert process.stdin is not None and process.stdout is not None
selector = selectors.DefaultSelector()
selector.register(process.stdout, selectors.EVENT_READ)
sequence = 0


def rpc(method: str, params: dict[str, object]) -> dict[str, object]:
    global sequence
    sequence += 1
    process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": sequence, "method": method, "params": params}) + "\n")
    process.stdin.flush()
    assert selector.select(5), "MCP response timed out"
    result = json.loads(process.stdout.readline())
    assert result["id"] == sequence and "error" not in result, "Unexpected MCP response"
    return result["result"]


def call(name: str, arguments: dict[str, object]) -> dict[str, object]:
    return rpc("tools/call", {"name": name, "arguments": arguments})


try:
    rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "operator-check", "version": "1"}})
    process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    process.stdin.flush()
    tools = {tool["name"]: tool for tool in rpc("tools/list", {})["tools"]}
    assert set(tools) == {"new_probe", "probe_status", "record_probe_approval", "cancel_probe"}
    assert tools["record_probe_approval"]["_meta"]["ui"]["visibility"] == ["app"]
    resource = rpc("resources/read", {"uri": tools["new_probe"]["_meta"]["ui"]["resourceUri"]})
    assert "Nothing runs here" in resource["contents"][0]["text"]
    assert resource["contents"][0]["_meta"]["openai/ui"] == {"availableDisplayModes": ["inline"], "preferredDisplayMode": "inline"}
    created = call("new_probe", {})
    hidden = created["_meta"]["probe"]
    public = created["structuredContent"]
    assert public["variant"] == "inline-only-v1"
    assert hidden["canary"] not in json.dumps(public) and hidden["capability"] not in json.dumps(public)
    request_id = public["request"]["id"]
    approval = {"id": request_id, "number": hidden["number"], "capability": hidden["capability"]}
    assert call("new_probe", {})["isError"] is True
    assert call("record_probe_approval", {**approval, "capability": "wrong"})["isError"] is True
    pending = call("probe_status", {"id": request_id})
    assert pending["structuredContent"]["receipt_count"] == 0 and "_meta" not in pending
    # Known limitation: a raw transport owner with the capability can record a receipt.
    accepted = call("record_probe_approval", approval)
    assert accepted["structuredContent"]["receipt_count"] == 1
    assert call("record_probe_approval", approval)["isError"] is True
    second = call("new_probe", {})
    second_id = second["structuredContent"]["request"]["id"]
    assert call("record_probe_approval", {**approval, "id": second_id})["isError"] is True
    denied = call("cancel_probe", {"id": second_id})
    assert denied["structuredContent"]["request"]["state"] == "denied"
    assert denied["structuredContent"]["receipt_count"] == 1
    print(json.dumps({"probe_protocol": "passed", "replay_and_cross_request": "rejected", "raw_capability_holder": "can approve (expected limitation)", "desktop_host_boundary": "not tested", "commands_executed": 0}))
finally:
    selector.close()
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
