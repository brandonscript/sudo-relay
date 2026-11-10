"""Copy only the compiled probe and card into a disposable local marketplace."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "target/debug/mcp-host-probe"
CARD = ROOT / "ui/dist/host-probe.html"
assert BINARY.is_file() and CARD.is_file(), "Build the probe and UI first"
marketplace = Path(tempfile.mkdtemp(prefix="sudo-relay-host-probe-"))
plugin = marketplace / "plugins/sudo-relay-host-probe"
plugin.mkdir(parents=True)
shutil.copy2(BINARY, plugin / "mcp-host-probe")
shutil.copy2(CARD, plugin / "card.html")


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


write(plugin / "plugin.json", {
    "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
    "name": "sudo-relay-host-probe", "version": "0.1.0",
    "description": "Receipt-only MCP Apps transport experiment. Never executes commands or connects to sudo.",
})
write(plugin / "mcp.json", {
    "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
    "mcpServers": {"host-probe": {"type": "stdio", "command": "${PLUGIN_ROOT}/mcp-host-probe", "args": ["${PLUGIN_ROOT}/card.html"]}},
})
write(marketplace / ".agents/plugins/marketplace.json", {
    "name": "sudo-relay-lab", "interface": {"displayName": "sudo-relay lab"},
    "plugins": [{"name": "sudo-relay-host-probe", "source": {"source": "local", "path": "./plugins/sudo-relay-host-probe"}, "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}, "category": "Productivity"}],
})
checksums = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(plugin.iterdir())}
write(marketplace / "checksums.json", checksums)
assert len(checksums) == 4
assert all((plugin / name).is_file() for name in checksums)
print(marketplace)
