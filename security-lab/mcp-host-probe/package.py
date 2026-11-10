"""Copy only the compiled probe and card into a disposable local marketplace."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "target/debug/mcp-host-probe"
CARD = ROOT / "ui/dist/host-probe.html"
VERSION = "0.1.7"
# shortcut: local cache paths avoid unresolved placeholders; use portable paths once the host loader passes startup checks.
installed = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "plugins/cache/sudo-relay-lab/sudo-relay-host-probe" / VERSION
assert BINARY.is_file() and CARD.is_file(), "Build the probe and UI first"
marketplace = Path(tempfile.mkdtemp(prefix="sudo-relay-host-probe-"))
plugin = marketplace / "plugins/sudo-relay-host-probe"
plugin.mkdir(parents=True)
shutil.copy2(BINARY, plugin / "mcp-host-probe")
shutil.copy2(CARD, plugin / "card.html")


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


write(plugin / ".codex-plugin/plugin.json", {
    "name": "sudo-relay-host-probe", "version": VERSION,
    "description": "Receipt-only MCP Apps transport experiment. Never executes commands or connects to sudo.",
    "mcpServers": "./.mcp.json",
    "interface": {"displayName": "sudo-relay host probe", "shortDescription": "Receipt-only MCP Apps transport experiment"},
})
write(plugin / ".mcp.json", {
    "mcpServers": {"host-probe": {"command": str(installed / "mcp-host-probe"), "args": [str(installed / "card.html")]}},
})
write(marketplace / ".agents/plugins/marketplace.json", {
    "name": "sudo-relay-lab", "interface": {"displayName": "sudo-relay lab"},
    "plugins": [{"name": "sudo-relay-host-probe", "source": {"source": "local", "path": "./plugins/sudo-relay-host-probe"}, "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}, "category": "Productivity"}],
})
manifest = json.loads((plugin / ".codex-plugin/plugin.json").read_text())
servers = json.loads((plugin / manifest["mcpServers"]).read_text())["mcpServers"]
assert set(servers) == {"host-probe"}
for value in [servers["host-probe"]["command"], *servers["host-probe"]["args"]]:
    resolved = Path(value)
    assert resolved.is_absolute() and resolved.is_relative_to(installed)
    assert (plugin / resolved.relative_to(installed)).is_file()
checksums = {p.relative_to(plugin).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(plugin.rglob("*")) if p.is_file()}
write(marketplace / "checksums.json", checksums)
assert len(checksums) == 4
assert all((plugin / name).is_file() for name in checksums)
print(marketplace)
