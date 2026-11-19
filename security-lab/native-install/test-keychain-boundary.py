#!/usr/bin/env python3
"""Opt-in Mac hardware test using a public marker, never an approval key."""
import argparse
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import uuid


def run(*args: str) -> str:
    result = subprocess.run(args, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signed-app", type=Path, required=True)
    parser.add_argument("--identity", required=True, help="Explicit local signing certificate identity")
    options = parser.parse_args()
    source = Path(__file__).with_name("KeychainProbe.swift")
    account = str(uuid.uuid4())
    # Keep the exact removal coordinates if cleanup fails; no key material is logged.
    report: dict[str, object] = {"account": account, "service": "sudo-relay.keychain-boundary-test.v1"}
    with tempfile.TemporaryDirectory(prefix="sudo-relay-keychain-") as directory:
        root = Path(directory)
        entitlements = root / "entitlements.plist"
        run("codesign", "--verify", "--strict", str(options.signed_app))
        run("codesign", "-d", "--entitlements", str(entitlements), "--xml", str(options.signed_app))
        settings = plistlib.loads(entitlements.read_bytes())
        groups = settings.get("keychain-access-groups", [])
        if len(groups) != 1 or not groups[0].endswith(".com.sudorelay.receiptlab"):
            raise ValueError("Expected only the receipt lab's Keychain group")
        group = groups[0]
        report["group"] = group
        print(json.dumps(report), flush=True)
        apps = []
        for name, substitute in (("Owner", False), ("Substitute", True)):
            app = root / f"{name}.app"
            shutil.copytree(options.signed_app, app)
            executable = app / "Contents/MacOS/ReceiptLab"
            executable.unlink()
            flags = ["-D", "SUBSTITUTE"] if substitute else []
            run("swiftc", "-swift-version", "6", "-warnings-as-errors",
                "-module-cache-path", str(root / "modules"), *flags, str(source), "-o", str(executable))
            run("codesign", "--force", "--sign", options.identity, "--options", "runtime",
                "--entitlements", str(entitlements), "--timestamp=none", str(app))
            run("codesign", "--verify", "--strict", str(app))
            apps.append(str(executable))
        outsider = root / "Outsider"
        run("swiftc", "-swift-version", "6", "-warnings-as-errors",
            "-module-cache-path", str(root / "modules"), str(source), "-o", str(outsider))
        run("codesign", "--force", "--sign", "-", str(outsider))
        owner, substitute = apps
        created = False
        try:
            report["create"] = run(owner, "create", group, account)
            created = True
            report["owner_read"] = run(owner, "read", group, account)
            report["outsider_explicit"] = run(str(outsider), "denied", group, account)
            report["outsider_unscoped"] = run(str(outsider), "denied", "unscoped", account)
            # Success here demonstrates that agent-accessible signing defeats code isolation.
            report["substitute_read"] = run(substitute, "read", group, account)
        finally:
            if created:
                report["delete"] = run(owner, "delete", group, account)
                report["owner_after_delete"] = run(owner, "denied", group, account)
            print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
