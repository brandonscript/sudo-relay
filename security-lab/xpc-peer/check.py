"""Temporary, ordinary-user XPC peer checks. No installation, credentials or command runner."""
from __future__ import annotations

import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent
assert sys.platform == "darwin" and os.getuid() != 0, "Run as an ordinary macOS user"


def run(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr}")
    return result


def write_plist(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(value))


def cdhash(bundle: Path) -> str:
    details = run("/usr/bin/codesign", "-d", "--verbose=4", str(bundle)).stderr
    match = re.search(r"^CDHash=([a-f0-9]{40})$", details, re.MULTILINE)
    assert match, "Missing code identity"
    return match.group(1)


def sign(bundle: Path) -> None:
    args = ["/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime"]
    run(*args, str(bundle))


def vary(bundle: Path) -> None:
    resource = bundle / "Contents/Resources/peer-test-variant.txt"
    resource.parent.mkdir(parents=True, exist_ok=True)
    resource.write_text("Different sealed resources; same bundle identifier.\n")
    sign(bundle)


with tempfile.TemporaryDirectory(prefix="sudo-relay-xpc-peer-") as scratch:
    root = Path(scratch)
    original = root / "original" / "PeerLab.app"
    helper_relative = Path("Contents/XPCServices/local.sudo-relay.peer-service.xpc")
    helper = original / helper_relative
    for bundle, role, identifier, kind in [
        (helper, "Service", "local.sudo-relay.peer-service", "XPC!"),
        (original, "Client", "local.sudo-relay.peer-client", "APPL"),
    ]:
        binary = bundle / "Contents/MacOS" / role
        binary.parent.mkdir(parents=True)
        run("/usr/bin/xcrun", "swiftc", "-swift-version", "6", "-parse-as-library", "-warnings-as-errors",
            "-module-cache-path", str(root / "modules"), str(SOURCE / "Shared.swift"),
            str(SOURCE.parent / "touch-id/Sources/ApprovalProbe/ReviewBoundary.swift"),
            str(SOURCE / f"{role}.swift"), "-o", str(binary))
        info: dict[str, object] = {"CFBundleExecutable": role, "CFBundleIdentifier": identifier,
                                  "CFBundleName": role, "CFBundlePackageType": kind, "CFBundleVersion": "1"}
        if role == "Service":
            info["XPCService"] = {"ServiceType": "Application"}
        write_plist(bundle / "Contents/Info.plist", info)
        sign(bundle)
    original_client = cdhash(original)
    original_service = cdhash(helper)
    results: list[dict[str, object]] = []
    for case in ["allowed", "variant-client-allowed", "substituted-client", "variant-service-allowed",
                 "substituted-service", "substituted-service-without-handshake", "signed-review"]:
        case_root = root / case
        app = case_root / "PeerLab.app"
        shutil.copytree(original, app)
        service = app / helper_relative
        if case in ["substituted-client", "variant-client-allowed"]:
            vary(app)
            assert cdhash(app) != original_client
        if case.startswith("substituted-service") or case == "variant-service-allowed":
            vary(service)
            sign(app)
            assert cdhash(service) != original_service
        run("/usr/bin/codesign", "--verify", "--deep", "--strict", str(app))
        # Fixture-controlled pins outside the signed bundles avoid circular code hashes.
        # This same-user file is NOT a protected production enrollment store.
        client_pin = original_client if case == "substituted-client" else cdhash(app)
        service_pin = original_service if case.startswith("substituted-service") else cdhash(service)
        (case_root / "policy.json").write_text(json.dumps({
            "client": f'identifier "local.sudo-relay.peer-client" and cdhash H"{client_pin}"',
            "service": f'identifier "local.sudo-relay.peer-service" and cdhash H"{service_pin}"',
        }))
        characterization = case.endswith("without-handshake")
        arguments = ["--characterize-without-handshake"] if characterization else []
        if case == "signed-review":
            run(str(app / "Contents/MacOS/Client"), "--fixture-key")
            arguments = ["--signed-review"]
        result = subprocess.run([str(app / "Contents/MacOS/Client"), *arguments], text=True,
                                capture_output=True, timeout=15)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        receipt = case_root / "receipt.txt"
        if case == "signed-review":
            assert result.returncode == 0 and events == [{"event": "peer-verified"},
                {"event": "signed-review-one-receipt-alteration-and-replay-rejected"}], (case, result)
            assert not receipt.exists()
        elif case.endswith("allowed"):
            assert result.returncode == 0 and events == [{"event": "peer-verified"}, {"event": "receipt-received"}], (case, result)
            assert receipt.read_text() == "peer-check-receipt-only\n"
        else:
            assert result.returncode == 1 and len(events) == 1 and events[0]["event"] == "peer-rejected", (case, result)
            assert events[0]["domain"] == "NSCocoaErrorDomain", (case, events)
            assert events[0]["code"] in (["4102"] if case.startswith("substituted-service") else ["4097", "4102"]), (case, events)
            assert receipt.exists() == characterization, f"{case}: unexpected receipt state"
        results.append({"case": case, "expectation_met": True, "known_unsafe_pattern": characterization,
                        "receipt_count": 1 if case == "signed-review" else int(receipt.exists()), "events": events})
    print(json.dumps({"cases": results, "uid": os.getuid(), "commands_executed": 0,
                      "human_approval_tested": False, "protected_deployment_tested": False}, indent=2))
