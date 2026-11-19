"""Read-only inventory for the proposed receipt lab. Never installs or signs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
INSTALL_ROOT = Path('/Library/PrivilegedHelperTools/sudo-relay-receipt-lab')
STATE_ROOT = Path('/private/var/db/sudo-relay-receipt-lab')


def command(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def main() -> None:
    if sys.platform != 'darwin' or os.geteuid() == 0:
        raise SystemExit('Run this read-only preflight as your ordinary macOS account.')
    identities = command('/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning')
    account = pwd.getpwuid(os.getuid())
    requester = pwd.getpwnam('nobody')
    targets = [INSTALL_ROOT, STATE_ROOT]
    facts: dict[str, object] = {
        'receipt_only': True,
        'install_ready': False,
        'source_commit': command('git', '-C', str(ROOT), 'rev-parse', 'HEAD'),
        'macos': command('/usr/bin/sw_vers', '-productVersion'),
        'approver': {'account': account.pw_name, 'uid': account.pw_uid, 'gid': account.pw_gid},
        'proposed_fixed_requester': {'account': requester.pw_name, 'uid': requester.pw_uid},
        'apple_development_identity_count': identities.count('"Apple Development:'),
        'developer_id_application_identity_count': identities.count('"Developer ID Application:'),
        'existing_install_paths': [str(path) for path in targets if path.exists() or path.is_symlink()],
        'changes_made': [],
        'remaining_gates': [
            'reviewer-specific provisioning profile and Keychain access group',
            'signing identity inaccessible to the agent without human authorization',
            'reviewed receipt-only launcher and teardown, tested in disposable CI',
            'explicit key enrollment and other-process Keychain denial test',
            'reviewed signed artifact hashes and administrator installation approval',
        ],
    }
    # Hash only the named integration sources, never keychain items or private credentials.
    names = ['ProtectedNativeApp.swift', 'ProtectedReceiptDecision.swift', 'BrokerReview.swift']
    facts['source_sha256'] = {
        name: hashlib.sha256((ROOT / 'security-lab/native-protocol' / name).read_bytes()).hexdigest()
        for name in names
    }
    print(json.dumps(facts, indent=2))


if __name__ == '__main__':
    main()
