"""Create disposable credentials and start the real broker; run no test cases."""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path('/lab')
AGENT_UID = 10001
APPROVER_UID = 10002
SOCKET_GID = 10001


def main() -> None:
    if os.environ.get('PE_DISPOSABLE_FIXTURE') != '1' or os.geteuid() != 0 or not Path('/.dockerenv').exists():
        raise RuntimeError('Start this fixture with its Docker Compose configuration')
    if not ROOT.is_mount() or any(ROOT.iterdir()):
        raise RuntimeError('/lab must be a fresh disposable mount')
    os.umask(0o077)
    for role in ['agent', 'approver']:
        (ROOT / role).mkdir(mode=0o700)
    key = ROOT / 'approver/key.pem'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(key)], check=True)
    key.chmod(0o600)
    public = subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'])
    if len(public) != 44 or public[:12].hex() != '302a300506032b6570032100':
        raise RuntimeError('Unexpected Ed25519 public-key encoding')
    os.chown(key, APPROVER_UID, SOCKET_GID)
    (ROOT / 'fake-secret').write_text(secrets.token_hex(32))
    config = ROOT / 'config.json'
    subprocess.run(['broker', 'init', str(config), str(ROOT / 'state'), str(ROOT / 'run/broker.sock'),
                    str(AGENT_UID), str(APPROVER_UID), str(SOCKET_GID)], check=True)
    subprocess.run(['broker', 'pair', str(config), 'fixture', public[12:].hex()], check=True)
    settings = json.loads(config.read_text())
    manifest = ROOT / 'fixture.json'
    manifest.write_text(json.dumps({
        'machine_id': settings['machine_id'], 'socket': settings['socket'],
        'agent_uid': AGENT_UID, 'approver_uid': APPROVER_UID, 'socket_gid': SOCKET_GID,
        'key_id': 'fixture', 'approver_key': str(key), 'fake_secret': str(ROOT / 'fake-secret'),
    }, indent=2) + '\n')
    manifest.chmod(0o444)
    if key.stat().st_uid != APPROVER_UID or key.stat().st_mode & 0o077:
        raise RuntimeError('Fixture key ownership or permissions are incorrect')
    for role, uid in [('agent', AGENT_UID), ('approver', APPROVER_UID)]:
        os.chown(ROOT / role, uid, SOCKET_GID)
    print('Fixture ready. No tests or commands submitted. Metadata: /lab/fixture.json', flush=True)
    os.execvp('broker', ['broker', 'serve', str(config)])


if __name__ == '__main__':
    main()
