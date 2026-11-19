"""Root-only disposable adapter. Never install this or its PAM stack on a host."""
from __future__ import annotations
import json
import os
from pathlib import Path
import pwd
import secrets
import subprocess
import sys
import time
import tempfile
import uuid
from typing import Any

ROOT = Path('/lab')
SUDO = '/usr/bin/sudo'
APPROVAL_GATE = ['/usr/local/bin/approval-gate']
BOOTSTRAP = "import os,sys; assert os.read(0,1)==b'G'; os.execv('/usr/bin/sudo',sys.argv[1:])"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def contained() -> None:
    require(sys.platform == 'linux' and Path('/.dockerenv').exists(), 'container only')
    require(os.getuid() == 0 and os.geteuid() == 0 and ROOT.is_mount(), 'root fixture only')
    require((ROOT / 'integration-fixture').read_text() == 'disposable', 'fixture not initialized')
    os.umask(0o077)


def identity(name: str) -> dict[str, Any]:
    user = pwd.getpwnam(name)
    require(user.pw_uid != 0, 'non-root sponsor required')
    return {'name': name, 'uid': user.pw_uid, 'gid': user.pw_gid,
            'home': user.pw_dir, 'shell': user.pw_shell}


def enroll() -> None:
    # sudo replaces these variables; only accept invocation by the real root sudo parent.
    require(Path(f'/proc/{os.getppid()}/exe').resolve() == Path(SUDO), f'installer requires sudo parent; observed {Path(f"/proc/{os.getppid()}/exe").resolve()}')
    status = Path(f'/proc/{os.getppid()}/status').read_text()
    uid_line = next(line for line in status.splitlines() if line.startswith('Uid:'))
    require(int(uid_line.split()[2]) == 0, 'sudo parent must be elevated')
    name = os.environ['SUDO_USER']
    sponsor = identity(name)
    require(sponsor['uid'] == int(os.environ['SUDO_UID']) and sponsor['gid'] == int(os.environ['SUDO_GID']), 'sudo identity mismatch')
    directory = ROOT / 'enrollments' / str(sponsor['uid'])
    directory.mkdir(mode=0o700)  # no overwrite/re-enrollment path in this milestone
    state = directory / 'state'
    state.mkdir(mode=0o700)
    config = {'machine_id': str(uuid.uuid4()), 'agent_uid': 11004, 'approver_uid': 11003,
              'socket_gid': 11004, 'state_dir': str(state), 'socket': str(directory / 'unused.sock'),
              'approval_ttl_secs': 30, 'max_execution_secs': 5}
    # Fixture pairing key supplied by the root test setup, never an installer argument.
    keys = state / 'keys'; keys.mkdir(mode=0o700)
    (directory / 'enrollment.json').write_text(json.dumps({'config': config, 'sponsor': sponsor}))
    subprocess.run(['/usr/local/bin/integrated-sudo-lab', str(directory / 'enrollment.json'), 'pair'], check=True)
    print(json.dumps({'sponsor': sponsor, 'enrollment': str(directory / 'enrollment.json')}))


def argv_for(spec: dict[str, Any]) -> list[str]:
    require(spec['command']['kind'] == 'argv' and not spec.get('env'), 'scripts/environment excluded')
    argv = spec['command']['argv']
    require(argv in [['/usr/bin/id', '-u'], ['/usr/bin/touch', '/lab/effect_a'],
                     ['/usr/bin/touch', '/lab/effect_b'], ['/usr/local/bin/output-probe']], 'only fixed harmless fixture commands')
    return argv


def policy(sponsor: dict[str, Any], argv: list[str]) -> None:
    require(identity(sponsor['name']) == sponsor, 'sponsor account changed')
    result = subprocess.run([SUDO, '-n', '-l', '-U', sponsor['name'], '-u', 'root', '--', *argv],
                            capture_output=True, timeout=5, env={'PATH': '/usr/bin:/bin'})
    require(result.returncode == 0, 'sponsor policy denied')


def checkpoint(stage: str) -> None:
    # Root-only deterministic fault injection. No client request can select a stage.
    control = ROOT / 'fault'
    if control.exists() and control.read_text() == stage:
        (ROOT / 'checkpoint').write_text(stage)
        deadline = time.monotonic() + 10
        while not (ROOT / 'continue').exists():
            require(time.monotonic() < deadline, 'fault checkpoint timed out; no retry')
            time.sleep(.01)


def launch(data: dict[str, Any]) -> dict[str, Any]:
    sponsor = data['sponsor']; envelope = data['envelope']
    argv = argv_for(envelope['spec'])
    checkpoint('after-consumption')
    policy(sponsor, argv)
    require(envelope['created_at'] <= time.time() < envelope['expires_at'], 'expired before launch')
    invocation = [SUDO, '-k', '-S', '-u', 'root', '--', *argv]
    # Fresh account/group lookup; do not inherit stale groups from a long-running agent.
    groups = os.getgrouplist(sponsor['name'], sponsor['gid'])
    # Anonymous RAM files avoid sudo I/O-monitor pipe backpressure; fixed fixture output is bounded.
    with os.fdopen(os.memfd_create('relay-stdout', os.MFD_CLOEXEC), 'w+b') as captured_out, \
         os.fdopen(os.memfd_create('relay-stderr', os.MFD_CLOEXEC), 'w+b') as captured_err:
        child = subprocess.Popen([sys.executable, '-I', '-c', BOOTSTRAP, *invocation],
                                 user=sponsor['uid'], group=sponsor['gid'], extra_groups=groups,
                                 cwd='/', env={'PATH': '/usr/bin:/bin'}, start_new_session=True,
                                 stdin=subprocess.PIPE, stdout=captured_out, stderr=captured_err)
        try:
            start = Path(f'/proc/{child.pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
            grant = {'domain': 'sudo-relay/pam-prototype/v1', 'machine': (ROOT / 'machine').read_text(),
                     'sponsor': sponsor['name'], 'uid': sponsor['uid'], 'pid': child.pid, 'start': start,
                     'expires': envelope['expires_at'], 'nonce': secrets.token_hex(32), 'argv': invocation}
            payload = json.dumps(grant, sort_keys=True, separators=(',', ':')).encode()
            with tempfile.NamedTemporaryFile(dir=ROOT) as payload_file:
                payload_file.write(payload); payload_file.flush()
                signature = subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey',
                                                     str(ROOT / 'internal-key.pem'), '-in', payload_file.name])
            ticket_path = ROOT / 'grants' / f'{child.pid}.json'
            ticket_path.write_text(json.dumps({'payload': payload.hex(), 'signature': signature.hex()}))
            expected = {key: grant[key] for key in ['sponsor', 'uid', 'pid', 'start', 'argv']}
            subprocess.run(APPROVAL_GATE, input=json.dumps(expected).encode(), check=True, capture_output=True, timeout=5)
            checkpoint('before-sudo')
            require(identity(sponsor['name']) == sponsor, 'sponsor account changed before release')
            require(os.getgrouplist(sponsor['name'], sponsor['gid']) == groups, 'sponsor groups changed before release')
            require(time.time() < envelope['expires_at'], 'expired before process release')
            # Native sudo now authoritatively evaluates current policy as the enrolled sponsor.
            child.communicate(b'G', timeout=envelope['spec']['timeout_secs'])
            captured_out.seek(0); captured_err.seek(0)
            output = captured_out.read(1024 * 1024 + 1)
            error = captured_err.read(1024 * 1024 + 1)
            checkpoint('after-execution')
            limit = 1024 * 1024 if data['share_output'] else 0
            outcome = {'exit_code': child.returncode,
                       'stdout': output[:limit].decode('utf-8', errors='replace'),
                       'stderr': error[:limit].decode('utf-8', errors='replace'),
                       'truncated': bool(limit and (len(output)>limit or len(error)>limit)),
                       'timed_out': False, 'cleanup_error': None, 'error': None}
            return {'outcome': outcome, 'exit_code': child.returncode, 'root_uid_observed': output == b'0\n',
                    'sponsor': sponsor['name'], 'request_id': envelope['id']}
        finally:
            if child.poll() is None:
                os.killpg(child.pid, 9)
            child.wait(timeout=5)
            for stream in [child.stdin, child.stdout, child.stderr]:
                if stream:
                    stream.close()
            (ROOT / 'grants' / f'{child.pid}.json').unlink(missing_ok=True)


def main() -> None:
    contained()
    operation = sys.argv[1]
    if operation == 'enroll':
        require(len(sys.argv) == 2, 'no sponsor selector')
        enroll(); return
    data = json.loads(sys.stdin.buffer.read(65537))
    if operation == 'check':
        policy(data['sponsor'], argv_for(data['spec']))
        print('{}')
    elif operation == 'launch':
        print(json.dumps(launch(data)))
    else:
        raise RuntimeError('unsupported operation')


if __name__ == '__main__':
    main()
