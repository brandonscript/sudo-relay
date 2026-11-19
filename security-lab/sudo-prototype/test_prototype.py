"""Disposable feasibility test; root controller simulates the broker and human signer."""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import unittest
import uuid

ROOT = Path('/lab')
SPONSORS = {'sponsor_a': 11001, 'sponsor_b': 11002}
BOOTSTRAP = "import os; token=os.read(0,1); assert token==b'G'; os.execv('/usr/bin/sudo',__import__('sys').argv[1:])"
SIGN = """import subprocess,sys,tempfile
with tempfile.NamedTemporaryFile(dir='/lab/approver') as f:
 f.write(bytes.fromhex(sys.argv[1]));f.flush()
 print(subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-inkey','/lab/approver/key.pem','-in',f.name]).hex())
"""


def policy(user: str, commands: str | None = 'ALL', *, authenticate: bool = True) -> None:
    path = Path('/etc/sudoers.d') / user
    if commands is None:
        path.unlink(missing_ok=True)
    else:
        path.unlink(missing_ok=True)
        path.write_text(f'{user} ALL=(root) {"PASSWD" if authenticate else "NOPASSWD"}: {commands}\n')
        path.chmod(0o440)
    subprocess.run(['/usr/sbin/visudo', '-c'], check=True, capture_output=True)


def check_request(user: str, command: list[str]) -> bool:
    result = subprocess.run(['/usr/bin/sudo', '-n', '-l', '-U', user, '-u', 'root', '--', *command],
                            capture_output=True, timeout=5)
    return result.returncode == 0


class NativeSudoPrototype(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if os.geteuid() != 0 or os.environ.get('PE_SUDO_PROTOTYPE') != '1' or not Path('/.dockerenv').exists():
            raise RuntimeError('Use only the disposable Compose fixture')
        if not ROOT.is_mount() or any(ROOT.iterdir()):
            raise RuntimeError('/lab must be a fresh empty mount')
        os.umask(0o077)
        (ROOT / 'grants').mkdir(mode=0o700)
        (ROOT / 'approver').mkdir(mode=0o700)
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', '/lab/approver/key.pem'],
                       check=True, capture_output=True)
        public = subprocess.check_output(['openssl', 'pkey', '-in', '/lab/approver/key.pem', '-pubout', '-outform', 'DER'])
        if len(public) != 44 or public[:12].hex() != '302a300506032b6570032100':
            raise RuntimeError('Unexpected public key encoding')
        (ROOT / 'public.hex').write_text(public[12:].hex())
        (ROOT / 'machine').write_text(str(uuid.uuid4()))
        os.chown(ROOT / 'approver/key.pem', 11003, 11003)
        os.chown(ROOT / 'approver', 11003, 11003)
        defaults = Path('/etc/sudoers.d/00-prototype')
        defaults.write_text('Defaults timestamp_timeout=0, passwd_tries=1, lecture=never, !use_pty\n'
                            'Defaults pam_service="sudo-relay", pam_askpass_service="sudo-relay"\n'
                            'Defaults logfile="/lab/sudo.log", log_year, log_exit_status\n')
        defaults.chmod(0o440)
        print(subprocess.check_output(['/usr/bin/sudo', '--version'], text=True).splitlines()[0])

    def setUp(self) -> None:
        self.launches: dict[int, str] = {}
        for user in SPONSORS:
            policy(user)
        (ROOT / 'effect').unlink(missing_ok=True)

    def prepare(self, command: list[str], user: str = 'sponsor_a', *, invalidate: bool = True) -> tuple[subprocess.Popen[bytes], dict[str, object]]:
        argv = ['/usr/bin/sudo', *(['-k'] if invalidate else []), '-S', '-u', 'root', '--', *command]
        child = subprocess.Popen([sys.executable, '-c', BOOTSTRAP, *argv], user=SPONSORS[user], group=SPONSORS[user],
                                 extra_groups=[], cwd='/', env={'PATH': '/usr/bin:/bin'},
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup_child, child)
        stat = Path(f'/proc/{child.pid}/stat').read_text().rsplit(') ', 1)[1].split()
        grant: dict[str, object] = {
            'domain': 'sudo-relay/pam-prototype/v1', 'machine': (ROOT / 'machine').read_text(),
            'sponsor': user, 'uid': SPONSORS[user], 'pid': child.pid, 'start': stat[19],
            'expires': int(time.time()) + 60, 'nonce': secrets.token_hex(32), 'argv': argv,
        }
        self.launches[child.pid] = json.dumps({key: grant[key] for key in ['sponsor', 'uid', 'pid', 'start', 'argv']})
        return child, grant

    def cleanup_child(self, child: subprocess.Popen[bytes]) -> None:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for stream in [child.stdin, child.stdout, child.stderr]:
            if stream is not None:
                stream.close()

    def ticket(self, child: subprocess.Popen[bytes], grant: dict[str, object], *, forged: bool = False) -> dict[str, str]:
        payload = json.dumps(grant, sort_keys=True, separators=(',', ':')).encode().hex()
        signature = subprocess.check_output([sys.executable, '-c', SIGN, payload], user=11003, group=11003,
                                            extra_groups=[], text=True, timeout=5).strip()
        ticket = {'payload': payload, 'signature': '00' * 64 if forged else signature}
        self.write_ticket(child.pid, ticket)
        return ticket

    def write_ticket(self, pid: int, ticket: dict[str, str]) -> None:
        path = ROOT / f'grants/{pid}.json'
        path.write_text(json.dumps(ticket))
        path.chmod(0o600)

    def gate(self, child: subprocess.Popen[bytes]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(['/usr/local/bin/approval-gate'], input=self.launches[child.pid].encode(),
                              capture_output=True, timeout=5)

    def launch(self, child: subprocess.Popen[bytes], *, enforce_gate: bool = True) -> subprocess.CompletedProcess[bytes]:
        if enforce_gate:
            verdict = self.gate(child)
            if verdict.returncode != 0:
                self.cleanup_child(child)
                return subprocess.CompletedProcess(child.args, verdict.returncode, b'', verdict.stderr)
        started = time.monotonic()
        output, error = child.communicate(b'G', timeout=5)
        print(f'  sudo launch/auth/exit: {(time.monotonic() - started) * 1000:.1f} ms')
        return subprocess.CompletedProcess(child.args, child.returncode, output, error)

    def test_approved_execution_is_root_and_logged_as_sponsor(self) -> None:
        for user in SPONSORS:
            with self.subTest(sponsor=user):
                command = ['/usr/bin/id', '-u']
                started = time.monotonic()
                self.assertTrue(check_request(user, command))
                print(f'  request policy lookup: {(time.monotonic() - started) * 1000:.1f} ms')
                child, grant = self.prepare(command, user)
                self.ticket(child, grant)
                result = self.launch(child)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b'0\n')
                log = (ROOT / 'sudo.log').read_text()
                self.assertRegex(log, rf'{user}\s*:.*USER=root.*COMMAND=/usr/bin/id -u')
                self.assertTrue((ROOT / f'grants/{grant["nonce"]}.consumed').exists())

    def test_denied_and_unapproved_requests_never_execute(self) -> None:
        for decision in ['denied', 'unapproved']:
            with self.subTest(decision=decision):
                child, _ = self.prepare(['/usr/bin/touch', '/lab/effect'])
                result = self.launch(child)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((ROOT / 'effect').exists())

    def test_invalid_signature_expiry_and_identity_are_rejected(self) -> None:
        for change in ['signature', 'expiry', 'sponsor', 'machine', 'start', 'argv']:
            with self.subTest(change=change):
                child, grant = self.prepare(['/usr/bin/touch', '/lab/effect'])
                if change == 'expiry': grant['expires'] = int(time.time()) - 1
                if change == 'sponsor': grant.update(sponsor='sponsor_b', uid=11002)
                if change == 'machine': grant['machine'] = 'another-machine'
                if change == 'start': grant['start'] = '0'
                if change == 'argv': grant['argv'] = ['/usr/bin/sudo', '-k', '-S', '-u', 'root', '--', '/usr/bin/id', '-u']
                self.ticket(child, grant, forged=change == 'signature')
                self.assertNotEqual(self.launch(child, enforce_gate=False).returncode, 0)
                self.assertFalse((ROOT / 'effect').exists())

    def test_signature_cannot_be_reused_for_another_process_or_sponsor(self) -> None:
        first, grant = self.prepare(['/usr/bin/printf', 'approved'])
        ticket = self.ticket(first, grant)
        self.assertEqual(self.launch(first).returncode, 0)
        for user in SPONSORS:
            second, _ = self.prepare(['/usr/bin/touch', '/lab/effect'], user)
            self.write_ticket(second.pid, ticket)
            self.assertNotEqual(self.launch(second).returncode, 0)
        self.assertFalse((ROOT / 'effect').exists())

    def test_consumed_nonce_cannot_authorize_a_new_launch(self) -> None:
        first, grant = self.prepare(['/usr/bin/printf', 'once'])
        self.ticket(first, grant)
        self.assertEqual(self.launch(first).returncode, 0)
        second, reused = self.prepare(['/usr/bin/touch', '/lab/effect'])
        reused['nonce'] = grant['nonce']
        self.ticket(second, reused)
        self.assertNotEqual(self.launch(second).returncode, 0)
        self.assertFalse((ROOT / 'effect').exists())

    def test_revocation_after_approval_blocks_native_sudo_and_other_sponsor_survives(self) -> None:
        command = ['/usr/bin/touch', '/lab/effect']
        self.assertTrue(check_request('sponsor_a', command))
        child, grant = self.prepare(command)
        self.ticket(child, grant)
        policy('sponsor_a', None)
        self.assertFalse(check_request('sponsor_a', command))
        result = self.launch(child)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((ROOT / 'effect').exists())
        other, grant_b = self.prepare(['/usr/bin/id', '-u'], 'sponsor_b')
        self.ticket(other, grant_b)
        self.assertEqual(self.launch(other).returncode, 0)

    def test_exact_command_policy_is_enforced_even_with_valid_signature(self) -> None:
        policy('sponsor_a', '/usr/bin/printf allowed')
        self.assertTrue(check_request('sponsor_a', ['/usr/bin/printf', 'allowed']))
        self.assertFalse(check_request('sponsor_a', ['/usr/bin/touch', '/lab/effect']))
        child, grant = self.prepare(['/usr/bin/touch', '/lab/effect'])
        self.ticket(child, grant)
        self.assertNotEqual(self.launch(child).returncode, 0)
        self.assertFalse((ROOT / 'effect').exists())

    def test_approval_does_not_create_reusable_sudo_authentication(self) -> None:
        child, grant = self.prepare(['/usr/bin/printf', 'approved'])
        self.ticket(child, grant)
        self.assertEqual(self.launch(child).returncode, 0)
        result = subprocess.run(['/usr/bin/sudo', '-S', '-u', 'root', '--', '/usr/bin/touch', '/lab/effect'],
                                user=11001, group=11001, extra_groups=[], input=b'', capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((ROOT / 'effect').exists())

    def test_known_limit_nopasswd_skips_pam_without_a_ticket(self) -> None:
        # Characterize an unsupported setup; success here is a missing approval gate, not protection.
        policy('sponsor_a', authenticate=False)
        child, _ = self.prepare(['/usr/bin/touch', '/lab/effect'])
        result = self.launch(child, enforce_gate=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((ROOT / 'effect').exists())

    def test_known_limit_cached_authentication_skips_pam_without_a_ticket(self) -> None:
        settings = Path('/etc/sudoers.d/99-cache-probe')
        settings.write_text('Defaults timestamp_timeout=5, timestamp_type=global\n')
        settings.chmod(0o440)
        self.addCleanup(settings.unlink)
        self.addCleanup(subprocess.run, ['/usr/bin/sudo', '-K'], user=11001, group=11001,
                        extra_groups=[], capture_output=True, timeout=5, check=True)
        subprocess.run(['/usr/sbin/visudo', '-c'], check=True, capture_output=True)
        # Omitting -k is deliberate: this models an integration that forgets cache isolation.
        first, grant = self.prepare(['/usr/bin/printf', 'approved'], invalidate=False)
        self.ticket(first, grant)
        self.assertEqual(self.launch(first, enforce_gate=False).returncode, 0)
        second, _ = self.prepare(['/usr/bin/touch', '/lab/effect'], invalidate=False)
        result = self.launch(second, enforce_gate=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((ROOT / 'effect').exists())
        (ROOT / 'effect').unlink()
        # The existing -k path must ignore that same cache and require a fresh grant.
        guarded, _ = self.prepare(['/usr/bin/touch', '/lab/effect'])
        self.assertNotEqual(self.launch(guarded, enforce_gate=False).returncode, 0)
        self.assertFalse((ROOT / 'effect').exists())

    def test_gate_blocks_nopasswd_bypass_and_preserves_valid_approval(self) -> None:
        policy('sponsor_a', authenticate=False)
        for kind in ['missing', 'forged', 'different-command', 'expired', 'different-sponsor']:
            with self.subTest(kind=kind):
                child, grant = self.prepare(['/usr/bin/touch', '/lab/effect'])
                if kind == 'different-command':
                    grant['argv'] = ['/usr/bin/sudo', '-k', '-S', '-u', 'root', '--', '/usr/bin/id', '-u']
                if kind == 'expired': grant['expires'] = int(time.time()) - 1
                if kind == 'different-sponsor': grant.update(sponsor='sponsor_b', uid=11002)
                if kind != 'missing': self.ticket(child, grant, forged=kind == 'forged')
                result = self.launch(child)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'Approval gate denied', result.stderr)
                self.assertFalse((ROOT / 'effect').exists())
        child, grant = self.prepare(['/usr/bin/touch', '/lab/effect'])
        self.ticket(child, grant)
        self.assertEqual(self.launch(child).returncode, 0)
        self.assertTrue((ROOT / 'effect').exists())
        self.assertTrue((ROOT / f'grants/{grant["nonce"]}.released').exists())
        self.assertFalse((ROOT / f'grants/{grant["nonce"]}.consumed').exists(), 'PAM should have been skipped')

    def test_gate_consumes_once_before_release_even_without_pam(self) -> None:
        policy('sponsor_a', authenticate=False)
        child, grant = self.prepare(['/usr/bin/touch', '/lab/effect'])
        self.ticket(child, grant)
        self.assertEqual(self.gate(child).returncode, 0)
        self.assertNotEqual(self.gate(child).returncode, 0)
        self.assertFalse((ROOT / 'effect').exists())
        # Simulate loss of the waiting process after durable gate consumption.
        self.cleanup_child(child)
        retry, replacement = self.prepare(['/usr/bin/touch', '/lab/effect'])
        replacement['nonce'] = grant['nonce']
        self.ticket(retry, replacement)
        self.assertNotEqual(self.launch(retry).returncode, 0)
        self.assertFalse((ROOT / 'effect').exists())

    def test_gate_rejects_sponsor_invocation_and_cache_unsafe_launcher(self) -> None:
        child, grant = self.prepare(['/usr/bin/touch', '/lab/effect'])
        self.ticket(child, grant)
        result = subprocess.run(['/usr/local/bin/approval-gate'], input=self.launches[child.pid].encode(),
                                user=11001, group=11001, extra_groups=[], capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        unsafe_child, unsafe_grant = self.prepare(['/usr/bin/touch', '/lab/effect'], invalidate=False)
        self.ticket(unsafe_child, unsafe_grant)
        self.assertNotEqual(self.launch(unsafe_child).returncode, 0)
        self.assertFalse((ROOT / 'effect').exists())

    def test_gate_does_not_warm_nonzero_sudo_cache(self) -> None:
        settings = Path('/etc/sudoers.d/99-cache-probe')
        settings.write_text('Defaults timestamp_timeout=5, timestamp_type=global\n')
        settings.chmod(0o440)
        self.addCleanup(settings.unlink)
        subprocess.run(['/usr/sbin/visudo', '-c'], check=True, capture_output=True)
        subprocess.run(['/usr/bin/sudo', '-K'], user=11001, group=11001, extra_groups=[], check=True, capture_output=True)
        child, grant = self.prepare(['/usr/bin/printf', 'approved'])
        self.ticket(child, grant)
        self.assertEqual(self.launch(child).returncode, 0)
        result = subprocess.run(['/usr/bin/sudo', '-S', '-u', 'root', '--', '/usr/bin/touch', '/lab/effect'],
                                user=11001, group=11001, extra_groups=[], input=b'', capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((ROOT / 'effect').exists())

    def test_sponsor_cannot_read_signing_key_or_modify_grants(self) -> None:
        for path in ['/lab/approver/key.pem', '/lab/grants']:
            result = subprocess.run([sys.executable, '-c', 'import os,sys; os.open(sys.argv[1],os.O_RDONLY)', path],
                                    user=11001, group=11001, extra_groups=[], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
        result = subprocess.run([sys.executable, '-c', "open('/lab/grants/forged.json','w').write('{}')"],
                                user=11001, group=11001, extra_groups=[], capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
