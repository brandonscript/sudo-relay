"""Exercise enrollment file protection only; never serve or submit an execution."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

# Public test vector only; no private key or authentication credential is needed.
PUBLIC_KEY = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'


class EnrollmentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.assertEqual(os.geteuid(), 0, 'Use the disposable fixture controller')
        self.assertEqual(os.environ.get('PE_DISPOSABLE_FIXTURE'), '1')
        self.assertTrue(Path('/.dockerenv').exists())
        self.root = Path(tempfile.mkdtemp(prefix='enrollment-', dir='/lab'))
        self.addCleanup(shutil.rmtree, self.root)
        self.config = self.root / 'config.json'
        self.keys = self.root / 'state/keys'
        self.run_broker('init', str(self.config), str(self.root / 'state'),
                        str(self.root / 'run/broker.sock'), '10001', '10002', '10001')

    def run_broker(self, *args: str, uid: int = 0, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(['broker', *args], capture_output=True, text=True,
                                timeout=5, user=uid, group=10001, extra_groups=[])
        self.assertEqual(result.returncode == 0, succeeds, result.stderr)
        return result

    def test_agent_and_approver_cannot_pair_or_revoke(self) -> None:
        self.run_broker('pair', str(self.config), 'existing', PUBLIC_KEY)
        original = (self.keys / 'existing.pub').read_bytes()
        for uid in [10001, 10002]:
            for args in [('pair', str(self.config), 'injected', PUBLIC_KEY),
                         ('revoke', str(self.config), 'existing')]:
                with self.subTest(uid=uid, command=args[0]):
                    result = self.run_broker(*args, uid=uid, succeeds=False)
                    self.assertIn('use root for production', result.stderr)
        self.assertFalse((self.keys / 'injected.pub').exists())
        self.assertEqual((self.keys / 'existing.pub').read_bytes(), original)

    def test_pair_refuses_replacement_and_admin_can_revoke(self) -> None:
        self.run_broker('pair', str(self.config), 'existing', PUBLIC_KEY)
        key = self.keys / 'existing.pub'
        self.assertEqual(key.stat().st_uid, 0)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.run_broker('pair', str(self.config), 'existing', PUBLIC_KEY, succeeds=False)
        self.assertEqual(key.read_text(), PUBLIC_KEY)
        self.run_broker('revoke', str(self.config), 'existing')
        self.assertFalse(key.exists())

    def test_mutable_config_or_parent_is_rejected(self) -> None:
        for target in [self.config, self.root]:
            for mode in [0o620, 0o602] if target == self.config else [0o720, 0o702]:
                with self.subTest(target=target.name, mode=oct(mode)):
                    original = target.stat().st_mode & 0o777
                    try:
                        target.chmod(mode)
                        result = self.run_broker('pair', str(self.config), 'injected', PUBLIC_KEY, succeeds=False)
                        self.assertIn('not group/world writable', result.stderr)
                        self.assertFalse((self.keys / 'injected.pub').exists())
                    finally:
                        target.chmod(original)

    def test_agent_owned_trust_directory_is_rejected(self) -> None:
        os.chown(self.keys, 10001, 10001)
        try:
            result = self.run_broker('pair', str(self.config), 'injected', PUBLIC_KEY, succeeds=False)
            self.assertIn('must be owned by uid 0', result.stderr)
        finally:
            os.chown(self.keys, 0, 10001)
        self.assertFalse((self.keys / 'injected.pub').exists())

    def test_key_symlink_cannot_replace_another_file(self) -> None:
        victim = self.root / 'unchanged'
        victim.write_text('fixture canary')
        (self.keys / 'injected.pub').symlink_to(victim)
        self.run_broker('pair', str(self.config), 'injected', PUBLIC_KEY, succeeds=False)
        self.assertEqual(victim.read_text(), 'fixture canary')


if __name__ == '__main__':
    unittest.main(verbosity=2)
