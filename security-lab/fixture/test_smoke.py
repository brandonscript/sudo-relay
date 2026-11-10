"""Run as the agent UID inside the disposable fixture; use no real secrets."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest
import uuid

PROTECTED = [
    Path('/lab/approver/key.pem'), Path('/lab/fake-secret'), Path('/lab/config.json'),
    Path('/lab/state/state.sqlite3'), Path('/lab/state/keys/fixture.pub'),
]


class ApprovalSmokeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.assertEqual(os.geteuid(), 10001, 'Run these tests as the fixture agent')

    def reply(self, method: str, **parameters: object) -> dict[str, object]:
        response = json.loads(subprocess.check_output([
            'python', '/fixture/rpc.py', json.dumps({'method': method, **parameters}),
        ], text=True))
        if not isinstance(response, dict):
            raise AssertionError('Expected a broker response object')
        return response

    def value(self, method: str, **parameters: object) -> dict[str, object]:
        response = self.reply(method, **parameters)
        self.assertIs(response.get('ok'), True, response)
        value = response.get('value')
        if not isinstance(value, dict):
            raise AssertionError('Expected a successful response object')
        return value

    def request_marker(self) -> tuple[str, str, Path]:
        marker = Path('/lab/agent') / f'unapproved-{uuid.uuid4()}'
        self.assertFalse(marker.exists())
        pending = self.value('request_execution', spec={
            'command': {'kind': 'argv', 'argv': ['/usr/bin/touch', str(marker)]},
            'env': {}, 'reason': 'Fixture test: must wait for approval', 'timeout_secs': 1,
        })
        envelope = pending.get('envelope')
        if not isinstance(envelope, dict):
            raise AssertionError('Expected a request envelope')
        request_id, number = envelope.get('id'), envelope.get('number')
        if not isinstance(request_id, str) or not isinstance(number, str):
            raise AssertionError('Expected a request ID and confirmation number')
        self.addCleanup(self.cancel_if_pending, request_id)
        return request_id, number, marker

    def cancel_if_pending(self, request_id: str) -> None:
        status = self.value('execution_status', id=request_id)
        if status['state'] == 'pending':
            self.value('cancel_execution', id=request_id)
        else:
            self.assertEqual(status['state'], 'cancelled')

    def test_unapproved_command_stays_pending(self) -> None:
        request_id, _, marker = self.request_marker()
        status = self.value('execution_status', id=request_id)
        self.assertEqual(status['state'], 'pending')
        self.assertIsNone(status['outcome'])
        self.assertFalse(marker.exists(), 'Command ran without approval')

    def test_agent_cannot_read_protected_files(self) -> None:
        for path in PROTECTED:
            with self.subTest(path=str(path)):
                with self.assertRaises(PermissionError):
                    with path.open('rb'):
                        pass

    def test_agent_cannot_open_protected_files_for_writing(self) -> None:
        for path in PROTECTED:
            with self.subTest(path=str(path)):
                with self.assertRaises(PermissionError):
                    with path.open('ab'):
                        pass

    def test_agent_cannot_self_approve_even_with_matching_number(self) -> None:
        request_id, number, marker = self.request_marker()
        response = self.reply('approve', id=request_id, key_id='fixture', number=number, signature='00' * 64, share_output=True)
        self.assertIs(response.get('ok'), False, response)
        self.assertIn('peer cannot approve', str(response.get('error')))
        self.assertEqual(self.value('execution_status', id=request_id)['state'], 'pending')
        self.assertFalse(marker.exists(), 'Self-approval launched a command')

    def test_cancellation_keeps_command_unexecuted(self) -> None:
        request_id, _, marker = self.request_marker()
        self.value('cancel_execution', id=request_id)
        status = self.value('execution_status', id=request_id)
        self.assertEqual(status['state'], 'cancelled')
        self.assertIsNone(status['outcome'])
        self.assertFalse(marker.exists(), 'Cancelled command ran')


if __name__ == '__main__':
    unittest.main(verbosity=2)
