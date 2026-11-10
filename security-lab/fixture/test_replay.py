"""Authorized signing controls inside the fixture, never a production signer."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import unittest
import uuid

AGENT = 10001
APPROVER = 10002
SIGN = '''import subprocess,sys,tempfile
with tempfile.NamedTemporaryFile(dir='/lab/approver') as payload:
 payload.write(bytes.fromhex(sys.argv[1]));payload.flush()
 signature=subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-inkey','/lab/approver/key.pem','-in',payload.name])
 print(signature.hex())
'''


class BrokerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.assertEqual(os.geteuid(), 0, 'Run as the disposable fixture controller')
        self.assertEqual(os.environ.get('PE_DISPOSABLE_FIXTURE'), '1')
        self.assertTrue(Path('/.dockerenv').exists())

    def call(self, uid: int, request: dict[str, object]) -> dict[str, object]:
        reply = json.loads(subprocess.check_output([
            'python', '/fixture/rpc.py', json.dumps(request),
        ], user=uid, group=AGENT, extra_groups=[], text=True, timeout=15))
        if not isinstance(reply, dict):
            raise AssertionError('Expected a broker response object')
        return reply

    def value(self, reply: dict[str, object]) -> dict[str, object]:
        self.assertIs(reply.get('ok'), True, reply)
        value = reply.get('value')
        if not isinstance(value, dict):
            raise AssertionError('Expected a successful response object')
        return value

    def request(self, spec: dict[str, object]) -> dict[str, object]:
        pending = self.value(self.call(AGENT, {'method': 'request_execution', 'spec': spec}))
        envelope = pending.get('envelope')
        if not isinstance(envelope, dict) or not isinstance(envelope.get('id'), str):
            raise AssertionError('Expected a request envelope')
        self.addCleanup(self.cancel_if_pending, envelope['id'])
        return pending

    def cancel_if_pending(self, request_id: str) -> None:
        status = self.value(self.call(AGENT, {'method': 'execution_status', 'id': request_id}))
        if status['state'] == 'pending':
            self.value(self.call(AGENT, {'method': 'cancel_execution', 'id': request_id}))
        else:
            self.assertEqual(status['state'], 'complete')

    def sign(self, pending: dict[str, object], share_output: bool = True) -> dict[str, object]:
        envelope = pending.get('envelope')
        payload = pending.get('signing_payload')
        if not isinstance(envelope, dict) or not isinstance(payload, str):
            raise AssertionError('Expected a signing payload and envelope')
        decision = subprocess.check_output(['fixture-approval-payload', payload, str(share_output).lower()],
            user=APPROVER, group=AGENT, extra_groups=[], text=True, timeout=5).strip()
        signature = subprocess.check_output(['python', '-c', SIGN, decision],
            user=APPROVER, group=AGENT, extra_groups=[], text=True, timeout=5).strip()
        self.assertEqual(len(signature), 128)
        return {'method': 'approve', 'id': envelope['id'], 'key_id': 'fixture',
                'number': envelope['number'], 'signature': signature, 'share_output': share_output}

    def status(self, request_id: object) -> dict[str, object]:
        return self.value(self.call(AGENT, {'method': 'execution_status', 'id': request_id}))

    def launch_count(self, request_id: object) -> int:
        with sqlite3.connect('file:/lab/state/state.sqlite3?mode=ro', uri=True) as database:
            return database.execute("SELECT COUNT(*) FROM audit WHERE id=? AND event='running'",
                                    (request_id,)).fetchone()[0]

    def approved_command(self) -> tuple[dict[str, object], dict[str, object], Path]:
        marker = Path('/lab') / f'executed-{uuid.uuid4()}'
        self.addCleanup(marker.unlink, missing_ok=True)
        spec: dict[str, object] = {
            'command': {'kind': 'script', 'interpreter': '/bin/sh',
                        'script': f"printf '%s\\n' executed >> '{marker}'"},
            'env': {}, 'reason': 'Authorized disposable replay test', 'timeout_secs': 2,
        }
        approval = self.sign(self.request(spec))
        self.value(self.call(APPROVER, approval))
        self.finish(approval)
        self.assertEqual(marker.read_text(), 'executed\n')
        self.assertEqual(self.launch_count(approval['id']), 1)
        return spec, approval, marker

    def finish(self, approval: dict[str, object]) -> dict[str, object]:
        deadline = time.monotonic() + 5
        while (status := self.status(approval['id']))['state'] != 'complete':
            if time.monotonic() >= deadline:
                self.fail(f'Approved command did not complete: {status}')
            time.sleep(0.02)
        outcome = status.get('outcome')
        if not isinstance(outcome, dict):
            raise AssertionError('Expected an execution result')
        self.assertEqual(outcome['exit_code'], 0, outcome)
        return outcome

    def assert_transplant_rejected(self, approval: dict[str, object], spec: dict[str, object]) -> None:
        pending = self.request(spec)
        envelope = pending.get('envelope')
        if not isinstance(envelope, dict):
            raise AssertionError('Expected a request envelope')
        transplanted = {**approval, 'id': envelope['id'], 'number': envelope['number']}
        reply = self.call(APPROVER, transplanted)
        self.assertIs(reply.get('ok'), False, reply)
        self.assertIn('invalid approval signature', str(reply.get('error')))
        self.assertEqual(self.status(envelope['id'])['state'], 'pending')
        self.assertEqual(self.launch_count(envelope['id']), 0)


class ApprovalReplayTest(BrokerTestCase):
    def test_same_request_cannot_substitute_command(self) -> None:
        spec: dict[str, object] = {
            'command': {'kind': 'argv', 'argv': ['/usr/bin/printf', 'approved']},
            'env': {}, 'reason': 'Command-binding fixture', 'timeout_secs': 2,
        }
        pending = self.request(spec)
        approval = self.sign(pending)
        # Keep the valid approval but try supplying a replacement command on the wire.
        injected = self.call(APPROVER, {**approval, 'spec': {
            **spec, 'command': {'kind': 'argv', 'argv': ['/usr/bin/printf', 'tampered']},
        }})
        self.assertIs(injected.get('ok'), False, injected)
        self.assertIn('unknown field', str(injected.get('error')))

        payload_hex = pending.get('signing_payload')
        if not isinstance(payload_hex, str):
            raise AssertionError('Expected a signing payload')
        payload = bytes.fromhex(payload_hex)
        # Equal-length, unique replacements change only one CBOR text value.
        for original, replacement in [(b'/usr/bin/printf', b'/usr/bin/whoami'), (b'approved', b'tampered')]:
            with self.subTest(replacement=replacement.decode()):
                self.assertEqual(len(original), len(replacement))
                self.assertEqual(payload.count(original), 1)
                altered = {**pending, 'signing_payload': payload.replace(original, replacement).hex()}
                substituted = self.sign(altered)
                self.assertEqual({**substituted, 'signature': approval['signature']}, approval)
                rejected = self.call(APPROVER, substituted)
                self.assertIs(rejected.get('ok'), False, rejected)
                self.assertIn('invalid approval signature', str(rejected.get('error')))
                self.assertEqual(self.status(approval['id'])['state'], 'pending')
                self.assertEqual(self.launch_count(approval['id']), 0)

        # The untouched approval must still execute exactly the original argument.
        self.value(self.call(APPROVER, approval))
        outcome = self.finish(approval)
        self.assertEqual(outcome['stdout'], 'approved')
        self.assertEqual(self.launch_count(approval['id']), 1)

    def test_replay_and_identical_new_request_cannot_reuse_approval(self) -> None:
        spec, approval, marker = self.approved_command()
        for attempt in range(3):
            with self.subTest(replay=attempt):
                reply = self.call(APPROVER, approval)
                self.assertIs(reply.get('ok'), False, reply)
                self.assertIn('request is not pending', str(reply.get('error')))
        self.assert_transplant_rejected(approval, spec)
        self.assertEqual(marker.read_text(), 'executed\n')
        self.assertEqual(self.launch_count(approval['id']), 1)

    def test_approval_cannot_run_a_different_command(self) -> None:
        spec, approval, original_marker = self.approved_command()
        changed_marker = Path('/lab') / f'different-{uuid.uuid4()}'
        self.addCleanup(changed_marker.unlink, missing_ok=True)
        changed_spec = {**spec, 'command': {'kind': 'script', 'interpreter': '/bin/sh',
            'script': f"printf '%s\\n' different >> '{changed_marker}'"}}
        self.assert_transplant_rejected(approval, changed_spec)
        self.assertFalse(changed_marker.exists())
        self.assertEqual(original_marker.read_text(), 'executed\n')
        self.assertEqual(self.launch_count(approval['id']), 1)



class ApprovalOutputTest(BrokerTestCase):
    def test_output_is_shared_only_when_approved_even_if_agent_needs_it(self) -> None:
        secret = Path('/lab/fake-secret').read_text()
        withheld_ids: list[object] = []
        for share in [False, True]:
            for needed in [False, True]:
                with self.subTest(share=share, needed=needed):
                    pending = self.request({
                        'command': {'kind': 'script', 'interpreter': '/bin/sh',
                            'script': 'cat /lab/fake-secret; cat /lab/fake-secret >&2; exit 7'},
                        'env': {}, 'reason': 'Output privacy fixture', 'timeout_secs': 2,
                        'output_needed': needed,
                    })
                    approval = self.sign(pending, share)
                    self.value(self.call(APPROVER, approval))
                    # A nonzero exit code still reports completion and follows sharing policy.
                    deadline = time.monotonic() + 5
                    while (status := self.status(approval['id']))['state'] != 'complete':
                        if time.monotonic() >= deadline: self.fail('Output test did not complete')
                        time.sleep(0.02)
                    self.assertIs(status['output_shared'], share)
                    outcome = status.get('outcome')
                    if not isinstance(outcome, dict): raise AssertionError('Missing outcome')
                    self.assertEqual(outcome['exit_code'], 7)
                    self.assertEqual(outcome['stdout'], secret if share else '')
                    self.assertEqual(outcome['stderr'], secret if share else '')
                    # Check repeat reads so a later status call cannot disclose withheld content.
                    self.assertEqual(secret in json.dumps(self.status(approval['id'])), share)
                    self.assertEqual(self.launch_count(approval['id']), 1)
                    if not share:
                        withheld_ids.append(approval['id'])
        for request_id in withheld_ids:
            status = self.status(request_id)
            self.assertIs(status['output_shared'], False)
            self.assertNotIn(secret, json.dumps(status), 'Later opt-in disclosed earlier withheld output')
        with sqlite3.connect('file:/lab/state/state.sqlite3?mode=ro', uri=True) as database:
            self.assertFalse(any(secret in statement for statement in database.iterdump()), 'Output persisted in ledger')

    def test_output_choice_is_required_boolean_and_bound_to_signature(self) -> None:
        for share in [False, True]:
            with self.subTest(share=share):
                pending = self.request({
                    'command': {'kind': 'argv', 'argv': ['/usr/bin/printf', 'fixture-output']},
                    'env': {}, 'reason': 'Output choice signature fixture', 'timeout_secs': 2,
                })
                approval = self.sign(pending, share)
                for invalid in [not share, 'true', 0, None]:
                    reply = self.call(APPROVER, {**approval, 'share_output': invalid})
                    self.assertIs(reply.get('ok'), False, reply)
                    if type(invalid) is bool:
                        self.assertIn('invalid approval signature', str(reply.get('error')))
                missing = {key: value for key, value in approval.items() if key != 'share_output'}
                self.assertIs(self.call(APPROVER, missing).get('ok'), False)
                self.assertEqual(self.status(approval['id'])['state'], 'pending')
                self.assertEqual(self.launch_count(approval['id']), 0)
                self.value(self.call(APPROVER, approval))
                outcome = self.finish(approval)
                self.assertEqual(outcome['stdout'], 'fixture-output' if share else '')

    def test_agent_cannot_set_sharing_in_execution_request(self) -> None:
        reply = self.call(AGENT, {'method': 'request_execution', 'spec': {
            'command': {'kind': 'argv', 'argv': ['/usr/bin/printf', 'not executed']},
            'share_output': True,
        }})
        self.assertIs(reply.get('ok'), False, reply)
        self.assertIn('unknown field', str(reply.get('error')))

if __name__ == '__main__':
    unittest.main(verbosity=2)
