"""Real MCP stdio -> authenticated Unix socket -> broker -> native sudo. Container only."""
from __future__ import annotations
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import unittest
from typing import Any

# Reuse only setup/helpers; previous milestone tests still run separately.
source = importlib.util.spec_from_file_location('fixture', '/integration/test_integration.py')
assert source and source.loader
fixture = importlib.util.module_from_spec(source)
source.loader.exec_module(fixture)
ROOT = Path('/lab')


class McpSudo(unittest.TestCase):
    setUpClass = classmethod(fixture.IntegratedSudo.setUpClass.__func__)
    setUp = fixture.IntegratedSudo.setUp
    stop_all = fixture.IntegratedSudo.stop_all
    wait_checkpoint = fixture.IntegratedSudo.wait_checkpoint
    count_marker_launches = fixture.IntegratedSudo.count_marker_launches

    def start(self, user: str = 'sponsor_a', ttl: int = 30) -> tuple[subprocess.Popen[str], str]:
        path = self.paths[user]
        data = json.loads(path.read_text())
        # Keep state private; expose only a separate root-owned, traversable socket directory.
        public = ROOT / ('socket-' + user)
        public.mkdir(mode=0o755, exist_ok=True)
        os.chmod(public, 0o755)
        socket = str(public / 'broker.sock')
        Path(socket).unlink(missing_ok=True)
        data['config']['socket'] = socket
        data['config']['approval_ttl_secs'] = ttl
        path.write_text(json.dumps(data))
        broker = subprocess.Popen(['/usr/local/bin/integrated-sudo-lab', str(path), 'serve'],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, start_new_session=True)
        self.children.append(broker)
        deadline = time.monotonic() + 5
        while not Path(socket).exists() and broker.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertIsNone(broker.poll(), 'socket broker failed to start')
        self.assertTrue(Path(socket).exists())
        return broker, socket

    def mcp(self, socket: str) -> subprocess.Popen[str]:
        process = subprocess.Popen(['/usr/local/bin/mcp-server', socket, '/integration/approval.html'],
                                   user=11004, group=11004, extra_groups=[], cwd='/',
                                   env={'PATH': '/usr/bin:/bin'}, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        self.children.append(process)
        result = self.rpc(process, 'initialize', {'protocolVersion': '2025-06-18',
                          'capabilities': {}, 'clientInfo': {'name': 'isolated-test', 'version': '1'}})
        self.assertIn('result', result)
        assert process.stdin
        process.stdin.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n')
        process.stdin.flush()
        return process

    def rpc(self, process: subprocess.Popen[str], method: str, params: dict[str, Any]) -> dict[str, Any]:
        assert process.stdin and process.stdout
        process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}) + '\n')
        process.stdin.flush()
        self.assertTrue(select.select([process.stdout], [], [], 15)[0], 'MCP response timed out')
        return json.loads(process.stdout.readline())

    def tool(self, process: subprocess.Popen[str], name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.rpc(process, 'tools/call', {'name': name, 'arguments': arguments})

    def value(self, response: dict[str, Any]) -> dict[str, Any]:
        self.assertNotIn('error', response, response)
        self.assertFalse(response['result'].get('isError'), response)
        return response['result']['structuredContent']

    def request(self, process: subprocess.Popen[str], argv: list[str] | None = None, needed: bool = False) -> dict[str, Any]:
        return self.value(self.tool(process, 'request_execution', {'spec': {
            'command': {'kind': 'argv', 'argv': argv or ['/usr/bin/id', '-u']},
            'env': {}, 'reason': 'Real MCP disposable Linux test', 'timeout_secs': 5, 'output_needed': needed}}))

    def client(self, socket: str, operation: str, data: dict[str, Any], uid: int = 11003) -> dict[str, Any]:
        result = fixture.run([sys.executable, '-I', '/integration/approver.py', socket, operation],
                             user=uid, group=uid, extra_groups=[11004], input=json.dumps(data).encode(), check=True)
        return json.loads(result.stdout)

    def sign(self, socket: str, view: dict[str, Any], share: bool = False, **changes: bool) -> dict[str, Any]:
        return self.client(socket, 'sign', {'id': view['envelope']['id'], 'share_output': share, **changes})

    def complete(self, process: subprocess.Popen[str], request_id: str) -> dict[str, Any]:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status = self.value(self.tool(process, 'execution_status', {'id': request_id}))
            if status['state'] == 'complete':
                return status
            time.sleep(.02)
        self.fail(f'execution did not complete: {status}')

    def test_actual_mcp_tools_peer_separation_and_success(self) -> None:
        _, socket = self.start(); mcp = self.mcp(socket)
        listed = self.rpc(mcp, 'tools/list', {})
        self.assertEqual({tool['name'] for tool in listed['result']['tools']},
                         {'request_execution', 'execution_status', 'cancel_execution'})
        view = self.request(mcp); approval = self.sign(socket, view, True)
        self.assertEqual(view, self.value(self.tool(mcp, 'execution_status', {'id': view['envelope']['id']}))['pending'])
        unavailable = self.tool(mcp, 'approve', approval)
        self.assertTrue('error' in unavailable or unavailable['result'].get('isError'))
        # Even possession of a valid signature cannot give the agent the approver's socket role.
        rejected = self.client(socket, 'submit', approval, 11004)
        self.assertFalse(rejected['ok']); self.assertIn('peer cannot approve', rejected['error'])
        self.assertFalse(self.client(socket, 'submit', approval, 11002)['ok'])
        self.assertTrue(self.client(socket, 'submit', approval)['ok'])
        status = self.complete(mcp, view['envelope']['id'])
        self.assertTrue(status['output_shared']); self.assertEqual(status['outcome']['stdout'], '0\n')
        self.assertEqual(status['outcome']['exit_code'], 0)
        self.assertFalse(self.client(socket, 'submit', approval)['ok'])
        log = (ROOT/'sudo.log').read_text().replace('\n    ', ' ')
        self.assertRegex(log, r'sponsor_a\s*:.*USER=root.*COMMAND=/usr/bin/id -u')

    def test_signed_output_choice_and_limits(self) -> None:
        _, socket = self.start(); mcp = self.mcp(socket)
        for share in [False, True] * 5:
            view = self.request(mcp, ['/usr/local/bin/output-probe'], needed=True)
            approval = self.sign(socket, view, share)
            self.assertFalse(self.client(socket, 'submit', {**approval, 'share_output': not share})['ok'])
            self.assertTrue(self.client(socket, 'submit', approval)['ok'])
            status = self.complete(mcp, view['envelope']['id']); outcome = status['outcome']
            self.assertEqual(status['output_shared'], share)
            self.assertEqual(outcome['exit_code'], 0)
            if share:
                self.assertTrue(outcome['stdout'].startswith('STDOUT-CANARY:'))
                self.assertEqual(len(outcome['stdout']), 1024 * 1024)
                self.assertEqual(outcome['stderr'], 'STDERR-CANARY'); self.assertTrue(outcome['truncated'])
            else:
                self.assertEqual(outcome['stdout'], ''); self.assertEqual(outcome['stderr'], '')
                self.assertFalse(outcome['truncated'])
                self.assertNotIn('STDOUT-CANARY', json.dumps(status)); self.assertNotIn('STDERR-CANARY', json.dumps(status))

    def test_altered_receipt_and_cross_enrollment_proofs(self) -> None:
        _, socket = self.start(); mcp = self.mcp(socket)
        view = self.request(mcp, ['/usr/bin/touch', '/lab/effect_a'])
        for changes in [{'alter_command': True}, {'receipt': True}]:
            self.assertFalse(self.client(socket, 'submit', self.sign(socket, view, **changes))['ok'])
        approval = self.sign(socket, view)
        _, other_socket = self.start('sponsor_b'); other_mcp = self.mcp(other_socket)
        other = self.request(other_mcp)
        cross = {**approval, 'id': other['envelope']['id'], 'number': other['envelope']['number']}
        self.assertFalse(self.client(other_socket, 'submit', cross)['ok'])
        self.assertFalse((ROOT/'effect_a').exists()); self.assertFalse((ROOT/'effect_b').exists())

    def test_concurrent_approval_consumes_once(self) -> None:
        _, socket = self.start(); mcp = self.mcp(socket)
        view = self.request(mcp, ['/usr/bin/touch', '/lab/effect_a']); approval = self.sign(socket, view)
        before = self.count_marker_launches()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            attempts = [workers.submit(self.client, socket, 'submit', approval) for _ in range(2)]
            replies = [attempt.result(timeout=10) for attempt in attempts]
        self.assertEqual(sum(reply['ok'] for reply in replies), 1)
        self.assertEqual(self.complete(mcp, view['envelope']['id'])['outcome']['exit_code'], 0)
        self.assertEqual(self.count_marker_launches(), before + 1)

    def test_mcp_cancellation_and_expiry(self) -> None:
        _, socket = self.start(ttl=2); mcp = self.mcp(socket)
        view = self.request(mcp); approval = self.sign(socket, view)
        self.value(self.tool(mcp, 'cancel_execution', {'id': view['envelope']['id']}))
        self.assertFalse(self.client(socket, 'submit', approval)['ok'])
        view = self.request(mcp); approval = self.sign(socket, view)
        time.sleep(2.1)
        self.assertFalse(self.client(socket, 'submit', approval)['ok'])
        status = self.value(self.tool(mcp, 'execution_status', {'id': view['envelope']['id']}))
        self.assertEqual(status['state'], 'expired'); self.assertIsNone(status['outcome'])

    def test_revocation_and_nopasswd_through_mcp(self) -> None:
        _, socket = self.start(); mcp = self.mcp(socket)
        view = self.request(mcp, ['/usr/bin/touch', '/lab/effect_a']); approval = self.sign(socket, view)
        fixture.policy('sponsor_a', None)
        self.assertTrue(self.client(socket, 'submit', approval)['ok'])  # consumption is not launch success
        status = self.complete(mcp, view['envelope']['id'])
        self.assertIsNotNone(status['outcome']['error']); self.assertFalse((ROOT/'effect_a').exists())
        denied = self.tool(mcp, 'request_execution', {'spec': view['envelope']['spec']})
        self.assertTrue(denied['result']['isError'])
        fixture.policy('sponsor_a', password=False)
        view = self.request(mcp); approval = self.sign(socket, view)
        self.assertFalse(self.client(socket, 'submit', {**approval, 'signature': '00'*64})['ok'])
        self.assertTrue(self.client(socket, 'submit', approval)['ok'])
        self.assertEqual(self.complete(mcp, view['envelope']['id'])['outcome']['exit_code'], 0)

    def test_approver_disconnect_mcp_reconnect_and_replay(self) -> None:
        _, socket = self.start(); mcp = self.mcp(socket)
        view = self.request(mcp, ['/usr/bin/touch', '/lab/effect_a']); approval = self.sign(socket, view)
        self.client(socket, 'disconnect', approval)
        mcp.kill(); mcp.wait()
        connected = self.mcp(socket)
        self.assertEqual(self.complete(connected, view['envelope']['id'])['outcome']['exit_code'], 0)
        self.assertTrue((ROOT/'effect_a').exists()); count = self.count_marker_launches()
        self.assertFalse(self.client(socket, 'submit', approval)['ok'])
        self.assertEqual(self.count_marker_launches(), count)

    def test_broker_disconnect_before_launch_is_uncertain_no_retry(self) -> None:
        broker, socket = self.start(); mcp = self.mcp(socket)
        view = self.request(mcp, ['/usr/bin/touch', '/lab/effect_a']); approval = self.sign(socket, view)
        (ROOT/'fault').write_text('after-consumption')
        self.assertTrue(self.client(socket, 'submit', approval)['ok']); self.wait_checkpoint()
        os.killpg(broker.pid, signal.SIGKILL); broker.wait()
        self.assertFalse((ROOT/'effect_a').exists())
        failure = self.tool(mcp, 'execution_status', {'id': view['envelope']['id']})
        self.assertTrue(failure['result']['isError'])
        Path(socket).unlink(); (ROOT/'fault').unlink()
        self.start()
        status = self.value(self.tool(mcp, 'execution_status', {'id': view['envelope']['id']}))
        self.assertEqual(status['state'], 'uncertain'); self.assertIsNone(status['outcome'])
        self.assertFalse(self.client(socket, 'submit', approval)['ok'])
        self.assertFalse((ROOT/'effect_a').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
