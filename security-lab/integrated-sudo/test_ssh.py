"""Pinned OpenSSH review transport, loopback inside the disposable container only."""
from __future__ import annotations
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import time
import unittest
from typing import Any

source = importlib.util.spec_from_file_location('mcp_fixture', '/integration/test_mcp.py')
assert source and source.loader
mcp_fixture = importlib.util.module_from_spec(source)
source.loader.exec_module(mcp_fixture)
fixture = mcp_fixture.fixture
ROOT = Path('/lab')


class SshReview(mcp_fixture.McpSudo):
    # Select these cases by name; inherited MCP coverage still runs in its own suite.
    def setUp(self) -> None:
        super().setUp()
        self.root = ROOT / 'ssh'
        self.root.mkdir(mode=0o755, exist_ok=True); self.root.chmod(0o755)
        for name in ['host', 'client', 'wrong']:
            path = self.root/name
            path.unlink(missing_ok=True); path.with_suffix('.pub').unlink(missing_ok=True)
            fixture.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(path)],check=True)
        os.chown(self.root/'client',11003,11003)
        self.host_line = 'relay-test ' + (self.root/'host.pub').read_text()
        self.known = self.root/'known_hosts'; self.known.write_text(self.host_line);self.known.chmod(0o644)
        authorized = self.root/'authorized_keys'
        authorized.write_text('restrict ' + (self.root/'client.pub').read_text());authorized.chmod(0o644)
        config = self.root/'sshd_config'
        config.write_text(f'''Port 2222
ListenAddress 127.0.0.1
HostKey {self.root}/host
PidFile {self.root}/sshd.pid
AuthorizedKeysFile {authorized}
StrictModes yes
AllowUsers approver
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
PermitTTY no
X11Forwarding no
PermitUserEnvironment no
ForceCommand /usr/local/bin/integrated-sudo-lab review-channel
LogLevel ERROR
''')
        Path('/run/sshd').mkdir(mode=0o755, exist_ok=True)
        daemon = subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(config)],
                                  stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                  text=True,start_new_session=True)
        self.children.append(daemon)
        time.sleep(.1);self.assertIsNone(daemon.poll(), 'fixture sshd failed')

    def target(self, ttl: int = 30) -> tuple[subprocess.Popen[str], str]:
        _, socket = self.start(ttl=ttl)
        path = ROOT/'ssh-target.json';path.write_text(json.dumps({'socket':socket}));path.chmod(0o644)
        return self.mcp(socket), socket

    def ssh(self, request: dict[str,Any], known: Path | None = None, command: str = 'review') -> subprocess.CompletedProcess[bytes]:
        argv = ['/usr/bin/ssh','-F','/dev/null','-T',
                '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=relay-test',
                '-o',f'UserKnownHostsFile={known or self.known}','-o','GlobalKnownHostsFile=/dev/null',
                '-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','ForwardAgent=no',
                '-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','ControlPath=none',
                '-o','ConnectTimeout=3','-o','ConnectionAttempts=1',
                '-i',str(self.root/'client'),'-p','2222','approver@127.0.0.1',command]
        return fixture.run(argv,user=11003,group=11003,extra_groups=[11004],input=json.dumps(request).encode())

    def test_ssh_pinned_review_and_one_execution(self) -> None:
        mcp, socket = self.target();view = self.request(mcp)
        result = self.ssh({'method':'execution_status','id':view['envelope']['id']})
        self.assertEqual(result.returncode,0,result.stderr)
        remote = json.loads(result.stdout)
        self.assertEqual(remote['value']['pending'],view)
        proof = self.sign(socket,view,True)
        self.assertTrue(json.loads(self.ssh(proof).stdout)['ok'])
        self.assertEqual(self.complete(mcp,view['envelope']['id'])['outcome']['stdout'],'0\n')
        self.assertFalse(json.loads(self.ssh(proof).stdout)['ok'])

    def test_ssh_wrong_or_missing_host_pin_rejects_before_approval(self) -> None:
        mcp, socket = self.target();view = self.request(mcp,['/usr/bin/touch','/lab/effect_a'])
        proof = self.sign(socket,view)
        for contents in ['', 'relay-test '+(self.root/'wrong.pub').read_text()]:
            wrong = self.root/'bad_hosts';wrong.write_text(contents);wrong.chmod(0o644)
            result = self.ssh(proof,wrong)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b'Host key verification failed',result.stderr)
            status = self.value(self.tool(mcp,'execution_status',{'id':view['envelope']['id']}))
            self.assertEqual(status['state'],'pending');self.assertFalse((ROOT/'effect_a').exists())

    def test_ssh_forced_command_and_unsigned_approval_rejected(self) -> None:
        mcp, socket = self.target();view = self.request(mcp)
        status = {'method':'execution_status','id':view['envelope']['id']}
        result = self.ssh(status,command='/usr/bin/touch /lab/ssh-shell-must-not-run')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'])
        self.assertFalse((ROOT/'ssh-shell-must-not-run').exists())
        proof = self.sign(socket,view)
        self.assertFalse(json.loads(self.ssh({**proof,'signature':'00'*64}).stdout)['ok'])
        request = {'method':'request_execution','spec':view['envelope']['spec']}
        self.assertNotEqual(self.ssh(request).returncode,0)
        self.assertNotEqual(self.ssh({**proof,'method':'approve_receipt'}).returncode,0)

    def test_ssh_cancel_prevents_later_signed_approval(self) -> None:
        mcp, socket = self.target();view = self.request(mcp)
        proof = self.sign(socket,view)
        result = self.ssh({'method':'cancel_execution','id':view['envelope']['id']})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'])
        self.assertFalse(json.loads(self.ssh(proof).stdout)['ok'])
        status = self.value(self.tool(mcp,'execution_status',{'id':view['envelope']['id']}))
        self.assertEqual(status['state'],'cancelled')

    def test_ssh_unprotected_target_and_oversized_input_rejected(self) -> None:
        mcp, _ = self.target();view = self.request(mcp)
        request = {'method':'execution_status','id':view['envelope']['id']}
        path = ROOT/'ssh-target.json'
        path.chmod(0o666)
        result = self.ssh(request)
        self.assertNotEqual(result.returncode,0)
        path.chmod(0o644)
        result = self.ssh({**request,'padding':'x'*65536})
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'request too large',result.stderr)

    def test_ssh_exact_native_bridge_with_p256_execution_proof(self) -> None:
        # Replace only this disposable fixture's human key, before starting its broker.
        key = ROOT/'human/key.pem'
        fixture.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(key)],user=11003,group=11003,extra_groups=[],check=True)
        der = fixture.run(['openssl','pkey','-in',str(key),'-pubout','-outform','DER'],user=11003,group=11003,extra_groups=[],check=True).stdout
        self.assertEqual(len(der),91); self.assertEqual(der[-65],4)
        public = 'p256-sha256:'+der[-65:].hex()
        (ROOT/'human-public.hex').write_text(public)
        state = Path(json.loads(self.paths['sponsor_a'].read_text())['config']['state_dir'])
        (state/'keys/human.pub').unlink()
        fixture.run(['/usr/local/bin/integrated-sudo-lab',str(self.paths['sponsor_a']),'pair'],check=True)
        mcp,socket = self.target();view = self.request(mcp)
        self.known.write_text(self.host_line.replace('relay-test ','sudo-relay-linux ',1))
        identity = self.root/'client';os.chown(identity,0,11003);identity.chmod(0o440)
        enrollment = ROOT/'native-execution.json'
        enrollment.write_text(json.dumps({'version':1,'purpose':'disposable-linux-execution-v1','approver_uid':11003,
            'machine_id':view['envelope']['machine_id'],'machine_name':'Linux trial','operating_system':'Debian 13',
            'account':'sponsor_a','signing_key':public,'signing_key_id':'human','port':2222,
            'known_hosts':str(self.known),'identity':str(identity)}));enrollment.chmod(0o644)
        def bridge(operation: str, **extra: Any) -> subprocess.CompletedProcess[bytes]:
            return fixture.run(['/usr/local/bin/execution-review-check'],user=11003,group=11003,extra_groups=[11004],
                input=json.dumps({'operation':operation,'enrollment':str(enrollment),'id':view['envelope']['id'],**extra}).encode())
        fetched = bridge('fetch');self.assertEqual(fetched.returncode,0,fetched.stderr)
        self.assertEqual(json.loads(json.loads(fetched.stdout)['pending_json']),view)
        receipt = self.sign(socket,view,True,receipt=True)
        self.assertNotEqual(bridge('approve',signature=receipt['signature'],share_output=True).returncode,0)
        proof = self.sign(socket,view,True)
        result = bridge('approve',signature=proof['signature'],share_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),{'approved':True})
        self.assertEqual(self.complete(mcp,view['envelope']['id'])['outcome']['stdout'],'0\n')
        self.assertNotEqual(bridge('approve',signature=proof['signature'],share_output=True).returncode,0)
        evidence=fixture.command_log((ROOT/'sudo.log').read_text())
        self.assertEqual(evidence['sudo_launches'],1)
        self.assertEqual(evidence['sudo_completions'],1)
        self.assertTrue(evidence['sudo_log_valid'])
        self.assertEqual(evidence['sudo_command_record_count'],2)
        records=evidence['sudo_command_records']
        duplicate=fixture.command_log('\n'.join(records+records))
        self.assertEqual(duplicate['sudo_launches'],2)
        self.assertFalse(duplicate['sudo_log_valid'])
        second=fixture.command_log('\n'.join(records+[re.sub(r'TSID=[0-9A-Za-z]+','TSID=999999',line) for line in records]))
        self.assertEqual(second['sudo_launches'],2)
        self.assertTrue(second['sudo_log_valid'])
        self.assertFalse(fixture.command_log(records[0])['sudo_log_valid'])
        self.assertFalse(fixture.command_log('\n'.join(records).replace('sponsor_a','sponsor_b'))['sudo_log_valid'])



if __name__=='__main__':
    suite=unittest.TestSuite(SshReview(name) for name in unittest.defaultTestLoader.getTestCaseNames(SshReview)
                            if name.startswith('test_ssh_'))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
