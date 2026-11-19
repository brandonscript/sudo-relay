"""Disposable-root integration tests; software signing simulates explicit human approval."""
from __future__ import annotations
import copy
import json
import os
import re
from pathlib import Path
import select
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import unittest
import uuid
from typing import Any

ROOT = Path('/lab')
USERS = {'sponsor_a': 11001, 'sponsor_b': 11002}
INSTALL = '/usr/local/bin/python3 -I /integration/launcher.py enroll'
SIGN = """import subprocess,sys,tempfile
with tempfile.NamedTemporaryFile(dir='/lab/human') as f:
 f.write(bytes.fromhex(sys.argv[1]));f.flush()
 print(subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-inkey','/lab/human/key.pem','-in',f.name]).hex())
"""

def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(argv, capture_output=True, timeout=10, **kwargs)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f'{argv}: {error.stderr.decode()}') from error


def command_log(log: str) -> dict[str, Any]:
    """Count launch records separately from sudo log_exit_status records."""
    records=[line for line in log.replace('\n    ',' ').splitlines()
             if 'COMMAND=/usr/bin/id -u' in line]
    starts: list[str]=[];exits: list[str]=[];valid=True
    for line in records:
        match=re.fullmatch(r'.+ : sponsor_a : PWD=[^;]+ ; USER=root ; TSID=([0-9A-Za-z]+) ; COMMAND=/usr/bin/id -u( ; EXIT=0)?',line)
        if match is None:
            valid=False
            continue
        (exits if match[2] else starts).append(match[1])
    return {'sudo_launches':len(starts),'sudo_completions':len(exits),
            'sudo_log_valid':valid and len(starts)==len(set(starts)) and sorted(starts)==sorted(exits),
            'sponsor_logged':bool(starts),'sudo_command_records':records[:16],
            'sudo_command_record_count':len(records)}


def policy(user: str, commands: str | None = 'ALL', password: bool = True) -> None:
    path = Path('/etc/sudoers.d') / user
    path.unlink(missing_ok=True)
    if commands is not None:
        path.write_text(f'{user} ALL=(root) {"PASSWD" if password else "NOPASSWD"}: {commands}\n')
        path.chmod(0o440)
    run(['/usr/sbin/visudo', '-c'], check=True)


def initialize_fixture(public_key: str | None = None) -> None:
    if not Path('/.dockerenv').exists() or not ROOT.is_mount() or any(ROOT.iterdir()) or os.getuid() != 0:
        raise RuntimeError('fresh disposable Docker fixture required')
    os.umask(0o077)
    (ROOT / 'integration-fixture').write_text('disposable')
    (ROOT / 'enrollments').mkdir(mode=0o700)
    (ROOT / 'grants').mkdir(mode=0o700)
    (ROOT / 'human').mkdir(mode=0o700)
    (ROOT / 'machine').write_text(str(uuid.uuid4()))
    pairs = [('internal-key.pem', 'public.hex')]
    if public_key is None:
        pairs.append(('human/key.pem', 'human-public.hex'))
    else:
        if not public_key.startswith('p256-sha256:') or len(public_key) != 142:
            raise RuntimeError('external P-256 approval public key required')
        (ROOT/'human-public.hex').write_text(public_key)
    for key, public in pairs:
        run(['openssl','genpkey','-algorithm','Ed25519','-out', str(ROOT/key)], check=True)
        der = run(['openssl','pkey','-in',str(ROOT/key),'-pubout','-outform','DER'],check=True).stdout
        assert len(der)==44 and der[:12].hex()=='302a300506032b6570032100'
        (ROOT/public).write_text(der[12:].hex())
    if public_key is None:
        os.chown(ROOT/'human/key.pem',11003,11003)
    os.chown(ROOT/'human',11003,11003)
    defaults=Path('/etc/sudoers.d/00-integration')
    defaults.write_text('Defaults timestamp_timeout=5, timestamp_type=global, passwd_tries=1, lecture=never, !use_pty\n'
                        'Defaults pam_service="sudo-relay", pam_askpass_service="sudo-relay"\n'
                        'Defaults logfile="/lab/sudo.log", log_year, log_exit_status, log_output, iolog_dir="/lab/io"\n')
    defaults.chmod(0o440)
    if public_key is None:
        print(run(['/usr/bin/sudo','--version'],check=True).stdout.decode().splitlines()[0])


class IntegratedSudo(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        initialize_fixture()

    def setUp(self) -> None:
        self.children: list[subprocess.Popen[str]]=[]
        self.paths: dict[str, Path]={}
        for name in ['fault','checkpoint','continue','effect_a','effect_b']:
            (ROOT/name).unlink(missing_ok=True)
        shutil.rmtree(ROOT/'enrollments');(ROOT/'enrollments').mkdir(mode=0o700)
        for user, uid in USERS.items():
            run(['/usr/bin/sudo','-K'],user=uid,group=uid,extra_groups=[])
            policy(user, INSTALL, False)
            # Forged variables in caller environment must be replaced by sudo.
            result=run(['/usr/bin/sudo','-n','--','/usr/local/bin/python3','-I','/integration/launcher.py','enroll'],
                       user=uid,group=uid,extra_groups=[],env={'PATH':'/usr/bin:/bin','SUDO_UID':'0','SUDO_USER':'root'},check=True)
            record=json.loads(result.stdout)
            self.assertEqual(record['sponsor']['uid'],uid)
            self.paths[user]=Path(record['enrollment'])
            policy(user)
        self.addCleanup(self.stop_all)

    def start(self, user: str='sponsor_a', ttl: int=30) -> subprocess.Popen[str]:
        path=self.paths[user]
        data=json.loads(path.read_text());data['config']['approval_ttl_secs']=ttl;path.write_text(json.dumps(data))
        child=subprocess.Popen(['/usr/local/bin/integrated-sudo-lab',str(path)],stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        self.children.append(child)
        return child

    def stop_all(self) -> None:
        for child in self.children:
            if child.poll() is None:
                os.killpg(child.pid,signal.SIGKILL)
            child.wait(timeout=5)
            for stream in [child.stdin,child.stdout,child.stderr]:
                if stream:stream.close()

    def send(self, child: subprocess.Popen[str], message: dict[str,Any]) -> None:
        assert child.stdin
        child.stdin.write(json.dumps(message)+'\n');child.stdin.flush()

    def receive(self, child: subprocess.Popen[str]) -> dict[str,Any]:
        assert child.stdout
        self.assertTrue(select.select([child.stdout],[],[],15)[0], 'broker response timeout')
        line=child.stdout.readline()
        self.assertTrue(line, f'broker exited {child.poll()}')
        return json.loads(line)

    def rpc(self, child: subprocess.Popen[str], message: dict[str,Any]) -> dict[str,Any]:
        self.send(child,message);return self.receive(child)

    def request(self, child: subprocess.Popen[str], argv: list[str] | None=None) -> dict[str,Any]:
        result=self.rpc(child,{'method':'request_execution','spec':{'command':{'kind':'argv','argv':argv or ['/usr/bin/id','-u']},'env':{},'reason':'Disposable Linux integration','timeout_secs':5,'output_needed':False}})
        self.assertTrue(result['ok'],result)
        return result['value']

    def approval(self, view: dict[str,Any], receipt: bool=False) -> dict[str,Any]:
        signature=run([sys.executable,'-I','-c',SIGN,view['receipt_payload' if receipt else 'approval_payload']],
                      user=11003,group=11003,extra_groups=[],check=True).stdout.decode().strip()
        env=view['envelope']
        return {'method':'approve','id':env['id'],'key_id':'human','number':env['number'],'signature':signature,'share_output':False}

    def wait_checkpoint(self) -> None:
        deadline=time.monotonic()+10
        while not (ROOT/'checkpoint').exists() and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue((ROOT/'checkpoint').exists())

    def state(self,user: str,request_id: str) -> str:
        path=self.paths[user].parent/'state'/'state.sqlite3'
        with sqlite3.connect(path) as db:
            return str(db.execute('SELECT state FROM requests WHERE id=?',(request_id,)).fetchone()[0])

    def test_enrollment_and_valid_execution_attribution(self) -> None:
        for user in USERS:
            child=self.start(user);view=self.request(child)
            result=self.rpc(child,self.approval(view));self.assertTrue(result['ok'],result)
            self.assertEqual(result['value']['launch']['exit_code'],0)
            self.assertTrue(result['value']['launch']['root_uid_observed'])
            self.assertRegex((ROOT/'sudo.log').read_text().replace('\n    ', ' '),rf'{user}\s*:.*USER=root.*COMMAND=/usr/bin/id -u')

    def test_replay_changed_signature_cross_account_and_receipt_proof(self) -> None:
        child=self.start();view=self.request(child);approval=self.approval(view)
        forged={**approval,'signature':'00'*64}
        self.assertFalse(self.rpc(child,forged)['ok'])
        changed=copy.deepcopy(view)
        payload=bytes.fromhex(changed['approval_payload'])
        changed['approval_payload']=payload.replace(b'/usr/bin/id',b'/usr/bin/dd').hex()
        self.assertNotEqual(changed['approval_payload'],view['approval_payload'])
        self.assertFalse(self.rpc(child,self.approval(changed))['ok'])
        self.assertFalse(self.rpc(child,self.approval(view,True))['ok'])
        self.assertTrue(self.rpc(child,approval)['ok'])
        self.assertFalse(self.rpc(child,approval)['ok'])
        second=self.request(child,['/usr/bin/touch','/lab/effect_a'])
        self.assertFalse(self.rpc(child,{**approval,'id':second['envelope']['id'],'number':second['envelope']['number']})['ok'])
        other=self.start('sponsor_b');other_view=self.request(other)
        self.assertFalse(self.rpc(other,{**approval,'id':other_view['envelope']['id'],'number':other_view['envelope']['number']})['ok'])
        self.assertFalse((ROOT/'effect_a').exists())

    def test_expiry_and_denial(self) -> None:
        child=self.start(ttl=1);view=self.request(child);approval=self.approval(view)
        time.sleep(1.1);self.assertFalse(self.rpc(child,approval)['ok'])
        view=self.request(child);approval=self.approval(view)
        self.assertTrue(self.rpc(child,{'method':'cancel_execution','id':view['envelope']['id']})['ok'])
        self.assertFalse(self.rpc(child,approval)['ok'])

    def test_revocation_after_consumption_and_at_native_launch(self) -> None:
        for stage in ['after-consumption','before-sudo']:
            with self.subTest(stage=stage):
                policy('sponsor_a');child=self.start();view=self.request(child,['/usr/bin/touch','/lab/effect_a'])
                (ROOT/'fault').write_text(stage);self.send(child,self.approval(view));self.wait_checkpoint()
                policy('sponsor_a',None);(ROOT/'continue').touch()
                result=self.receive(child)
                self.assertTrue(not result['ok'] or result['value']['launch']['exit_code']!=0,result)
                self.assertFalse((ROOT/'effect_a').exists())
                child.kill();child.wait()
                for name in ['fault','checkpoint','continue']:(ROOT/name).unlink(missing_ok=True)
        other=self.start('sponsor_b');self.assertTrue(self.rpc(other,self.approval(self.request(other)))['ok'])

    def test_narrowed_command_policy_and_early_denial(self) -> None:
        child=self.start();view=self.request(child,['/usr/bin/touch','/lab/effect_a'])
        policy('sponsor_a','/usr/bin/id -u')
        self.assertFalse(self.rpc(child,self.approval(view))['ok'])
        self.assertFalse((ROOT/'effect_a').exists())
        result=self.rpc(child,{'method':'request_execution','spec':view['envelope']['spec']})
        self.assertFalse(result['ok'])


    def warm_cache_control(self) -> None:
        # Deliberately outside the supported launcher: create a real pre-existing timestamp.
        # The control omits -k and independently mints a disposable internal PAM ticket.
        argv=['/usr/bin/sudo','-S','-u','root','--','/usr/bin/id','-u']
        bootstrap="import os,sys; assert os.read(0,1)==b'G'; os.execv('/usr/bin/sudo',sys.argv[1:])"
        child=subprocess.Popen([sys.executable,'-I','-c',bootstrap,*argv],user=11001,group=11001,
                               extra_groups=[],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            start=Path(f'/proc/{child.pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
            grant={'domain':'sudo-relay/pam-prototype/v1','machine':(ROOT/'machine').read_text(),
                   'sponsor':'sponsor_a','uid':11001,'pid':child.pid,'start':start,
                   'expires':int(time.time())+30,'nonce':secrets.token_hex(32),'argv':argv}
            payload=json.dumps(grant,sort_keys=True,separators=(',',':')).encode()
            source=ROOT/'cache-control-payload';source.write_bytes(payload)
            signature=run(['openssl','pkeyutl','-sign','-rawin','-inkey','/lab/internal-key.pem','-in',str(source)],check=True).stdout
            (ROOT/'grants'/f'{child.pid}.json').write_text(json.dumps({'payload':payload.hex(),'signature':signature.hex()}))
            output,error=child.communicate(b'G',timeout=5)
            self.assertEqual(child.returncode,0,error);self.assertEqual(output,b'0\n')
            cached=run(['/usr/bin/sudo','-n','/usr/bin/id','-u'],user=11001,group=11001,extra_groups=[])
            self.assertEqual(cached.returncode,0,cached.stderr)
            self.assertEqual(cached.stdout,b'0\n')
        finally:
            if child.poll() is None:child.kill()
            child.wait(timeout=5)
            for stream in [child.stdin,child.stdout,child.stderr]:
                if stream:stream.close()
            (ROOT/'grants'/f'{child.pid}.json').unlink(missing_ok=True)

    def count_marker_launches(self) -> int:
        log=(ROOT/'sudo.log').read_text().replace('\n    ',' ')
        return sum('COMMAND=/usr/bin/touch /lab/effect_a' in line and 'EXIT=' not in line for line in log.splitlines())

    def test_competing_controller_and_expiry_after_consumption(self) -> None:
        child=self.start(ttl=2);view=self.request(child,['/usr/bin/touch','/lab/effect_a']);approval=self.approval(view)
        competitor=run(['/usr/local/bin/integrated-sudo-lab',str(self.paths['sponsor_a'])],input=b'')
        self.assertNotEqual(competitor.returncode,0)
        self.assertIn(b'broker already owns state',competitor.stderr)
        (ROOT/'fault').write_text('before-sudo');self.send(child,approval);self.wait_checkpoint()
        time.sleep(2.1);(ROOT/'continue').touch()
        self.assertFalse(self.receive(child)['ok']);self.assertFalse((ROOT/'effect_a').exists())
        self.assertFalse(self.rpc(child,approval)['ok'])

    def test_nopasswd_and_cache_do_not_replace_approval(self) -> None:
        policy('sponsor_a',password=False);child=self.start();view=self.request(child)
        self.assertFalse(self.rpc(child,{**self.approval(view),'signature':'00'*64})['ok'])
        self.assertTrue(self.rpc(child,self.approval(view))['ok'])
        ordinary=run(['/usr/bin/sudo','-n','/usr/bin/id','-u'],user=11001,group=11001,extra_groups=[])
        self.assertEqual(ordinary.returncode,0,ordinary.stderr)  # Existing NOPASSWD routes are outside the broker.
        policy('sponsor_a')
        self.warm_cache_control()
        fresh=self.request(child);self.assertFalse(self.rpc(child,{**self.approval(fresh),'signature':'00'*64})['ok'])
        policy('sponsor_a');run(['/usr/bin/sudo','-K'],user=11001,group=11001,extra_groups=[],check=True)
        self.assertTrue(self.rpc(child,self.approval(fresh))['ok'])
        ordinary=run(['/usr/bin/sudo','-S','-u','root','--','/usr/bin/touch','/lab/effect_a'],user=11001,group=11001,extra_groups=[],input=b'')
        self.assertNotEqual(ordinary.returncode,0);self.assertFalse((ROOT/'effect_a').exists())

    def test_crash_before_and_after_launch_never_retries(self) -> None:
        for stage, effect in [('after-consumption',False),('after-execution',True)]:
            with self.subTest(stage=stage):
                child=self.start();view=self.request(child,['/usr/bin/touch','/lab/effect_a']);approval=self.approval(view)
                (ROOT/'fault').write_text(stage);self.send(child,approval);self.wait_checkpoint()
                os.killpg(child.pid,signal.SIGKILL);child.wait()
                self.assertEqual((ROOT/'effect_a').exists(),effect)
                count=self.count_marker_launches()
                restarted=self.start();self.assertFalse(self.rpc(restarted,approval)['ok'])
                self.assertEqual(self.count_marker_launches(),count)
                self.assertEqual(self.state('sponsor_a',view['envelope']['id']),'uncertain')
                restarted.kill();restarted.wait()
                for name in ['fault','checkpoint','continue','effect_a']:(ROOT/name).unlink(missing_ok=True)

    def test_agent_cannot_install_read_keys_or_invoke_gate(self) -> None:
        for argv in [[sys.executable,'-I','/integration/launcher.py','enroll'],
                     ['/usr/local/bin/approval-gate'],
                     ['/usr/local/bin/integrated-sudo-lab',str(self.paths['sponsor_a'])],
                     ['/usr/bin/cat','/lab/human/key.pem'], ['/usr/bin/cat','/lab/internal-key.pem']]:
            self.assertNotEqual(run(argv,user=11004,group=11004,extra_groups=[],input=b'{}').returncode,0)
        policy('sponsor_a',INSTALL,False)
        selector=run(['/usr/bin/sudo','-n','--',sys.executable,'-I','/integration/launcher.py','enroll','sponsor_b'],user=11001,group=11001,extra_groups=[])
        self.assertNotEqual(selector.returncode,0)
        direct=run([sys.executable,'-I','/integration/launcher.py','enroll'],env={'SUDO_USER':'sponsor_b','SUDO_UID':'11002','SUDO_GID':'11002'})
        self.assertNotEqual(direct.returncode,0)


if __name__=='__main__':
    unittest.main(verbosity=2)
