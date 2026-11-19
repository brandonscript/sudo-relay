"""Validation and acceptance checks; no root writes, Keychain access or execution."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import io
import json
import os
import tempfile
from pathlib import Path
import stat
import unittest
from unittest.mock import patch
import subprocess
import uuid
import zipfile

HERE=Path(__file__).resolve().parent

def load(name: str):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    assert spec and spec.loader
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

install=load('protected_install');runner=load('run_trial')


class Handoff(unittest.TestCase):
    def test_docker_preflight_stops_before_build_when_daemon_is_missing(self):
        for result in [subprocess.CompletedProcess([],1,'','missing socket'),subprocess.CompletedProcess([],0,'','')]:
            with patch.object(runner.subprocess,'run',return_value=result) as call:
                with self.assertRaisesRegex(RuntimeError,'daemon unavailable'):
                    runner.check_docker('/fixture/docker')
                self.assertEqual(call.call_args.args[0],['/fixture/docker','info','--format','{{.ServerVersion}}'])
        with patch.object(runner.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'29.8.2\n','')):
            runner.check_docker('/fixture/docker')
        with patch.object(runner.subprocess,'run',side_effect=subprocess.TimeoutExpired('docker',15)):
            with self.assertRaisesRegex(RuntimeError,'did not respond'):
                runner.check_docker('/fixture/docker')

    def test_isolated_docker_preserves_daemon_plugins_and_restores_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin=Path(directory)/'docker-compose';plugin.write_text('fixture')
            plugins=json.dumps([{'Name':'compose','Path':str(plugin)}])
            original={'DOCKER_CONFIG':'/original','DOCKER_CONTEXT':'colima',
                      'DOCKER_HOST':'unix:///ignored.sock','DOCKER_AUTH_CONFIG':'private fixture'}
            for final_id in ('server-a','server-b'):
                replies=['server-a','"unix:///colima.sock"',plugins,final_id]
                with patch.dict(os.environ,original,clear=True),patch.object(runner,'check_docker'), \
                     patch.object(runner.subprocess,'check_output',side_effect=replies), \
                     patch.object(runner.subprocess,'run'):
                    if final_id=='server-b':
                        with self.assertRaisesRegex(RuntimeError,'server changed'):
                            with runner.isolated_docker('/docker'):self.fail('must not run')
                    else:
                        with self.assertRaisesRegex(RuntimeError,'simulated build failure'):
                            with runner.isolated_docker('/docker'):
                                temporary=Path(os.environ['DOCKER_CONFIG'])
                                self.assertEqual(json.loads((temporary/'config.json').read_text()),{'auths':{'https://index.docker.io/v1/':{}}})
                                self.assertEqual((temporary/'cli-plugins/docker-compose').resolve(),plugin.resolve())
                                self.assertEqual(os.environ['DOCKER_HOST'],'unix:///colima.sock')
                                self.assertNotIn('DOCKER_CONTEXT',os.environ)
                                self.assertNotIn('DOCKER_AUTH_CONFIG',os.environ)
                                raise RuntimeError('simulated build failure')
                        self.assertFalse(temporary.exists())
                    self.assertEqual(dict(os.environ),original)

    def test_isolated_docker_rejects_remote_endpoint(self):
        with patch.dict(os.environ,{'DOCKER_HOST':'ssh://other'},clear=True), \
             patch.object(runner,'check_docker'), \
             patch.object(runner.subprocess,'check_output',side_effect=['server-a','"unix:///ignored.sock"']):
            with self.assertRaisesRegex(RuntimeError,'local Docker Unix socket'):
                with runner.isolated_docker('/docker'):self.fail('must not run')

    def test_failed_build_never_starts_container_or_administrator_helper(self):
        with patch.object(runner.subprocess,'run',side_effect=subprocess.CalledProcessError(1,'build')), \
             patch.object(runner.subprocess,'Popen') as launch:
            with self.assertRaisesRegex(RuntimeError,'No administrator setup'):
                runner.run_trial('/docker',{})
            launch.assert_not_called()

    def test_authentication_inherits_terminal_and_failure_stops_before_launch(self):
        with patch.object(runner.subprocess,'run',side_effect=[
                subprocess.CompletedProcess([],0),subprocess.CompletedProcess([],1)]) as run, \
             patch.object(runner.subprocess,'Popen') as launch:
            with self.assertRaisesRegex(RuntimeError,'authentication cancelled or failed'):
                runner.run_trial('/docker',{})
            self.assertEqual(run.call_args.args,(['/usr/bin/sudo','-v'],))
            self.assertEqual(run.call_args.kwargs,{})
            launch.assert_not_called()

    def test_pinned_lab_acknowledgement_with_biometric_diagnostics(self):
        output=('Interactive signature returned; verifying receipt next.\n'
                'Execution approval accepted. Check MCP status for completion.\n'
                'Noninteractive attempt produced no signature (com.apple.LocalAuthentication -1004).\n')
        self.assertTrue(runner.acknowledged(output))
        self.assertTrue(runner.accepted(self.status(False),'request',0,output))
        for changed in (output+'extra\n',output+output,output.replace('no signature','a signature'),
                        output.replace('-1004','-999'),output.replace('Execution approval accepted. Check MCP status for completion.\n','')):
            self.assertFalse(runner.acknowledged(changed))
        self.assertFalse(runner.accepted(self.status(False),'request',1,output))
        self.assertFalse(runner.accepted({**self.status(False),'sudo_launches':2},'request',0,output))

    def fixture(self):
        raw='04'+'11'*64
        pins={'approver_uid':501,'signing_key':'p256-sha256:'+raw,'keychain_account':hashlib.sha256(bytes.fromhex(raw)).hexdigest()}
        ready=dict(signing_key=pins['signing_key'],signing_key_id='human',software_approval_key_absent=True,
            machine_id=str(uuid.uuid4()),machine_name='Astra Linux trial',account='sponsor_a',operating_system='Debian GNU/Linux 13',
            port=12345,known_hosts='sudo-relay-linux ssh-ed25519 AAAAtest\n',
            transport_identity='-----BEGIN OPENSSH PRIVATE KEY-----\n'+'A'*100+'\n-----END OPENSSH PRIVATE KEY-----\n')
        return pins,ready

    def test_policy_binds_key_account_host_and_absolute_protected_paths(self):
        pins,ready=self.fixture();root=Path('/private/var/db/sr-linux-trial-fixture')
        policy=install.enrollment(ready,pins,root,501)
        self.assertEqual(policy['purpose'],'disposable-linux-execution-v1')
        self.assertEqual(policy['identity'],str(root/'transport-key'))
        for key,value in [('signing_key','p256-sha256:00'),('signing_key_id','receipt'),('software_approval_key_absent',False),
                          ('machine_id','bad'),('machine_name','other'),('account','root'),('port',0),('port',True),
                          ('operating_system','Debian\nspoof'),('known_hosts','* ssh-ed25519 AAAA\n'),('transport_identity','invalid')]:
            with self.subTest(key=key),self.assertRaises((ValueError,TypeError)):
                install.enrollment({**ready,key:value},pins,root,501)
        with self.assertRaises(ValueError):install.enrollment(ready,pins,root,502)
        with self.assertRaises(ValueError):install.enrollment(ready,{**pins,'keychain_account':'00'*32},root,501)

    def test_vm_pairing_rejects_changed_machine_and_host_pin(self):
        pins,ready=self.fixture();root=Path('/private/var/db/sr-vm-fixture')
        pins.update(machine_name=ready['machine_name'],machine_id=ready['machine_id'],known_hosts=ready['known_hosts'])
        policy=install.enrollment(ready,pins,root,501)
        self.assertEqual(policy['purpose'],'disposable-linux-vm-execution-v1')
        for field,value in [('machine_id',str(uuid.uuid4())),('machine_name','Different VM'),('known_hosts','sudo-relay-linux ssh-ed25519 AAAAwrong\n')]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                install.enrollment({**ready,field:value},pins,root,501)

    def archive(self,extra: str | None=None,symlink=False):
        buffer=io.BytesIO();binary=b'fixture executable bytes'
        with zipfile.ZipFile(buffer,'w') as archive:
            prefix='sudo-relay-execution-ready/sudo-relay.app/'
            archive.writestr(prefix+'Contents/MacOS/sudo-relay',binary)
            if extra:
                info=zipfile.ZipInfo(prefix+extra)
                info.external_attr=((stat.S_IFLNK if symlink else stat.S_IFREG)|0o644)<<16
                archive.writestr(info,b'/outside')
        data=buffer.getvalue()
        return data,dict(archive_sha256=hashlib.sha256(data).hexdigest(),binary_sha256=hashlib.sha256(binary).hexdigest())

    def test_pinned_archive_rejects_changed_binary_traversal_and_links(self):
        data,pins=self.archive();self.assertEqual(len(install.bundle_files(data,pins)),1)
        with self.assertRaises(ValueError):install.bundle_files(data,{**pins,'archive_sha256':'0'*64})
        with self.assertRaises(ValueError):install.bundle_files(data,{**pins,'binary_sha256':'0'*64})
        for extra,symlink in [('../outside',False),('Contents/link',True)]:
            data,pins=self.archive(extra,symlink)
            with self.assertRaises(ValueError):install.bundle_files(data,pins)

    def test_runtime_rejects_relaxed_container_boundaries(self):
        original={'Mounts':[], 'HostConfig':{'NetworkMode':'none','PortBindings':{},'ReadonlyRootfs':True,
            'Privileged':False,'CapDrop':['ALL'],'CapAdd':['CHOWN','SETUID','SETGID','FOWNER','KILL','AUDIT_WRITE','SYS_PTRACE','SYS_CHROOT']}}
        self.assertTrue(runner.contained(original))
        for field,value in [('NetworkMode','host'),('ReadonlyRootfs',False),('Privileged',True),('PidMode','host'),('CapDrop',[]),('CapAdd',['SYS_ADMIN'])]:
            changed=copy.deepcopy(original);changed['HostConfig'][field]=value
            self.assertFalse(runner.contained(changed))
        changed=copy.deepcopy(original);changed['Mounts']=[{'Type':'bind'}]
        self.assertFalse(runner.contained(changed))

    def status(self,shared: bool):
        return {'sudo_launches':1,'sudo_completions':1,'sudo_log_valid':True,'sponsor_logged':True,'status':{'id':'request','state':'complete','output_shared':shared,
            'outcome':{'exit_code':0,'stdout':'0\n' if shared else '', 'stderr':'','error':None,'cleanup_error':None,'timed_out':False,'truncated':False}}}

    def test_success_requires_app_ack_native_launch_and_exact_sharing(self):
        ack='Execution approval accepted. Check MCP status for completion.\n'
        for shared in [False,True]:
            status=self.status(shared)
            self.assertTrue(runner.accepted(status,'request',0,ack))
            for mutation in [dict(sudo_launches=0),dict(sudo_launches=2),dict(sponsor_logged=False),dict(sudo_completions=0),dict(sudo_completions=2),dict(sudo_log_valid=False)]:
                self.assertFalse(runner.accepted({**status,**mutation},'request',0,ack))
            self.assertFalse(runner.accepted(status,'other',0,ack))
            self.assertFalse(runner.accepted(status,'request',1,ack))
            for output in ('',ack+ack,'noise\n'+ack,ack.rstrip()):
                self.assertFalse(runner.accepted(status,'request',0,output))
            for field,value in [('exit_code',1),('timed_out',True),('error','failed'),('stdout','unexpected')]:
                changed=copy.deepcopy(status);changed['status']['outcome'][field]=value
                self.assertFalse(runner.accepted(changed,'request',0,ack))


if __name__=='__main__':unittest.main(verbosity=2)
