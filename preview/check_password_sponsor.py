"""VM-only acceptance: a second sponsor installs through password-required sudo."""
from __future__ import annotations
import os,pwd,subprocess,sys
from pathlib import Path

if os.geteuid()!=0:raise PermissionError('root VM test driver only')
subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],check=True,capture_output=True)
source=Path(__file__).resolve().parents[1];name='sr-preview-password-owner';policy=Path('/etc/sudoers.d/sr-preview-password-test')
try:pwd.getpwnam(name)
except KeyError:pass
else:raise RuntimeError('test owner already exists')
if policy.exists():raise RuntimeError('test policy already exists')
password='throwaway-preview-test-password'
subprocess.run(['useradd','--user-group','--no-create-home','--shell','/bin/sh',name],check=True)
account=pwd.getpwnam(name);enrollment=Path('/etc/sudo-relay')/str(account.pw_uid)/'enrollment.json'
installed=False
try:
    subprocess.run(['chpasswd'],input=(name+':'+password+'\n').encode(),check=True)
    policy.write_text(name+' ALL=(root) PASSWD: ALL\n');policy.chmod(0o440)
    subprocess.run(['visudo','-c'],check=True,capture_output=True)
    def admin(operation: str) -> subprocess.CompletedProcess:
        return subprocess.run(['/usr/bin/sudo','-k','-S','--','/usr/bin/python3','-B',str(source/'preview/admin.py'),operation],
            user=account.pw_uid,group=account.pw_gid,extra_groups=[],env={'PATH':'/usr/bin:/bin'},
            input=(password+'\n').encode(),capture_output=True,timeout=60)
    result=admin('install')
    if result.returncode:raise RuntimeError(result.stderr.decode())
    installed=True
    print('PASS: second sponsor derived from real password-authenticated sudo; independent namespace',flush=True)
    subprocess.run(['/usr/bin/python3','-B',str(source/'preview/check_vm.py'),str(enrollment),str(source/'target/release/integrated-sudo-lab')],check=True)
    result=admin('remove')
    if result.returncode:raise RuntimeError(result.stderr.decode())
    installed=False
    print('PASS: password-required PAM authentication via scoped module and second-sponsor removal',flush=True)
finally:
    if installed:
        result=admin('remove')
        if result.returncode:print('CLEANUP REQUIRED: '+result.stderr.decode(),file=sys.stderr)
    policy.unlink(missing_ok=True)
    subprocess.run(['userdel',name],check=True)
