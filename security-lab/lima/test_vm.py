"""Actual systemd/MCP/sudo tests with disposable credentials; no biometric claims."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

spec=importlib.util.spec_from_file_location('vm_installer',Path(__file__).with_name('install_vm.py'))
assert spec and spec.loader
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
spec=importlib.util.spec_from_file_location('fixture','/integration/test_mcp.py')
assert spec and spec.loader
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
SOCKET='/lab/socket-sponsor_a/broker.sock'
ENROLL='/lab/enrollments/11001/enrollment.json'
UNIT='sudo-relay-vm-lab.service'
RESULTS: list[str]=[]


def run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv,capture_output=True,timeout=20,**kw)


def check(condition: bool, label: str) -> None:
    if not condition:raise AssertionError(label)
    RESULTS.append(label);print('PASS: '+label,flush=True)


def restart() -> None:
    subprocess.run(['systemctl','restart',UNIT],check=True,timeout=20)
    for _ in range(100):
        if Path(SOCKET).exists():return
        time.sleep(.05)
    raise RuntimeError('broker socket absent')


def main() -> None:
    assert os.geteuid()==0 and Path('/etc/machine-id').read_text().strip()==installer.MACHINE
    trial=fixture.McpSudo();trial.children=[]
    try:
        mcp=trial.mcp(SOCKET)
        def request():return trial.request(mcp)
        def submit(proof):return trial.client(SOCKET,'submit',proof)
        def cancel(view):return submit({'method':'cancel_execution','id':view['envelope']['id']})
        # Test both the untouched service and scoped fallback with dummy passwords.
        for user in (11002,11001):
            base=dict(user=user,group=user,extra_groups=[],env={'PATH':'/usr/bin:/bin'})
            wrong=run(['/usr/bin/sudo','-k','-S','--','/usr/bin/id','-u'],input=b'wrong\n',**base)
            check(wrong.returncode!=0,f'UID {user} wrong password denied')
            good=run(['/usr/bin/sudo','-k','-S','--','/usr/bin/id','-u'],input=(installer.PASSWORD+'\n').encode(),**base)
            check(good.returncode==0 and good.stdout==b'0\n',f'UID {user} ordinary password authentication retained')
        for path in ['/lab/human/key.pem','/lab/internal-key.pem','/lab/enrollments/11001/enrollment.json']:
            result=run(['/bin/cat',path],user=11004,group=11004,extra_groups=[])
            check(result.returncode!=0,'agent cannot read '+path)
        check(run(['/usr/bin/sudo','-n','--','/usr/bin/id','-u'],user=11004,group=11004,extra_groups=[]).returncode!=0,'agent direct sudo denied')
        view=request();proof=trial.sign(SOCKET,view,True)
        check(not trial.client(SOCKET,'submit',proof,uid=11004)['ok'],'agent cannot submit approval')
        bad=trial.sign(SOCKET,view,True,alter_command=True)
        check(not submit(bad)['ok'],'approval for changed command rejected')
        check(submit(proof)['ok'],'signed approval accepted')
        status=trial.complete(mcp,view['envelope']['id'])
        check(status['outcome']['exit_code']==0 and status['outcome']['stdout']=='0\n','MCP reports successful native root command')
        check(not submit(proof)['ok'],'approval replay rejected')
        restart()
        check(not submit(proof)['ok'],'replay rejected after service restart')
        # Actual key revocation API, not merely deleting a file.
        view=request();proof=trial.sign(SOCKET,view)
        subprocess.run(['/usr/local/bin/integrated-sudo-lab',ENROLL,'revoke'],check=True)
        check(not submit(proof)['ok'],'revoked key cannot approve pending request')
        restart();check(not submit(proof)['ok'],'key revocation persists across restart')
        cancel(view)
        view=request();proof=trial.sign(SOCKET,view)
        check(not submit(proof)['ok'],'revoked key rejects a fresh request after restart')
        cancel(view)
        subprocess.run(['/usr/local/bin/integrated-sudo-lab',ENROLL,'pair'],check=True)
        view=request();proof=trial.sign(SOCKET,view)
        policy=Path('/etc/sudoers.d/sr-vm-sponsor');original=policy.read_text()
        policy.write_text(original.replace('sponsor_a ALL=(root) PASSWD: /usr/bin/id -u','sponsor_a ALL=(root) PASSWD: /usr/bin/false'))
        try:
            submit(proof)
            status=trial.complete(mcp,view['envelope']['id'])
            check(status['outcome']['error'] is not None,'sponsor revocation blocks approved pending execution')
            denied=trial.tool(mcp,'request_execution',{'spec':{'command':{'kind':'argv','argv':['/usr/bin/id','-u']},'env':{},'reason':'denied policy','timeout_secs':5,'output_needed':False}})
            check(denied['result'].get('isError') is True,'sponsor revocation blocks new requests')
        finally:policy.write_text(original)
        view=request();proof=trial.sign(SOCKET,view)
        check(cancel(view)['ok'] and not submit(proof)['ok'],'cancelled request cannot execute')
        view=request();proof=trial.sign(SOCKET,view,False)
        check(submit(proof)['ok'],'second explicit approval accepted')
        status=trial.complete(mcp,view['envelope']['id'])
        check(status['outcome']['exit_code']==0 and status['outcome']['stdout']=='' and status['outcome']['stderr']=='','output withheld when sharing off')
        Path('/lab/reboot-check.json').write_text(json.dumps(proof))
        check(installer.baseline()==json.loads(Path('/lab/install-manifest.json').read_text())['baseline'],'original sudo/PAM files unchanged')
        Path('/lab/test-results.json').write_text(json.dumps({'passed':RESULTS,'software_test_approvals':True},indent=2))
    finally:trial.stop_all()


if __name__=='__main__':main()
