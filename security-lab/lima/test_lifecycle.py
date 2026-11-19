"""Expiry, VM guard and actual VM reboot checks for the installed experiment."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from test_vm import installer,fixture,SOCKET,ENROLL,UNIT,check,restart,RESULTS


def main() -> None:
    assert Path('/etc/machine-id').read_text().strip()==installer.MACHINE
    trial=fixture.McpSudo();trial.children=[]
    try:
        if sys.argv[1:]==['before-reboot']:
            marker=Path('/etc/sudo-relay-vm-lab-id');original=marker.read_bytes()
            try:
                marker.write_text('different-machine\n')
                denied=subprocess.run(['/usr/local/bin/integrated-sudo-lab',ENROLL,'pair'],capture_output=True)
                check(denied.returncode!=0,'VM identity mismatch rejects privileged controller')
            finally:marker.write_bytes(original)
            enrollment=Path(ENROLL);config=json.loads(enrollment.read_text());normal=config['config']['approval_ttl_secs']
            config['config']['approval_ttl_secs']=1;enrollment.write_text(json.dumps(config));restart()
            try:
                mcp=trial.mcp(SOCKET);view=trial.request(mcp);proof=trial.sign(SOCKET,view)
                time.sleep(2)
                check(not trial.client(SOCKET,'submit',proof)['ok'],'expired approval cannot execute in full VM')
            finally:
                config['config']['approval_ttl_secs']=normal;enrollment.write_text(json.dumps(config));restart()
            report=json.loads(Path('/lab/test-results.json').read_text());report['passed']+=RESULTS
            report['pre_reboot_log_sha256']=hashlib.sha256(Path('/lab/sudo.log').read_bytes()).hexdigest()
            Path('/lab/test-results.json').write_text(json.dumps(report,indent=2))
        elif sys.argv[1:]==['after-reboot']:
            report=json.loads(Path('/lab/test-results.json').read_text())
            check(subprocess.run(['systemctl','is-active','--quiet',UNIT]).returncode==0,'service starts after full VM reboot')
            check(hashlib.sha256(Path('/lab/sudo.log').read_bytes()).hexdigest()==report['pre_reboot_log_sha256'],'reboot did not launch another sponsor command')
            proof=json.loads(Path('/lab/reboot-check.json').read_text())
            check(not trial.client(SOCKET,'submit',proof)['ok'],'consumed approval rejected after full VM reboot')
            mcp=trial.mcp(SOCKET)
            status=trial.value(trial.tool(mcp,'execution_status',{'id':proof['id']}))
            check(status['state']=='complete' and status['outcome'] is None,'completed state survives reboot; transient outcome is not persisted')
            check(installer.baseline()==json.loads(Path('/lab/install-manifest.json').read_text())['baseline'],'original sudo/PAM unchanged after reboot')
            report['passed']+=RESULTS;report['completed']=True
            Path('/lab/test-results.json').write_text(json.dumps(report,indent=2))
        elif sys.argv[1:]==['key-revocation']:
            subprocess.run(['/usr/local/bin/integrated-sudo-lab',ENROLL,'revoke'],check=True)
            try:
                restart();mcp=trial.mcp(SOCKET);view=trial.request(mcp);proof=trial.sign(SOCKET,view)
                check(not trial.client(SOCKET,'submit',proof)['ok'],'revoked key rejects fresh approval after restart')
                trial.client(SOCKET,'submit',{'method':'cancel_execution','id':view['envelope']['id']})
            finally:subprocess.run(['/usr/local/bin/integrated-sudo-lab',ENROLL,'pair'],check=True)
            report=json.loads(Path('/lab/test-results.json').read_text());report['passed']+=RESULTS
            Path('/lab/test-results.json').write_text(json.dumps(report,indent=2))
        else:raise RuntimeError('choose before-reboot, after-reboot or key-revocation')
    finally:trial.stop_all()


if __name__=='__main__':main()
