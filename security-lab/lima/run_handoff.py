"""Astra ordinary-user handoff; only explicit human approval can authorize execution."""
from __future__ import annotations
import json,os,shutil,subprocess,sys,time,uuid
from pathlib import Path
KIT=Path(__file__).resolve().parent
# Only the reviewed kit directory supplies siblings under Python isolated mode.
sys.path.insert(0,str(KIT))
from run_trial import response,send,accepted,acknowledged
from loopback import LoopbackRelay

def main() -> None:
    if sys.platform!='darwin' or os.getuid()!=501:raise RuntimeError('use the ordinary Astra account')
    if sys.argv[1:]!=['--check'] and os.stat('/dev/console').st_uid!=501:raise RuntimeError('log out of the signing account and use the ordinary Astra console account')
    lima=shutil.which('limactl')
    if not lima:raise RuntimeError('Lima unavailable')
    env=dict(os.environ);env.pop('LIMA_HOME',None)
    pins=json.loads((KIT/'pins.json').read_text())
    base=[lima,'shell','--workdir=/','sudo-relay-lab']
    child=subprocess.Popen(base+['sudo','-n','/usr/bin/python3','-I','/integration/vm_session.py'],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,env=env)
    installer=None;root=None;report={'completed':False,'target':'Astra Linux VM','software_approval_key_absent':False}
    try:
        ready=response(child)
        if any(ready[k]!=pins[k] for k in ('machine_id','machine_name','signing_key','known_hosts')):raise RuntimeError('VM pairing pins changed')
        report['software_approval_key_absent']=ready['software_approval_key_absent'] is True
        # No user-supplied shell text; pinned SSH authenticates the endpoint above this byte carrier.
        command=base+['/usr/bin/python3','-I','/integration/ssh_stdio.py']
        os.environ.pop('LIMA_HOME',None)
        with LoopbackRelay('', 'vm',command=command) as relay:
            ready['port']=relay.port
            if sys.argv[1:]==['--check']:
                from protected_install import enrollment
                enrollment(ready,pins,Path('/private/var/db/sr-check-only'),501)
                hosts=KIT/'check-known-hosts';identity=KIT/'check-transport'
                try:
                    hosts.write_text(ready['known_hosts']);identity.write_text(ready['transport_identity']);identity.chmod(0o600)
                    ssh=['/usr/bin/ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=sudo-relay-linux','-o',f'UserKnownHostsFile={hosts}','-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-i',str(identity),'-p',str(relay.port),'approver@127.0.0.1','review']
                    r=subprocess.run(ssh,input='{"method":"execution_status","id":"00000000-0000-0000-0000-000000000000"}',text=True,capture_output=True,timeout=15)
                    if r.returncode or json.loads(r.stdout).get('ok') is not False:raise RuntimeError('review channel preflight failed')
                    print('PASS: VM pins, public-key-only session and Astra-to-VM SSH carrier; no request or approval created')
                finally:hosts.unlink(missing_ok=True);identity.unlink(missing_ok=True)
                return
            if sys.argv[1:]:raise RuntimeError('unsupported arguments')
            print('Pair Astra Linux VM · sponsor_a with key '+pins['keychain_account']+'. Authenticate in Terminal for the temporary protected reviewer.',flush=True)
            if subprocess.run(['/usr/bin/sudo','-v']).returncode:raise RuntimeError('administrator authentication stopped')
            installer=subprocess.Popen(['/usr/bin/sudo','-n','--','/usr/bin/python3','-I','-B',str(KIT/'protected_install.py')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            assert installer.stdin
            installer.stdin.write(json.dumps(ready)+'\n');installer.stdin.flush();installed=response(installer,120);root=Path(installed['root'])
            pending=send(child,{'operation':'request'})['pending'];request_id=pending['envelope']['id'];report['request_id']=request_id
            review=subprocess.run([str(Path(installed['app'])/'Contents/MacOS/sudo-relay'),installed['enrollment'],request_id],capture_output=True,text=True,timeout=360)
            for _ in range(150):
                status=send(child,{'operation':'status'})
                if status['status']['state'] not in ('running','consumed'):break
                time.sleep(.1)
            report.update(status=status,reviewer_exit_code=review.returncode,verified_app_ack=acknowledged(review.stdout),reviewer_stdout=review.stdout[:2048],reviewer_error=review.stderr[:2048])
            report['completed']=accepted(status,request_id,review.returncode,review.stdout)
    finally:
        if installer:
            try:
                assert installer.stdin
                if installer.poll() is None:installer.stdin.write('cleanup\n');installer.stdin.flush()
                output,_=installer.communicate(timeout=15)
                report['temporary_install_removed']=any(json.loads(line).get('temporary_install_removed') is True for line in output.splitlines() if line.startswith('{')) and root is not None and not root.exists()
            except (OSError,ValueError,subprocess.TimeoutExpired):report['temporary_install_removed']=False
        if child.poll() is None:
            try:send(child,{'operation':'stop'})
            except (OSError,ValueError,RuntimeError):pass
        try:child.communicate(timeout=10)
        except subprocess.TimeoutExpired:child.kill();child.communicate(timeout=5)
        if installer:
            # VM cleanup only. No Docker or host policy operation.
            cleaned=subprocess.run(base+['sudo','-n','/usr/bin/python3','-B','/home/brandon.guest/sudo-relay-source/security-lab/lima/install_vm.py','remove'],capture_output=True,text=True,timeout=60,env=env)
            report['vm_install_removed']=cleaned.returncode==0
            report['completed']=report['completed'] and report.get('temporary_install_removed',False) and report['vm_install_removed']
            destination=Path.home()/'Downloads'/('sudo-relay-vm-result-'+uuid.uuid4().hex+'.json');destination.write_text(json.dumps(report,indent=2)+'\n')
            print(json.dumps(report,indent=2));print('Report: '+str(destination))
if __name__=='__main__':
    try:main()
    except (RuntimeError,subprocess.SubprocessError) as error:print('Handoff stopped: '+str(error),file=sys.stderr);raise SystemExit(1)
