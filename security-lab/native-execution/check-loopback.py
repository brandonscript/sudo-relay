"""Verify the Astra-style host/VM/container hop with fixture credentials; never approves."""
from __future__ import annotations
import json
import shutil
from loopback import LoopbackRelay
from run_trial import contained
from pathlib import Path
import select
import subprocess
import tempfile
import uuid

REPO=Path(__file__).resolve().parents[2]


def main() -> None:
    project='sr-loopback-'+uuid.uuid4().hex[:12]
    name=project+'-container'
    compose=['docker','compose','-p',project,'-f',str(REPO/'security-lab/integrated-sudo/compose.yaml')]
    public=json.loads((REPO/'ui/test/p256-fixture.json').read_text())['public_key_sec1']
    child=subprocess.Popen(compose+['run','--rm','--no-deps','-T','--name',name,'--entrypoint','python3','integration','-I','/integration/human_session.py'],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        def call(message: dict[str,object]) -> dict[str,object]:
            assert child.stdin and child.stdout
            child.stdin.write(json.dumps(message)+'\n');child.stdin.flush()
            if not select.select([child.stdout],[],[],20)[0]:
                raise RuntimeError('session response timeout')
            line=child.stdout.readline()
            if not line: raise RuntimeError('session closed')
            result=json.loads(line)
            if not result.get('ok'): raise RuntimeError('container session rejected request')
            return result
        ready=call({'public_key':'p256-sha256:'+public})
        assert ready['software_approval_key_absent']
        inspect=json.loads(subprocess.check_output(['docker','inspect',name],timeout=10))[0]
        assert not inspect['Mounts'] or all(m['Type']=='tmpfs' for m in inspect['Mounts'])
        assert contained(inspect)
        pending=call({'operation':'request'})['pending']
        assert isinstance(pending,dict)
        with LoopbackRelay(shutil.which('docker') or '/usr/local/bin/docker', name) as relay, tempfile.TemporaryDirectory(prefix='sudo-relay-loopback-') as temporary:
            root=Path(temporary)
            identity=root/'identity';identity.write_text(str(ready['transport_identity']));identity.chmod(0o600)
            hosts=root/'known_hosts';hosts.write_text(str(ready['known_hosts']));hosts.chmod(0o600)
            command=['/usr/bin/ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','HostKeyAlias=sudo-relay-linux','-o',f'UserKnownHostsFile={hosts}',
                '-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
                '-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','ControlPath=none','-o','ControlMaster=no',
                '-o','ConnectTimeout=3','-o','ConnectionAttempts=1','-i',str(identity),'-p',str(relay.port),
                'approver@127.0.0.1','review']
            response=subprocess.run(command,input=json.dumps({'method':'execution_status','id':pending['envelope']['id']}),
                text=True,capture_output=True,timeout=10)
            assert response.returncode==0,response.stderr
            result=json.loads(response.stdout)
            assert result['ok'] and result['value']['pending']==pending
            hosts.write_text('')
            rejected=subprocess.run(command,input='{}',text=True,capture_output=True,timeout=10)
            assert rejected.returncode!=0 and 'Host key verification failed' in rejected.stderr
        status=call({'operation':'status'})
        assert status['sudo_launches']==0 and status['status']['state']=='pending'
        assert child.stdin
        child.stdin.write('{"operation":"stop"}\n');child.stdin.flush()
        child.communicate(timeout=10)
        assert child.returncode==0
        assert subprocess.run(['docker','inspect',name],capture_output=True,timeout=10).returncode!=0
        print('PASS: host loopback SSH pin and request matched; missing pin rejected; zero sudo launches; container removed.')
    finally:
        subprocess.run(compose+['down','--volumes','--remove-orphans','--timeout','0'],capture_output=True,timeout=20)
        subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=10)
        if child.poll() is None: child.kill()
        child.communicate(timeout=5)


if __name__=='__main__':
    main()
