"""Ordinary-account runner: Docker execution, pinned native review, explicit cleanup."""
from __future__ import annotations
from contextlib import contextmanager
from collections.abc import Iterator
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time
import tempfile
import uuid
from typing import Any

KIT=Path(__file__).resolve().parent
source=importlib.util.spec_from_file_location('trial_loopback',KIT/'loopback.py')
assert source and source.loader
module=importlib.util.module_from_spec(source);source.loader.exec_module(module)


def response(child: subprocess.Popen[str], timeout: int = 30) -> dict[str,Any]:
    assert child.stdout
    if not select.select([child.stdout],[],[],timeout)[0]:raise RuntimeError('trial response timed out')
    line=child.stdout.readline(32769)
    if len(line)>32768 or not line.endswith('\n'):raise RuntimeError('missing or oversized trial reply')
    value=json.loads(line)
    if not isinstance(value,dict) or value.get('ok') is False:raise RuntimeError('trial rejected the operation')
    return value


def send(child: subprocess.Popen[str], value: dict[str,Any]) -> dict[str,Any]:
    assert child.stdin
    child.stdin.write(json.dumps(value)+'\n');child.stdin.flush()
    return response(child)


def contained(inspect: dict[str,Any]) -> bool:
    config=inspect['HostConfig']
    caps={value.removeprefix('CAP_') for value in config.get('CapAdd') or []}
    return (config['NetworkMode']=='none' and not config.get('PortBindings')
        and config.get('ReadonlyRootfs') is True and not config.get('Privileged')
        and config.get('PidMode','')!='host' and config.get('IpcMode','')!='host'
        and set(config.get('CapDrop') or [])=={'ALL'}
        and caps=={'CHOWN','SETUID','SETGID','FOWNER','KILL','AUDIT_WRITE','SYS_PTRACE','SYS_CHROOT'}
        and not config.get('Devices') and not config.get('DeviceRequests')
        and all(m['Type']=='tmpfs' for m in inspect['Mounts']))


def acknowledged(output: str) -> bool:
    ack='Execution approval accepted. Check MCP status for completion.\n'
    # The pinned lab app also emits these two biometric self-test diagnostics.
    legacy=('Interactive signature returned; verifying receipt next.\n'+ack+
            'Noninteractive attempt produced no signature (com.apple.LocalAuthentication -1004).\n')
    return output in (ack,legacy)


def accepted(status: dict[str,Any], request_id: str, app_code: int, app_stdout: str) -> bool:
    value=status.get('status',{});outcome=value.get('outcome') or {}
    if not (app_code==0 and acknowledged(app_stdout)
            and value.get('id')==request_id and value.get('state')=='complete'
            and status.get('sudo_launches')==1 and status.get('sudo_completions')==1
            and status.get('sudo_log_valid') is True and status.get('sponsor_logged') is True
            and outcome.get('exit_code')==0 and not outcome.get('error') and not outcome.get('cleanup_error')
            and outcome.get('timed_out') is False and outcome.get('truncated') is False):return False
    if value.get('output_shared') is True:
        return outcome.get('stdout')=='0\n' and outcome.get('stderr')==''
    return value.get('output_shared') is False and outcome.get('stdout')=='' and outcome.get('stderr')==''


def check_docker(docker: str) -> None:
    try:
        result=subprocess.run([docker,'info','--format','{{.ServerVersion}}'],
            capture_output=True,text=True,timeout=15)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError('Docker did not respond. Start the configured Docker runtime and verify docker info before retrying.') from error
    if result.returncode!=0 or not result.stdout.strip():
        raise RuntimeError('Docker daemon unavailable. Start the configured runtime (Colima, OrbStack or Docker Desktop) and verify docker info. No build or administrator setup was attempted.')


@contextmanager
def isolated_docker(docker: str) -> Iterator[None]:
    """Keep registry credentials out of the trial without switching its daemon."""
    check_docker(docker)
    original_id=subprocess.check_output([docker,'info','--format','{{.ID}}'],text=True,timeout=15).strip()
    endpoint=json.loads(subprocess.check_output(
        [docker,'context','inspect','--format','{{json .Endpoints.docker.Host}}'],text=True,timeout=15))
    if os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'):
        endpoint=os.environ['DOCKER_HOST']
    if not original_id or not isinstance(endpoint,str) or not endpoint.startswith('unix:///'):
        raise RuntimeError('This trial requires a local Docker Unix socket')
    plugins=json.loads(subprocess.check_output(
        [docker,'info','--format','{{json .ClientInfo.Plugins}}'],text=True,timeout=15))
    keys=('DOCKER_CONFIG','DOCKER_HOST','DOCKER_CONTEXT','DOCKER_AUTH_CONFIG')
    previous={key:os.environ.get(key) for key in keys}
    with tempfile.TemporaryDirectory(prefix='sudo-relay-docker-') as directory:
        config=Path(directory)
        # An empty auth map triggers Docker's automatic native Keychain helper.
        (config/'config.json').write_text('{"auths":{"https://index.docker.io/v1/":{}}}\n')
        (config/'cli-plugins').mkdir()
        for plugin in plugins:
            if plugin.get('Name') in ('compose','buildx'):
                path=Path(plugin['Path'])
                if not path.is_absolute() or not path.is_file():
                    raise RuntimeError('Docker plugin path is unavailable')
                (config/'cli-plugins'/('docker-'+plugin['Name'])).symlink_to(path)
        try:
            os.environ.update(DOCKER_CONFIG=directory,DOCKER_HOST=endpoint)
            os.environ.pop('DOCKER_CONTEXT',None)
            os.environ.pop('DOCKER_AUTH_CONFIG',None)
            isolated_id=subprocess.check_output([docker,'info','--format','{{.ID}}'],text=True,timeout=15).strip()
            if isolated_id!=original_id:raise RuntimeError('Docker server changed; trial stopped')
            subprocess.run([docker,'compose','version'],check=True,capture_output=True,timeout=15)
            yield
        finally:
            for key,value in previous.items():
                if value is None:os.environ.pop(key,None)
                else:os.environ[key]=value


def main() -> None:
    if sys.platform!='darwin' or os.getuid()!=501 or os.stat('/dev/console').st_uid!=os.getuid():
        raise RuntimeError('Run in the ordinary Astra console account, without sudo')
    pins=json.loads((KIT/'pins.json').read_text())
    docker=shutil.which('docker')
    if not docker:raise RuntimeError('Docker CLI is not available')
    with isolated_docker(docker):
        run_trial(docker,pins)


def run_trial(docker: str, pins: dict[str,Any]) -> None:
    compose=[docker,'compose','-p','sudo-relay-integrated','-f',str(KIT/'Source/security-lab/integrated-sudo/compose.yaml')]
    print('Building the disposable Linux image as your ordinary account…',flush=True)
    try:
        subprocess.run(compose+['build'],check=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError('Docker image build failed; see its error above. No administrator setup or approval was attempted.') from error
    print('Authenticate in Terminal for temporary reviewer installation. Type your Mac password here if sudo asks; input is not echoed.',flush=True)
    if subprocess.run(['/usr/bin/sudo','-v']).returncode!=0:
        raise RuntimeError('Administrator authentication cancelled or failed. No container or temporary installation was started.')
    name='sudo-relay-human-'+uuid.uuid4().hex[:12]
    container=subprocess.Popen(compose+['run','--rm','--no-deps','-T','--name',name,'--entrypoint','python3',
        'integration','-I','/integration/human_session.py'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    installer: subprocess.Popen[str] | None=None
    root: Path | None=None
    report: dict[str,Any]={'completed':False,'receipt_only':False,'execution_target':'disposable Linux',
        'key_fingerprint':pins['keychain_account'],'reviewer_sha256':pins['binary_sha256']}
    try:
        ready=send(container,{'public_key':pins['signing_key']})
        if ready.get('software_approval_key_absent') is not True:raise RuntimeError('software approval key unexpectedly present')
        inspect=json.loads(subprocess.check_output([docker,'inspect',name],timeout=10))[0]
        if not contained(inspect):
            raise RuntimeError('container containment mismatch')
        report['image_id']=inspect['Image'];report['software_approval_key_absent']=True
        with module.LoopbackRelay(docker,name) as relay:
            ready['port']=relay.port
            print('Administrator pairing: temporarily install this exact reviewer and key/host pins. No host sudo/PAM settings change.',flush=True)
            print('Approval key fingerprint: '+pins['keychain_account'],flush=True)
            installer=subprocess.Popen(['/usr/bin/sudo','-n','--','/usr/bin/python3','-I','-B',str(KIT/'protected_install.py')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            assert installer.stdin
            installer.stdin.write(json.dumps(ready)+'\n');installer.stdin.flush()
            installed=response(installer,120)
            if installed.get('installed') is not True:raise RuntimeError('administrator pairing failed')
            root=Path(installed['root'])
            pending=send(container,{'operation':'request'})['pending']
            request_id=pending['envelope']['id'];report['request_id']=request_id
            print('Review /usr/bin/id -u in disposable Linux. Choose output sharing, then approve with Touch ID yourself.',flush=True)
            review=subprocess.run([str(Path(installed['app'])/'Contents/MacOS/sudo-relay'),installed['enrollment'],request_id],
                capture_output=True,text=True,timeout=360)
            deadline=time.monotonic()+15
            while True:
                status=send(container,{'operation':'status'})
                if status['status']['state'] not in ('consumed','running') or time.monotonic()>=deadline:break
                time.sleep(.1)
            report.update(status=status,reviewer_exit_code=review.returncode,
                reviewer_stdout=review.stdout[:2048],reviewer_stdout_length=len(review.stdout),
                verified_app_ack=acknowledged(review.stdout))
            report['completed']=accepted(status,request_id,review.returncode,review.stdout)
            if not report['completed']:report['reviewer_error']=review.stderr.strip()[:1000]
    finally:
        if installer is not None:
            try:
                if installer.stdin and installer.poll() is None:
                    installer.stdin.write('cleanup\n');installer.stdin.flush()
                remaining,_=installer.communicate(timeout=10)
                notices=[json.loads(line) for line in remaining.splitlines() if line.startswith('{')]
                report['temporary_install_removed']=any(n.get('temporary_install_removed') is True for n in notices) and (root is None or not root.exists())
            except (OSError,ValueError,subprocess.TimeoutExpired):
                report['temporary_install_removed']=False
                if root is not None:report['cleanup_needed']=str(root)
        try:
            if container.stdin and container.poll() is None:
                container.stdin.write('{"operation":"stop"}\n');container.stdin.flush()
            container.communicate(timeout=10)
        except (OSError,ValueError,subprocess.TimeoutExpired):
            if container.poll() is None:container.kill()
            container.communicate(timeout=5)
        subprocess.run([docker,'rm','-f',name],capture_output=True,timeout=10)
        report['container_removed']=subprocess.run([docker,'inspect',name],capture_output=True,timeout=10).returncode!=0
        report['completed']=report['completed'] and report.get('temporary_install_removed') is True and report['container_removed']
        destination=Path.home()/'Downloads'/('sudo-relay-linux-trial-result-'+uuid.uuid4().hex+'.json')
        destination.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2));print('Report: '+str(destination))


if __name__=='__main__':
    try:
        main()
    except RuntimeError as error:
        print('Trial stopped: '+str(error),file=sys.stderr)
        raise SystemExit(1)
