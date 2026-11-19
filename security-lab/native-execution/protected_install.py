"""Temporary administrator installation for one Linux trial; never launches commands."""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import uuid
import zipfile
from typing import Any


def require(condition: bool, message: str) -> None:
    if not condition: raise ValueError(message)


def bundle_files(data: bytes, pins: dict[str, Any]) -> dict[str, bytes]:
    require(hashlib.sha256(data).hexdigest()==pins['archive_sha256'],'signed archive hash mismatch')
    prefix='sudo-relay-execution-ready/sudo-relay.app/'
    result: dict[str,bytes]={}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(len(archive.infolist())<=100,'too many archive entries')
        total=0
        for entry in archive.infolist():
            if not entry.filename.startswith(prefix) or entry.is_dir(): continue
            name=entry.filename[len(prefix):];parts=PurePosixPath(name).parts
            require(bool(parts) and not name.startswith('/') and '..' not in parts and name not in result,'unsafe bundle member')
            require(stat.S_IFMT(entry.external_attr>>16) in (0,stat.S_IFREG),'non-regular bundle member')
            total+=entry.file_size;require(total<=25000000,'oversized app')
            result[name]=archive.read(entry)
    require(hashlib.sha256(result.get('Contents/MacOS/sudo-relay',b'')).hexdigest()==pins['binary_sha256'],'reviewer binary mismatch')
    return result


def enrollment(ready: dict[str,Any], pins: dict[str,Any], root: Path, uid: int) -> dict[str,Any]:
    require(uid==pins['approver_uid'] and uid!=0,'wrong approving account')
    require(ready['signing_key']==pins['signing_key'] and ready['signing_key_id']=='human','wrong approving key')
    raw=bytes.fromhex(pins['signing_key'].removeprefix('p256-sha256:'))
    require(len(raw)==65 and raw[0]==4 and hashlib.sha256(raw).hexdigest()==pins['keychain_account'],'wrong key fingerprint')
    require(ready['software_approval_key_absent'] is True,'software approval key must be absent')
    uuid.UUID(ready['machine_id'])
    require(ready['machine_name']==pins.get('machine_name','Astra Linux trial') and ready['account']=='sponsor_a','wrong target labels')
    if 'machine_id' in pins:require(ready['machine_id']==pins['machine_id'],'wrong VM identity')
    if 'known_hosts' in pins:require(ready['known_hosts']==pins['known_hosts'],'wrong VM SSH pin')
    operating_system=ready['operating_system']
    require(isinstance(operating_system,str) and 0<len(operating_system)<=100 and operating_system.isascii()
            and all(32<=ord(c)<=126 for c in operating_system),'invalid operating-system label')
    require(type(ready['port']) is int and 1<=ready['port']<=65535,'invalid loopback port')
    host=ready['known_hosts']
    require(isinstance(host,str) and len(host)<1024 and re.fullmatch(r'sudo-relay-linux ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?\n?',host) is not None,'invalid host pin')
    identity=ready['transport_identity']
    require(isinstance(identity,str) and 100<len(identity)<4096 and identity.startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n')
            and identity.endswith('-----END OPENSSH PRIVATE KEY-----\n'),'invalid transport identity')
    return dict(version=1,purpose=('disposable-linux-vm-execution-v1' if 'machine_id' in pins else 'disposable-linux-execution-v1'),approver_uid=uid,
        machine_id=ready['machine_id'],machine_name=ready['machine_name'],operating_system=operating_system,
        account='sponsor_a',signing_key=pins['signing_key'],signing_key_id='human',port=ready['port'],
        known_hosts=str(root/'known_hosts'),identity=str(root/'transport-key'))


def main() -> None:
    require(sys.platform=='darwin' and os.getuid()==0 and os.geteuid()==0 and len(sys.argv)==1,'administrator installer only')
    uid=int(os.environ.get('SUDO_UID','0'))
    require(uid==501 and os.stat('/dev/console').st_uid==uid,'use the ordinary Astra console account')
    user=pwd.getpwuid(uid)
    kit=Path(__file__).resolve().parent
    pins=json.loads((kit/'pins.json').read_bytes())
    require(re.fullmatch(r'[0-9a-f]{40}',pins['cdhash']) is not None,'invalid code pin')
    archive=kit/'signed-reviewer.zip';require(archive.stat().st_size<=25000000,'archive too large')
    files=bundle_files(archive.read_bytes(),pins)
    line=sys.stdin.buffer.readline(16385)
    require(len(line)<=16384 and line.endswith(b'\n'),'bounded setup required')
    ready=json.loads(line)
    root=Path('/private/var/db')/('sr-linux-trial-'+uuid.uuid4().hex[:16])
    policy=enrollment(ready,pins,root,uid)
    os.umask(0o077);root.mkdir(mode=0o755);root.chmod(0o755)
    def expired(_signal: int, _frame: Any) -> None:
        raise TimeoutError('temporary installation expired')
    signal.signal(signal.SIGALRM,expired);signal.signal(signal.SIGTERM,expired);signal.signal(signal.SIGHUP,expired);signal.alarm(900)
    try:
        app=root/'sudo-relay.app'
        for name,data in files.items():
            destination=app/name;destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(data);destination.chmod(0o755 if name=='Contents/MacOS/sudo-relay' else 0o644)
        for folder in [app,*[p for p in app.rglob('*') if p.is_dir()]]:folder.chmod(0o755)
        requirement=f'=anchor apple generic and identifier "com.sudorelay.receiptlab.astra" and certificate leaf[subject.OU] = "R86CYUZWPR" and cdhash H"{pins["cdhash"]}"'
        subprocess.run(['/usr/bin/codesign','--verify','--strict','-R',requirement,str(app)],check=True)
        for name,content in [('enrollment.json',json.dumps(policy)),('known_hosts',ready['known_hosts']),('transport-key',ready['transport_identity'])]:
            path=root/name;path.write_text(content);path.chmod(0o644 if name!='transport-key' else 0o440)
            if name=='transport-key':os.chown(path,0,user.pw_gid)
        print(json.dumps({'installed':True,'root':str(root),'app':str(app),'enrollment':str(root/'enrollment.json')}),flush=True)
        # The unprivileged runner can only end this temporary installation, never ask it to launch work.
        finish=sys.stdin.buffer.readline(9)
        require(finish in (b'',b'cleanup\n'),'unsupported installer operation')
    finally:
        shutil.rmtree(root)
        print(json.dumps({'temporary_install_removed':not root.exists()}),flush=True)


if __name__=='__main__':
    main()
