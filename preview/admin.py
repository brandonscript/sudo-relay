"""Linux VM developer-preview installation and per-sponsor administration."""
from __future__ import annotations
from dataclasses import asdict
import hashlib
import grp
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parent))
from install_context import Sponsor,InstallPaths,sponsoring_account,read_source

LIB=Path('/usr/local/libexec/sudo-relay')
PAM=Path('/usr/local/lib/sudo-relay-pam.so')

def run(arguments: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(arguments,check=True,capture_output=True,timeout=60,**kwargs)

def write(path: Path, text: str, mode: int = 0o600) -> None:
    with path.open('x') as stream:stream.write(text);stream.flush();os.fsync(stream.fileno())
    path.chmod(mode)

def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700,parents=True,exist_ok=False)

def baseline() -> dict[str,str]:
    paths=[Path('/etc/sudoers'),Path('/etc/pam.d/sudo'),*Path('/etc/pam.d').glob('common-*')]
    return {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}

def trusted_ancestors(path: Path) -> None:
    existing=path
    while not existing.exists():
        if existing.is_symlink():raise PermissionError('symlink in installation path')
        existing=existing.parent
    for parent in (existing,*existing.parents):
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise PermissionError('installation parent must be root-owned and not writable by clients')


def remove_roles(names: list[str], expected: dict[str,list[int]] | None = None) -> None:
    groups={}
    for name in names:
        try:account=pwd.getpwnam(name)
        except KeyError:continue
        if expected is not None and [account.pw_uid,account.pw_gid]!=expected.get(name):
            raise RuntimeError('role identity changed; administrator recovery required')
        groups[name]=account.pw_gid
    for name in reversed(names):
        if name in groups:run(['/usr/sbin/userdel',name])
    for name,gid in groups.items():
        try:group=grp.getgrnam(name)
        except KeyError:continue
        if group.gr_gid!=gid or group.gr_mem or any(user.pw_gid==gid for user in pwd.getpwall()):
            raise RuntimeError('role group still in use; reviewed cleanup required')
        run(['/usr/sbin/groupdel',name])


def reviewed_pam(stock: str,common: str) -> None:
    def active(text: str) -> list[str]:
        return [' '.join(line.split('#',1)[0].split()) for line in text.splitlines() if line.split('#',1)[0].strip()]
    expected=['auth [success=1 default=ignore] pam_unix.so nullok','auth requisite pam_deny.so','auth required pam_permit.so']
    lines=active(common)
    if lines not in (expected,expected+['auth optional pam_cap.so']):
        raise RuntimeError('custom common-auth/MFA stack is outside this preview; no PAM changes made')
    includes=[line for line in active(stock) if line.startswith('@include') or line.split()[0] in ('auth','-auth')]
    if includes!=['@include common-auth','@include common-account','@include common-session-noninteractive']:
        raise RuntimeError('custom sudo authentication stack is outside this preview')


def install(sponsor: Sponsor, source: Path) -> None:
    # This preview is deliberately gated to disposable Linux VMs while installation is evaluated.
    run(['/usr/bin/systemd-detect-virt','--vm'])
    if not re.fullmatch(r'[a-z_][a-z0-9_-]*',sponsor.name):raise ValueError('unsupported sudoers account spelling')
    run(['/usr/bin/sudo','-n','-l','-U',sponsor.name,'-u','root','--','/usr/bin/id','-u'])
    paths=InstallPaths(sponsor.uid);unit=f'sudo-relay-{sponsor.uid}.service'
    policy=Path('/etc/sudoers.d')/f'sudo-relay-{sponsor.uid}'
    pam=Path('/etc/pam.d')/f'sudo-relay-{sponsor.uid}'
    unit_path=Path('/etc/systemd/system')/unit
    if any(p.exists() or p.is_symlink() for p in (paths.configuration,paths.state,policy,pam,unit_path)):
        raise FileExistsError('preview installation already exists or conflicts')
    stock=Path('/etc/pam.d/sudo').read_text()
    reviewed_pam(stock,Path('/etc/pam.d/common-auth').read_text())
    defaults=run(['/usr/bin/sudo','-n','-l','-U',sponsor.name],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}).stdout.decode()
    if re.search(r'\bpam_(?:askpass_)?service\s*=',defaults):raise RuntimeError('existing sudo PAM-service override; administrator review required')
    names=[f'sr-agent-{sponsor.uid}',f'sr-review-{sponsor.uid}']
    for name in names:
        try:pwd.getpwnam(name)
        except KeyError:continue
        raise FileExistsError('preview role account already exists')
    for name in names:
        try:grp.getgrnam(name)
        except KeyError:continue
        raise FileExistsError('preview role group already exists')
    bundle={
      'sudo-relay-preview':source/'target/release/sudo-relay-preview',
      'mcp-server':source/'target/release/mcp-server',
      'approval-gate':source/'security-lab/sudo-prototype/target/release/approval-gate',
      'launcher.py':source/'preview/launcher.py',
      'sudo_adapter.py':source/'security-lab/integrated-sudo/launcher.py',
      'admin.py':source/'preview/admin.py',
      'install_context.py':source/'preview/install_context.py',
      'approval.html':source/'preview/approval.html',
      'channel.py':source/'preview/channel.py',
      'channel_setup.py':source/'preview/channel_setup.py',
      'ssh_stdio.py':source/'preview/ssh_stdio.py',
    }
    library=source/'security-lab/sudo-prototype/target/release/libsudo_relay_pam_prototype.so'
    if not all(p.is_file() for p in [*bundle.values(),library]):raise RuntimeError('build preview binaries first')
    shared_new=not LIB.exists()
    if not shared_new:
        for name,original in bundle.items():
            if (LIB/name).read_bytes()!=original.read_bytes():raise RuntimeError('different shared preview version; reviewed upgrade required')
        if PAM.read_bytes()!=library.read_bytes():raise RuntimeError('different PAM version; reviewed upgrade required')
    elif PAM.exists() or PAM.is_symlink():raise FileExistsError('PAM module path occupied')
    for parent in (LIB.parent,PAM.parent,paths.configuration.parent,paths.state.parent,policy.parent,pam.parent,unit_path.parent):trusted_ancestors(parent)
    old=baseline();created_users=[];created=[];shared_created=False
    try:
        if shared_new:
            if not LIB.parent.exists():LIB.parent.mkdir(mode=0o755);LIB.parent.chmod(0o755)
            LIB.mkdir(parents=True,mode=0o755);shared_created=True;LIB.chmod(0o755)
            for name,original in bundle.items():
                (LIB/name).write_bytes(read_source(original,sponsor.uid,sponsor.gid));(LIB/name).chmod(0o755 if name in ('sudo-relay-preview','mcp-server','approval-gate') else 0o644)
            PAM.write_bytes(read_source(library,sponsor.uid,sponsor.gid));PAM.chmod(0o755)
        private_directory(paths.configuration);created.append(paths.configuration)
        private_directory(paths.state);created.append(paths.state)
        gate=paths.state/'gate';private_directory(gate);private_directory(gate/'grants');private_directory(paths.state/'broker');private_directory(paths.state/'broker/keys')
        for name in names:
            run(['/usr/sbin/useradd','--system','--user-group','--no-create-home','--shell','/usr/sbin/nologin',name]);created_users.append(name)
        agent,review=[pwd.getpwnam(name) for name in names]
        run(['/usr/sbin/usermod','-aG',agent.pw_name,review.pw_name])
        machine=str(uuid.uuid4());write(gate/'machine',machine)
        run(['/usr/bin/openssl','genpkey','-algorithm','Ed25519','-out',str(gate/'internal-key.pem')])
        der=run(['/usr/bin/openssl','pkey','-in',str(gate/'internal-key.pem'),'-pubout','-outform','DER']).stdout
        if len(der)!=44 or der[:12].hex()!='302a300506032b6570032100':raise RuntimeError('unexpected grant key format')
        write(gate/'public.hex',der[12:].hex())
        config={'machine_id':machine,'agent_uid':agent.pw_uid,'approver_uid':review.pw_uid,
                'socket_gid':agent.pw_gid,'state_dir':str(paths.state/'broker'),'socket':str(paths.socket),
                'approval_ttl_secs':300,'max_execution_secs':5}
        write(paths.configuration/'enrollment.json',json.dumps({'config':config,'sponsor':asdict(sponsor)},indent=2)+'\n')
        write(pam,stock.replace('@include common-auth',f'auth sufficient {PAM} root={gate}\n@include common-auth'),0o644);created.append(pam)
        write(policy,f'Defaults:{sponsor.name} pam_service="sudo-relay-{sponsor.uid}", pam_askpass_service="sudo-relay-{sponsor.uid}"\n',0o440);created.append(policy)
        run(['/usr/sbin/visudo','-c'])
        text=('[Unit]\nDescription=sudo-relay fixed-command developer preview\nAfter=local-fs.target\n[Service]\n'
              f'ExecStart={LIB}/sudo-relay-preview serve {paths.configuration}/enrollment.json\n'
              f'RuntimeDirectory=sudo-relay/{sponsor.uid}\nRuntimeDirectoryMode=0755\n'
              'UMask=0077\nRestart=no\nKillMode=control-group\n[Install]\nWantedBy=multi-user.target\n')
        write(unit_path,text,0o644);created.append(unit_path)
        write(paths.configuration/'install.json',json.dumps({'sponsor':asdict(sponsor),'users':names,'baseline':old,'unit':unit,'shared_new':shared_new,'roles':{name:[pwd.getpwnam(name).pw_uid,pwd.getpwnam(name).pw_gid] for name in names}}))
        run(['/usr/bin/systemctl','daemon-reload']);run(['/usr/bin/systemctl','enable','--now',unit])
        for _ in range(100):
            if paths.socket.exists():break
            time.sleep(.05)
        else:raise RuntimeError('broker socket did not become ready')
        run(['/usr/bin/systemctl','is-active','--quiet',unit])
        if baseline()!=old:raise RuntimeError('original sudo/PAM files changed')
        print(json.dumps({'installed':True,'sponsor':sponsor.name,'machine_id':machine,'agent_uid':agent.pw_uid,'review_uid':review.pw_uid,'socket':str(paths.socket)}))
    except BaseException:
        subprocess.run(['/usr/bin/systemctl','disable','--now',unit],capture_output=True,timeout=30)
        for path in reversed(created):
            if path.is_dir():shutil.rmtree(path)
            else:path.unlink(missing_ok=True)
        remove_roles(created_users)
        if shared_created:shutil.rmtree(LIB);PAM.unlink(missing_ok=True)
        run(['/usr/bin/systemctl','daemon-reload'])
        raise

def main_locked() -> None:
    if sys.platform!='linux':raise RuntimeError('Linux only')
    os.umask(0o077);sponsor=sponsoring_account();paths=InstallPaths(sponsor.uid)
    args=sys.argv[1:]
    if args==['install']:install(sponsor,Path(__file__).resolve().parent.parent);return
    enrollment=paths.configuration/'enrollment.json'
    if args and args[0] in ('pair','revoke'):
        if args[0]=='pair' and len(args)==2:result=run([str(LIB/'sudo-relay-preview'),'pair',str(enrollment),args[1]])
        elif args==['revoke']:result=run([str(LIB/'sudo-relay-preview'),'revoke',str(enrollment)])
        else:raise ValueError('use pair PUBLIC_KEY or revoke')
        print('Approving key updated. Pending requests cancelled.');return
    if len(args)==3 and args[0]=='configure-channel':
        from channel_setup import configure
        configure(sponsor,args[1],args[2]);return
    if args==['status']:
        print(run(['/usr/bin/systemctl','is-active',f'sudo-relay-{sponsor.uid}.service']).stdout.decode().strip());return
    if args==['remove']:
        manifest=json.loads((paths.configuration/'install.json').read_text())
        if manifest['sponsor']!=asdict(sponsor):raise PermissionError('sponsor account changed; administrator recovery required')
        if 'roles' not in manifest:raise RuntimeError('use the matching installed removal helper for older preview state')
        from channel_setup import remove
        remove(sponsor.uid)
        run(['/usr/bin/systemctl','disable','--now',manifest['unit']])
        for p in (Path('/etc/systemd/system')/manifest['unit'],Path('/etc/pam.d')/f'sudo-relay-{sponsor.uid}',Path('/etc/sudoers.d')/f'sudo-relay-{sponsor.uid}'):p.unlink()
        run(['/usr/bin/systemctl','daemon-reload'])
        if 'roles' not in manifest:raise RuntimeError('use the matching installed removal helper for older preview state')
        remove_roles(manifest['users'],manifest['roles'])
        if baseline()!=manifest['baseline']:raise RuntimeError('sudo/PAM baseline changed; preserve state for review')
        shutil.rmtree(paths.state);shutil.rmtree(paths.configuration)
        if not any(Path('/etc/sudo-relay').glob('*/install.json')):shutil.rmtree(LIB);PAM.unlink()
        print('Removed preview installation; original sudo/PAM files unchanged.');return
    raise ValueError('use install, pair PUBLIC_KEY, revoke, status or remove')
def main() -> None:
    if sys.platform!='linux' or os.geteuid()!=0:raise PermissionError('sudo-elevated Linux administrator required')
    fd=os.open('/run/sudo-relay-admin.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o077:raise PermissionError('unprotected administrator lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        main_locked()
    finally:os.close(fd)

if __name__=='__main__':main()
