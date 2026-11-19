"""Reversible experiment installer, restricted to the dedicated Astra VM."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys

MACHINE='9838ca5cac0344a2a9720e6a8a8b1ce3'
ROOT=Path('/lab')
UNIT=Path('/etc/systemd/system/sudo-relay-vm-lab.service')
MARKER=Path('/etc/sudo-relay-vm-lab-id')
SOURCE=Path(__file__).resolve().parents[2]
USERS={'sponsor_a':11001,'sr_observer':11002,'approver':11003,'agent':11004}
PASSWORD='disposable-vm-only-not-a-real-password'
FILES=[UNIT,MARKER,Path('/etc/pam.d/sudo-relay-vm-lab'),Path('/etc/sudoers.d/sr-vm-sponsor'),
       Path('/etc/sudoers.d/sr-vm-observer'),Path('/usr/local/bin/integrated-sudo-lab'),
       Path('/usr/local/bin/mcp-server'),Path('/usr/local/bin/approval-gate'),
       Path('/usr/local/lib/pam_relay_prototype.so'),Path('/usr/local/bin/python3')]


def require(condition: bool, message: str) -> None:
    if not condition:raise RuntimeError(message)


def run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv,check=True,capture_output=True,timeout=60,**kw)


def baseline() -> dict[str,str]:
    paths=[Path('/etc/sudoers'),Path('/etc/pam.d/sudo'),*Path('/etc/pam.d').glob('common-*')]
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def remove() -> None:
    manifest=json.loads((ROOT/'install-manifest.json').read_text())
    require(manifest['machine']==MACHINE,'wrong uninstall manifest')
    subprocess.run(['systemctl','stop','sudo-relay-vm-review.service'],capture_output=True,timeout=30)
    subprocess.run(['systemctl','disable','--now',UNIT.name],capture_output=True,timeout=30)
    for p in FILES:p.unlink(missing_ok=True)
    run(['systemctl','daemon-reload'])
    for name,uid in USERS.items():
        try: account=pwd.getpwnam(name)
        except KeyError:continue
        require(account.pw_uid==uid,'account identity changed; stop cleanup')
        run(['userdel',name])
    if Path('/integration').exists():shutil.rmtree('/integration')
    require(baseline()==manifest['baseline'],'original sudo/PAM changed')
    shutil.rmtree(ROOT)
    print(json.dumps({'uninstalled':True,'original_sudo_pam_unchanged':True}))


def install(public_key: str | None = None) -> None:
    if public_key is not None:
        require(re.fullmatch(r"p256-sha256:04[0-9a-f]{128}",public_key) is not None,"execution P-256 public key required")
    require(not ROOT.exists() and not ROOT.is_symlink() and not Path('/integration').exists() and not Path('/integration').is_symlink(),'existing lab paths')
    require(all(not p.exists() and not p.is_symlink() for p in FILES),'installation path collision')
    for name,uid in USERS.items():
        try:pwd.getpwnam(name)
        except KeyError:pass
        else:raise RuntimeError('account collision')
        try:pwd.getpwuid(uid)
        except KeyError:pass
        else:raise RuntimeError('UID collision')
    ROOT.mkdir(mode=0o755);ROOT.chmod(0o755)
    (ROOT/'install-manifest.json').write_text(json.dumps({'machine':MACHINE,'baseline':baseline()}))
    try:
        MARKER.write_text(MACHINE+'\n');MARKER.chmod(0o644)
        (ROOT/'integration-fixture').write_text('disposable')
        for name in ('enrollments','grants','human'):(ROOT/name).mkdir(mode=0o700)
        (ROOT/'machine').write_text(MACHINE)
        for name,uid in USERS.items():run(['useradd','-u',str(uid),'-M','-s','/bin/sh',name])
        run(['chpasswd'],input=('sponsor_a:'+PASSWORD+'\nsr_observer:'+PASSWORD+'\n').encode())
        os.chown(ROOT/'human',11003,11003)
        run(['usermod','-aG','agent','approver'])
        pairs=[('internal-key.pem','public.hex')]
        if public_key is None:pairs.append(('human/key.pem','human-public.hex'))
        else:(ROOT/'human-public.hex').write_text(public_key)
        for key,public in pairs:
            run(['openssl','genpkey','-algorithm','Ed25519','-out',str(ROOT/key)])
            der=run(['openssl','pkey','-in',str(ROOT/key),'-pubout','-outform','DER']).stdout
            (ROOT/public).write_text(der[-32:].hex())
        if public_key is None:os.chown(ROOT/'human/key.pem',11003,11003)
        for name in ('integrated-sudo-lab','mcp-server'):
            shutil.copy2(SOURCE/'target/debug'/name,Path('/usr/local/bin')/name)
        for name,target in [('approval-gate','/usr/local/bin/approval-gate'),('libsudo_relay_pam_prototype.so','/usr/local/lib/pam_relay_prototype.so')]:
            shutil.copy2(SOURCE/'security-lab/sudo-prototype/target/release'/name,target)
        Path('/usr/local/bin/python3').symlink_to('/usr/bin/python3')
        Path('/integration').mkdir(mode=0o755);Path('/integration').chmod(0o755)
        for name in ('test_mcp.py','test_integration.py','approver.py'):
            shutil.copy2(SOURCE/'security-lab/integrated-sudo'/name,Path('/integration')/name)
        shutil.copy2(SOURCE/'security-lab/integrated-sudo/launcher.py','/integration/container_launcher.py')
        shutil.copy2(SOURCE/'security-lab/lima/vm_launcher.py','/integration/launcher.py')
        Path('/integration/approval.html').write_text('VM lab, software test approvals only')
        for p in Path('/integration').iterdir():p.chmod(0o644)
        policy=Path('/etc/sudoers.d/sr-vm-sponsor')
        defaults='Defaults:sponsor_a !use_pty, log_output, log_exit_status, logfile="/lab/sudo.log", iolog_dir="/lab/io"\n'
        policy.write_text(defaults+'sponsor_a ALL=(root) PASSWD: /usr/local/bin/python3 -I /integration/launcher.py enroll, /usr/bin/id -u\n');policy.chmod(0o440)
        observer=Path('/etc/sudoers.d/sr-vm-observer');observer.write_text('sr_observer ALL=(root) PASSWD: /usr/bin/id -u\n');observer.chmod(0o440)
        run(['visudo','-c'])
        result=run(['/usr/bin/sudo','-k','-S','--','/usr/local/bin/python3','-I','/integration/launcher.py','enroll'],
                   input=(PASSWORD+'\n').encode(),user=11001,group=11001,extra_groups=[],env={'PATH':'/usr/bin:/bin'})
        require(json.loads(result.stdout)['sponsor']['uid']==11001,'wrong enrolled sponsor')
        # Preserve stock account/session handling and ordinary-password fallback for this test user.
        original=Path('/etc/pam.d/sudo').read_text()
        require(original.count('@include common-auth')==1,'unexpected Ubuntu PAM stack')
        Path('/etc/pam.d/sudo-relay-vm-lab').write_text(original.replace('@include common-auth',
            'auth sufficient /usr/local/lib/pam_relay_prototype.so\n@include common-auth'))
        policy.write_text(defaults+'Defaults:sponsor_a pam_service="sudo-relay-vm-lab", pam_askpass_service="sudo-relay-vm-lab"\n'
                          'sponsor_a ALL=(root) PASSWD: /usr/bin/id -u\n')
        run(['visudo','-c'])
        directory=ROOT/'enrollments/11001';config=json.loads((directory/'enrollment.json').read_text())
        (ROOT/'socket-sponsor_a').mkdir(mode=0o755);(ROOT/'socket-sponsor_a').chmod(0o755)
        config['config']['socket']='/lab/socket-sponsor_a/broker.sock'
        config['config']['approval_ttl_secs']=60
        (directory/'enrollment.json').write_text(json.dumps(config))
        UNIT.write_text('[Unit]\nDescription=sudo-relay bounded VM experiment\nAfter=local-fs.target\n[Service]\n'
                        'ExecStart=/usr/local/bin/integrated-sudo-lab /lab/enrollments/11001/enrollment.json serve\n'
                        'Restart=no\nUMask=0077\nKillMode=control-group\n[Install]\nWantedBy=multi-user.target\n')
        run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',UNIT.name])
        require(baseline()==json.loads((ROOT/'install-manifest.json').read_text())['baseline'],'original sudo/PAM changed')
        print(json.dumps({'installed':True,'sponsor':11001,'software_test_key':public_key is None}))
    except BaseException:
        remove()
        raise


if __name__=='__main__':
    require(os.geteuid()==0 and sys.platform=='linux' and not Path('/.dockerenv').exists(),'dedicated root VM only')
    require(Path('/etc/machine-id').read_text().strip()==MACHINE,'wrong VM identity')
    require(run(['systemd-detect-virt','--vm']).stdout.strip()==b'apple','expected Apple Virtualization VM')
    os.umask(0o077)
    if sys.argv[1:]==['install']:install()
    elif len(sys.argv)==3 and sys.argv[1]=='install-human':install(sys.argv[2])
    elif sys.argv[1:]==['remove']:remove()
    else:raise RuntimeError('choose install or remove')
