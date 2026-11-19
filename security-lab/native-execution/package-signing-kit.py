"""Prepare an unsigned app and public provisioning material; never accesses signing keys."""
from __future__ import annotations
from datetime import datetime, timezone
import uuid
import hashlib
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

REPO = Path(__file__).resolve().parents[2]
TEAM = 'R86CYUZWPR'
IDENTIFIER = 'com.sudorelay.receiptlab.astra'


def run(*args: str) -> None:
    result=subprocess.run(args,capture_output=True,text=True)
    if result.returncode:
        raise RuntimeError('Packaging command failed: '+str(args[0])+'\n'+result.stderr[-6000:])


def main() -> None:
    template, destination = map(Path, sys.argv[1:3])
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination=destination.with_name(f"{destination.stem}-{stamp}-{uuid.uuid4().hex[:8]}.zip")
    if destination.exists():
        raise RuntimeError('Output already exists; choose a fresh path')
    with tempfile.TemporaryDirectory(prefix='sudo-relay-execution-kit-') as temporary:
        stage = Path(temporary)
        original = stage/'original.app'
        prefix = 'sudo-relay-enrollment-ready/ReceiptLab-protected.app/'
        with zipfile.ZipFile(template) as archive:
            for item in archive.infolist():
                if not item.filename.startswith(prefix) or item.is_dir():
                    continue
                relative = Path(item.filename.removeprefix(prefix))
                if relative.is_absolute() or '..' in relative.parts or stat.S_ISLNK(item.external_attr >> 16):
                    raise RuntimeError('Unsafe template archive')
                path = original/relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.read(item))
                path.chmod((item.external_attr >> 16) & 0o777 or 0o644)
        run('/usr/bin/codesign','--verify','--strict',str(original))
        kit = stage/destination.stem;kit.mkdir()
        signing = kit/'Signing';signing.mkdir()
        run('/usr/bin/codesign','-d','--entitlements',str(signing/'entitlements.plist'),'--xml',str(original))
        claims = plistlib.loads((signing/'entitlements.plist').read_bytes())
        if claims.get('com.apple.developer.team-identifier') != TEAM or claims.get('com.apple.application-identifier') != f'{TEAM}.{IDENTIFIER}' or claims.get('keychain-access-groups') != [f'{TEAM}.{IDENTIFIER}'] or claims.get('com.apple.security.get-task-allow',False):
            raise RuntimeError('Unexpected signing authority or debugging entitlement')
        run('/usr/bin/codesign','-d',f'--extract-certificates={stage}/cert',str(original))
        (signing/'identity.txt').write_text(hashlib.sha1((stage/'cert0').read_bytes()).hexdigest()+'\n')
        shutil.copyfile(original/'Contents/embedded.provisionprofile',signing/'embedded.provisionprofile')
        app = kit/'Unsigned/sudo-relay.app/Contents'
        (app/'MacOS').mkdir(parents=True);(app/'Resources').mkdir()
        run('/bin/sh',str(REPO/'security-lab/native-execution/build-app.sh'),str(app/'MacOS/sudo-relay'))
        info = plistlib.loads((REPO/'security-lab/native-install/ReceiptLab-Info.plist').read_bytes())
        info['CFBundleExecutable']='sudo-relay';info['CFBundleIdentifier']=IDENTIFIER
        info['SRPreviewProtocol']='linux-developer-preview-v1'
        (app/'Info.plist').write_bytes(plistlib.dumps(info))
        shutil.copyfile(REPO/'assets/icon/sudo-relay.icns',app/'Resources/sudo-relay.icns')
        shutil.copyfile(REPO/'security-lab/native-execution/sign-on-astra.command',kit/'sign-on-astra.command')
        (kit/'sign-on-astra.command').chmod(0o755)
        source=kit/'Source';source.mkdir()
        for relative in ['src','security-lab/native-execution','security-lab/native-protocol','security-lab/touch-id/Sources/ApprovalProbe','preview']:
            shutil.copytree(REPO/relative,source/relative,ignore=shutil.ignore_patterns("__pycache__","target"))
        for relative in ['Cargo.toml','Cargo.lock']:
            shutil.copyfile(REPO/relative,source/relative)
        (kit/'README.txt').write_text('''sudo-relay disposable Linux execution reviewer — signing only

On Astra, sign in to the isolated Xcode signing account and run sign-on-astra.command.
It verifies the files, signs the app with the same isolated certificate/profile as
our receipt test, and creates a uniquely named ready ZIP and matching folder. It does not launch
an app, create a Keychain item, enroll a key, install a service or execute commands.

Return the ready ZIP and log out of the signing account. Do not enroll yet.
The preview can reuse the existing execution-purpose key in the ordinary
account. Do not re-enroll or delete a key merely because the reviewer changed.
Existing receipt keys are not reused. The execution reviewer accepts
only /usr/bin/id -u for the disposable Linux trial, with administrator-paired
identity and host-key pinning. No host sudo/PAM changes are included.

This is an experimental test build, not a release or a completed security audit.
The existing bundle identifier is retained for the isolated provisioning profile;
the new key uses a separate Keychain service. Public signing material is included,
never the certificate's private key. Source is provided for review.
''')
        files=sorted(p for p in kit.rglob('*') if p.is_file())
        (kit/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(kit)}\n' for p in files))
        destination.parent.mkdir(parents=True,exist_ok=True)
        with zipfile.ZipFile(destination,'x',zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(kit.rglob('*')):
                if path.is_file(): archive.write(path,path.relative_to(stage))
        print(destination)
        print('sha256',hashlib.sha256(destination.read_bytes()).hexdigest())


if __name__=='__main__':
    main()
