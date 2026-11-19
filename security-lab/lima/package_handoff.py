"""Package exact reviewed app and current VM pins; never signs or approves."""
from pathlib import Path
from datetime import datetime,timezone
import json,subprocess,hashlib,re,shutil,uuid,zipfile
import sys
repo=Path(__file__).resolve().parents[2]
archive,verification,candidate,destination=map(Path,sys.argv[1:5])
name='sudo-relay-vm-pairing-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
kit=destination/name;kit.mkdir()
command="export PATH=/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin; limactl shell --workdir=/ sudo-relay-lab sudo -n /usr/bin/python3 -c "+__import__('shlex').quote("import json;from pathlib import Path;r=Path('/lab');c=json.loads((r/'enrollments/11001/enrollment.json').read_text());print(json.dumps({'machine_id':c['config']['machine_id'],'known_hosts':'sudo-relay-linux '+(r/'review/host.pub').read_text()}))")
metadata=json.loads(subprocess.check_output(['ssh','-o','BatchMode=yes','astra',command],text=True))
pins=json.loads(candidate.read_text());pins.update(metadata);pins['machine_name']='Astra Linux VM'
shutil.copyfile(archive,kit/'signed-reviewer.zip')
app=verification/'sudo-relay-execution-ready/sudo-relay.app'
pins['archive_sha256']=hashlib.sha256(archive.read_bytes()).hexdigest();pins['binary_sha256']=hashlib.sha256((app/'Contents/MacOS/sudo-relay').read_bytes()).hexdigest()
sig=subprocess.run(['codesign','-d','--verbose=4',str(app)],capture_output=True,text=True,check=True).stderr
pins['cdhash']=re.search(r'^CDHash=(\w+)$',sig,re.M)[1]
(kit/'pins.json').write_text(json.dumps(pins,indent=2)+'\n')
for path in ['security-lab/lima/run_handoff.py','security-lab/native-execution/protected_install.py','security-lab/native-execution/loopback.py','security-lab/native-execution/run_trial.py']:
 shutil.copyfile(repo/path,kit/Path(path).name)
(kit/'run-vm-trial.command').write_text('#!/bin/sh\nset -eu\ncd "$(dirname "$0")"\n/usr/bin/shasum -a 256 -c SHA256SUMS\nexport PATH="/opt/homebrew/bin:$PATH"\nexec /usr/bin/python3 -I -B "$PWD/run_handoff.py" "$@"\n');(kit/'run-vm-trial.command').chmod(0o755)
(kit/'README.txt').write_text('''sudo-relay: one native approval for the full Linux VM

Run on Astra in your ordinary account, logged out of the signing account.
Do not re-enroll a key. This uses your existing execution key.

1. Run run-vm-trial.command --check in Terminal for a no-approval preflight.
2. Run run-vm-trial.command for the actual trial. It asks for normal Mac
   administrator authentication in Terminal to pin the exact signed reviewer,
   VM identity and approving key in a temporary protected directory.
3. Review Astra Linux VM, Ubuntu and sponsor_a, with /usr/bin/id -u.
   Choose output sharing, approve with Touch ID, and return the printed JSON.

The SSH review endpoint is pinned independently of the carrier. Linux has no
software approval key. Only one execution request is allowed; no approval retry.
Normal completion removes temporary Mac files and the VM test installation.
Docker and macOS sudo/PAM configuration are not changed. The existing Keychain
approval key is retained. This is an experimental fixed-command test.

The test VM installation is already prepared for this exact kit. Do not rerun an
old kit after cleanup or substitute a different VM/pin. If it stops, send the
report rather than reinstalling automatically. A force-kill or power loss may
leave temporary files; report their path for reviewed cleanup.
''')
files=sorted(p for p in kit.iterdir() if p.is_file());(kit/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files))
out=kit.with_suffix('.zip')
with zipfile.ZipFile(out,'x',zipfile.ZIP_DEFLATED) as z:
 for p in kit.iterdir():z.write(p,p.relative_to(kit.parent))
print(out)
