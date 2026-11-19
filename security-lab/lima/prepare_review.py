"""Create and test a loopback-only review channel in the dedicated VM."""
from pathlib import Path
import json,os,subprocess
from install_vm import MACHINE,require
require(os.geteuid()==0 and Path('/etc/machine-id').read_text().strip()==MACHINE,'dedicated VM only')
r=Path('/lab/review');r.mkdir(mode=0o755);r.chmod(0o755)
def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,timeout=15,**kw)
for name in ('host','client','wrong'):
 run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(r/name)])
(r/'authorized_keys').write_text('restrict '+(r/'client.pub').read_text());(r/'authorized_keys').chmod(0o644)
Path('/lab/ssh-target.json').write_text(json.dumps({'socket':'/lab/socket-sponsor_a/broker.sock'}));Path('/lab/ssh-target.json').chmod(0o644)
run(['passwd','-d','approver'])
(r/'sshd_config').write_text(f'''Port 2222
ListenAddress 127.0.0.1
HostKey {r}/host
AuthorizedKeysFile {r}/authorized_keys
StrictModes yes
AllowUsers approver
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
PermitTTY no
X11Forwarding no
PermitUserEnvironment no
ForceCommand /usr/local/bin/integrated-sudo-lab review-channel
''')
run(['/usr/sbin/sshd','-t','-f',str(r/'sshd_config')])
run(['systemd-run','--unit=sudo-relay-vm-review','--collect','/usr/sbin/sshd','-D','-f',str(r/'sshd_config')])
(r/'known_hosts').write_text('sudo-relay-linux '+(r/'host.pub').read_text())
base=['ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=sudo-relay-linux','-o',f'UserKnownHostsFile={r}/known_hosts','-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-i',str(r/'client'),'-p','2222','approver@127.0.0.1']
reply=run(base+['review'],input=b'{"method":"execution_status","id":"00000000-0000-0000-0000-000000000000"}').stdout
require(json.loads(reply).get('ok') is False,'expected missing request response')
reply=subprocess.run(base+['sh -c id'],input=b'{"method":"request_execution","spec":{}}',capture_output=True,timeout=10)
require(reply.returncode!=0,'shell/request creation must not run')
(r/'known_hosts').write_text('')
wrong=subprocess.run(base+['review'],input=b'{}',capture_output=True,timeout=10)
require(wrong.returncode!=0 and b'Host key verification failed' in wrong.stderr,'missing host pin must reject')
(r/'known_hosts').write_text('sudo-relay-linux '+(r/'host.pub').read_text())
wrong=base.copy();wrong[wrong.index(str(r/'client'))]=str(r/'wrong')
require(subprocess.run(wrong+['review'],input=b'{}',capture_output=True,timeout=10).returncode!=0,'wrong client identity must reject')
print('PASS: forced review-only channel; shell/request creation, missing pin and wrong identity rejected; no approval submitted')
