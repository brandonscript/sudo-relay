"""Administrator-owned loopback SSH endpoint for a single sponsor installation."""
from __future__ import annotations
import base64,json,pwd,secrets,socket,struct,subprocess
from pathlib import Path
from install_context import InstallPaths,Sponsor


def public_key(value: str) -> str:
    fields=value.split()
    if len(fields)!=2 or fields[0]!='ssh-ed25519':raise ValueError('supply ssh-ed25519 and its base64 key only')
    raw=base64.b64decode(fields[1],validate=True)
    if len(raw)!=51 or raw[:19]!=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':raise ValueError('invalid Ed25519 transport public key')
    return ' '.join(fields)


def configure(sponsor: Sponsor,agent_public: str,review_public: str) -> None:
    agent_public=public_key(agent_public);review_public=public_key(review_public)
    if agent_public==review_public:raise ValueError('MCP and review transport keys must differ')
    from admin import LIB,run,write,trusted_ancestors
    paths=InstallPaths(sponsor.uid);enrollment=json.loads((paths.configuration/'enrollment.json').read_text());config=enrollment['config']
    root=paths.state/'channel';public=Path('/usr/local/share/sudo-relay')/str(sponsor.uid)
    unit=Path('/etc/systemd/system')/f'sudo-relay-ssh-{sponsor.uid}.service'
    if root.exists() or public.exists() or unit.exists():raise FileExistsError('channel already exists; reviewed removal required')
    trusted_ancestors(public.parent)
    if not public.parent.exists():public.parent.mkdir(mode=0o755);public.parent.chmod(0o755)
    root.mkdir(mode=0o700);public.mkdir(mode=0o755);public.chmod(0o755)
    names={role:pwd.getpwuid(config[field]).pw_name for role,field in [('agent','agent_uid'),('review','approver_uid')]}
    try:
        run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/'host')])
        for role,key in [('agent',agent_public),('review',review_public)]:
            write(public/f'authorized_{names[role]}','restrict '+key+'\n',0o644)
            run(['/usr/sbin/usermod','--shell','/bin/sh',names[role]])
            # Unlock public-key login with an unrecorded high-entropy password, never empty authentication.
            password=secrets.token_urlsafe(48).encode()+b'\n'
            hashed=run(['/usr/bin/openssl','passwd','-6','-stdin'],input=password).stdout.decode().strip()
            run(['/usr/sbin/usermod','--password',hashed,names[role]])
        write(public/'target.json',json.dumps({'socket':config['socket'],'agent_uid':config['agent_uid'],'review_uid':config['approver_uid']}),0o644)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        text=f'''Port {port}
ListenAddress 127.0.0.1
HostKey {root}/host
AuthorizedKeysFile {public}/authorized_%u
StrictModes yes
AllowUsers {names['agent']} {names['review']}
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
Match User {names['agent']}
    ForceCommand /usr/bin/python3 -I {LIB}/channel.py {public}/target.json agent
Match User {names['review']}
    ForceCommand /usr/bin/python3 -I {LIB}/channel.py {public}/target.json review
'''
        write(root/'sshd_config',text)
        run(['/usr/sbin/sshd','-t','-f',str(root/'sshd_config')])
        write(unit,'[Unit]\nDescription=sudo-relay restricted transport\nAfter=network.target\n[Service]\n'
              f'ExecStart=/usr/sbin/sshd -D -f {root}/sshd_config\nRestart=no\nKillMode=control-group\n[Install]\nWantedBy=multi-user.target\n',0o644)
        run(['/usr/bin/systemctl','daemon-reload']);run(['/usr/bin/systemctl','enable','--now',unit.name])
        run(['/usr/bin/systemctl','is-active','--quiet',unit.name])
        export={'machine_id':config['machine_id'],'account':sponsor.name,'port':port,
                'host_key':'sudo-relay-linux '+(root/'host.pub').read_text(),
                'agent_account':names['agent'],'review_account':names['review'],
                'agent_transport_public_key':agent_public,'review_transport_public_key':review_public,
                'machine_name':socket.gethostname(),
                'operating_system':dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)['PRETTY_NAME'].strip('"')}
        write(public/'connection.json',json.dumps(export,indent=2)+'\n',0o644)
        print(json.dumps(export))
    except BaseException:
        remove(sponsor.uid)
        raise


def remove(uid: int) -> None:
    import shutil,subprocess
    unit=Path('/etc/systemd/system')/f'sudo-relay-ssh-{uid}.service'
    subprocess.run(['/usr/bin/systemctl','disable','--now',unit.name],capture_output=True,timeout=30)
    unit.unlink(missing_ok=True)
    for path in (Path('/usr/local/share/sudo-relay')/str(uid),InstallPaths(uid).state/'channel'):
        if path.exists():shutil.rmtree(path)
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,capture_output=True,timeout=30)
