"""Prepare transport keys and install a reviewed native preview target on macOS."""
from __future__ import annotations
import base64,hashlib,json,os,plistlib,tempfile,pwd,re,shutil,socket,stat,subprocess,sys,uuid
from pathlib import Path
from datetime import datetime,timezone


def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(argv,check=True,capture_output=True,timeout=60,**kwargs)


def matches_transport_key(derived: str,expected: str) -> bool:
    # OpenSSH may retain a comment; only the algorithm and encoded key identify it.
    return derived.split()[:2]==expected.split() and len(expected.split())==2


def validate(plan: dict) -> None:
    if type(plan.get('version')) is not int or plan.get('version')!=1:raise ValueError('invalid setup version')
    uuid.UUID(plan['machine_id'])
    for key in ('machine_name','operating_system','account','agent_account','review_account','lima_vm'):
        text=plan[key]
        if not isinstance(text,str) or not text or len(text)>100 or not text.isascii() or any(ord(c)<32 or ord(c)>126 for c in text):raise ValueError('invalid target label')
    for key in ('agent_account','review_account','lima_vm'):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',plan[key]) or plan[key]=='root':raise ValueError('invalid transport identity')
    if plan['agent_account']==plan['review_account']:raise ValueError('separate channel identities required')
    for field in ('agent_transport_public_key','review_transport_public_key'):
        fields=plan[field].split()
        if len(fields)!=2 or fields[0]!='ssh-ed25519':raise ValueError('invalid transport public key')
        decoded=base64.b64decode(fields[1],validate=True)
        if len(decoded)!=51 or decoded[:19]!=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':raise ValueError('invalid transport key encoding')
    if plan['agent_transport_public_key']==plan['review_transport_public_key']:raise ValueError('separate transport keys required')
    if type(plan['remote_port']) is not int or not 1<=plan['remote_port']<=65535:raise ValueError('invalid remote port')
    if not re.fullmatch(r'[A-Z0-9]{10}',plan['team']) or not re.fullmatch(r'[A-Za-z0-9.-]+',plan['bundle_id']):raise ValueError('invalid signing authority')
    if plan.get('keychain_group')!=plan['team']+'.'+plan['bundle_id']:raise ValueError('wrong Keychain access group')
    if not re.fullmatch(r'[0-9a-f]{40}',plan['cdhash']):raise ValueError('invalid code identity')
    if not re.fullmatch(r'[0-9a-f]{64}',plan['binary_sha256']):raise ValueError('invalid binary digest')
    key=plan['signing_key']
    if not isinstance(key,str) or not re.fullmatch(r'p256-sha256:04[0-9a-f]{128}',key):raise ValueError('P-256 public key required')
    if hashlib.sha256(bytes.fromhex(key.split(':')[1])).hexdigest()!=plan['key_fingerprint']:raise ValueError('public key fingerprint mismatch')
    if not re.fullmatch(r'sudo-relay-linux ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?\n?',plan['host_key']):raise ValueError('invalid host pin')
    host=base64.b64decode(plan['host_key'].split()[2],validate=True)
    if len(host)!=51 or host[:19]!=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':raise ValueError('invalid Ed25519 host key')


def keys(destination: Path) -> None:
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    directory=destination/('sudo-relay-transport-'+stamp+'-'+uuid.uuid4().hex[:8]);directory.mkdir(mode=0o700)
    for name in ('agent','review'):run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(directory/name)])
    print(directory)
    print('Only copy each public .pub key to Linux; private transport keys stay on this Mac.')


def prepare(connection: Path,candidate: Path,app: Path,vm: str,destination: Path) -> None:
    if sys.platform!='darwin' or os.getuid()==0:raise PermissionError('prepare in the ordinary approving Mac account')
    target=json.loads(connection.read_text());key=json.loads(candidate.read_text())
    if key.get('purpose')!='execution-lab-public-key-candidate-not-paired' or key.get('approver_uid')!=os.getuid():raise ValueError('wrong public approval candidate')
    info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
    if info.get('SRPreviewProtocol')!='linux-developer-preview-v1':raise ValueError('this signed reviewer does not declare preview support')
    run(['/usr/bin/codesign','--verify','--strict',str(app)])
    details=run(['/usr/bin/codesign','-d','--verbose=4',str(app)]).stderr.decode()
    team=re.search(r'^TeamIdentifier=([A-Z0-9]{10})$',details,re.M)
    digest=re.search(r'^CDHash=([0-9a-f]{40})$',details,re.M)
    if not team or not digest:raise ValueError('signed reviewer identity missing')
    with tempfile.TemporaryDirectory(prefix='sr-public-claims-') as temporary:
        claims_path=Path(temporary)/'claims.plist'
        run(['/usr/bin/codesign','-d','--entitlements',str(claims_path),'--xml',str(app)])
        claims=plistlib.loads(claims_path.read_bytes())
    if claims.get('com.apple.security.get-task-allow',False) or claims.get('keychain-access-groups')!=[key['keychain_group']]:raise ValueError('wrong Keychain or debugging entitlements')
    plan={'version':1,'machine_id':target['machine_id'],'machine_name':target['machine_name'],'operating_system':target['operating_system'],
          'account':target['account'],'agent_account':target['agent_account'],'review_account':target['review_account'],
          'lima_vm':vm,'remote_port':target['port'],'host_key':target['host_key'],
          'agent_transport_public_key':target['agent_transport_public_key'],'review_transport_public_key':target['review_transport_public_key'],
          'signing_key':key['signing_key'],'key_fingerprint':key['keychain_account'],
          'team':team[1],'bundle_id':info['CFBundleIdentifier'],'keychain_group':key['keychain_group'],'cdhash':digest[1],
          'binary_sha256':hashlib.sha256((app/'Contents/MacOS/sudo-relay').read_bytes()).hexdigest()}
    validate(plan)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output=destination/('sudo-relay-plan-'+stamp+'-'+uuid.uuid4().hex[:8]);output.mkdir(mode=0o700)
    (output/'target-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(output/'target-plan.json')


def install(app_source: Path,plan_path: Path,key_directory: Path) -> None:
    if sys.platform!='darwin' or os.getuid()!=0 or os.geteuid()!=0:raise PermissionError('Mac administrator setup required')
    uid=int(os.environ.get('SUDO_UID','0'))
    if uid==0 or os.stat('/dev/console').st_uid!=uid:raise PermissionError('elevate from the ordinary approving console account')
    account=pwd.getpwuid(uid)
    if os.environ.get('SUDO_USER')!=account.pw_name:raise PermissionError('sudo account mismatch')
    sys.path.insert(0,str(Path(__file__).resolve().parent));from install_context import read_source
    plan=json.loads(read_source(plan_path,uid,account.pw_gid,16384));validate(plan)
    # Import only the reviewed source's path checker; isolated Python ignores environment imports.
    sys.path.insert(0,str(Path(__file__).resolve().parent));from mac_mcp import protected
    base=Path('/Library/Application Support/sudo-relay')
    protected(base.parent)
    if not base.exists():base.mkdir(mode=0o755);base.chmod(0o755)
    protected(base)
    target=base/plan['machine_id']
    if target.exists() or target.is_symlink():raise FileExistsError('target already installed; reviewed removal required')
    target.mkdir(mode=0o755);target.chmod(0o755)
    try:
        app=target/'sudo-relay.app'
        for path in app_source.rglob('*'):
            info=path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):raise ValueError('nonregular app member')
        app.mkdir(mode=0o700)
        for path in app_source.rglob('*'):
            destination=app/path.relative_to(app_source)
            if path.is_dir():destination.mkdir(mode=0o700)
            else:destination.write_bytes(read_source(path,uid,account.pw_gid,25000000))
        info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
        if info.get('SRPreviewProtocol')!='linux-developer-preview-v1':raise ValueError('reviewer lacks preview protocol declaration')
        binary=app/'Contents/MacOS/sudo-relay'
        if hashlib.sha256(binary.read_bytes()).hexdigest()!=plan['binary_sha256']:raise ValueError('reviewed executable mismatch')
        binary.chmod(0o755)
        requirement=f'=anchor apple generic and identifier "{plan["bundle_id"]}" and certificate leaf[subject.OU] = "{plan["team"]}" and cdhash H"{plan["cdhash"]}"'
        run(['/usr/bin/codesign','--verify','--strict','-R',requirement,str(app)])
        claim_path=target/'verified-claims.plist'
        run(['/usr/bin/codesign','-d','--entitlements',str(claim_path),'--xml',str(app)])
        claims=plistlib.loads(claim_path.read_bytes());claim_path.unlink()
        if claims.get('com.apple.security.get-task-allow',False) or claims.get('keychain-access-groups')!=[plan['keychain_group']]:raise ValueError('wrong installed reviewer entitlements')
        for path in (app,*app.rglob('*')):
            os.chown(path,0,0);path.chmod(0o755 if path.is_dir() or path==binary else 0o644)
        source=Path(__file__).resolve().parent
        for name in ('mac_mcp.py','mac_setup.py','ssh_carrier.py','install_context.py'):
            (target/name).write_bytes(read_source(source/name,uid,account.pw_gid));(target/name).chmod(0o644)
        (target/'loopback.py').write_bytes(read_source(source.parent/'security-lab/native-execution/loopback.py',uid,account.pw_gid));(target/'loopback.py').chmod(0o644)
        for name in ('agent','review'):
            (target/name).write_bytes(read_source(key_directory/name,uid,account.pw_gid,4096));os.chown(target/name,0,account.pw_gid);(target/name).chmod(0o600)
        for role in ('agent','review'):
            public=run(['/usr/bin/ssh-keygen','-y','-f',str(target/role)]).stdout.decode().strip()
            if not matches_transport_key(public,plan[role+'_transport_public_key']):raise ValueError('transport private key does not match target pairing')
            (target/role).chmod(0o640)
        (target/'known_hosts').write_text(plan['host_key']);(target/'known_hosts').chmod(0o644)
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        enrollment={'version':1,'purpose':'linux-developer-preview-v1','approver_uid':uid,'machine_id':plan['machine_id'],
          'machine_name':plan['machine_name'],'operating_system':plan['operating_system'],'account':plan['account'],
          'signing_key':plan['signing_key'],'signing_key_id':'human','port':port,'ssh_user':plan['review_account'],
          'known_hosts':str(target/'known_hosts'),'identity':str(target/'review')}
        (target/'enrollment.json').write_text(json.dumps(enrollment,indent=2)+'\n');(target/'enrollment.json').chmod(0o644)
        ssh=['/usr/bin/ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=sudo-relay-linux',
             '-o',f'UserKnownHostsFile="{target}/known_hosts"','-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
             '-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-i',str(target/'agent'),'-p',str(port),plan['agent_account']+'@127.0.0.1']
        carrier=['/usr/bin/python3','-I',str(target/'ssh_carrier.py'),plan['lima_vm'],str(plan['remote_port'])]
        config={'version':1,'mcp_command':ssh,'reviewer':str(binary),'enrollment':str(target/'enrollment.json'),
                'carrier_command':carrier,'local_port':port}
        (target/'adapter.json').write_text(json.dumps(config,indent=2)+'\n');(target/'adapter.json').chmod(0o644)
        (target/'install.json').write_text(json.dumps({'owner_uid':uid,'machine_id':plan['machine_id'],'plan':plan},indent=2)+'\n');(target/'install.json').chmod(0o600)
        for path in target.rglob('*'):protected(path)
        print(json.dumps({'installed':True,'mcp_command':['/usr/bin/python3','-I',str(target/'mac_mcp.py'),str(target/'adapter.json')]}))
    except BaseException:
        shutil.rmtree(target)
        raise


def remove(identifier: str) -> None:
    if sys.platform!='darwin' or os.geteuid()!=0:raise PermissionError('Mac administrator removal required')
    if str(uuid.UUID(identifier))!=identifier:raise ValueError('canonical target UUID required')
    target=Path('/Library/Application Support/sudo-relay')/identifier
    sys.path.insert(0,str(Path(__file__).resolve().parent));from mac_mcp import protected
    protected(target);protected(target/'install.json')
    manifest=json.loads((target/'install.json').read_text())
    if manifest['machine_id']!=identifier or manifest['owner_uid']!=int(os.environ.get('SUDO_UID','0')):raise PermissionError('wrong approving account')
    shutil.rmtree(target);print('Removed Mac target files. Existing Keychain approval key retained.')

if __name__=='__main__':
    os.umask(0o077)
    if len(sys.argv)==3 and sys.argv[1]=='keys':keys(Path(sys.argv[2]))
    elif len(sys.argv)==7 and sys.argv[1]=='plan':prepare(Path(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4]),sys.argv[5],Path(sys.argv[6]))
    elif len(sys.argv)==5 and sys.argv[1]=='install':install(*map(Path,sys.argv[2:]))
    elif len(sys.argv)==3 and sys.argv[1]=='remove':remove(sys.argv[2])
    else:raise SystemExit('use keys DESTINATION, plan CONNECTION CANDIDATE SIGNED_APP VM DESTINATION, install SIGNED_APP PLAN_JSON TRANSPORT_DIRECTORY, or remove TARGET_UUID')
