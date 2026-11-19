"""Exercise installed SSH role separation without an approving private key."""
from __future__ import annotations
import json,os,pwd,select,subprocess,tempfile
from pathlib import Path

source=Path(__file__).resolve().parents[1]
if os.geteuid()!=0:raise PermissionError('VM test driver only')
owner=pwd.getpwnam(os.environ['SUDO_USER']);enrollment=Path('/etc/sudo-relay')/str(owner.pw_uid)/'enrollment.json'
config=json.loads(enrollment.read_text())['config']
with tempfile.TemporaryDirectory(prefix='sr-preview-channel-') as directory:
    root=Path(directory)
    for role in ('agent','review','wrong'):
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/role)],check=True)
    keys=[' '.join((root/(role+'.pub')).read_text().split()[:2]) for role in ('agent','review')]
    configured=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/python3','-B',str(source/'preview/admin.py'),'configure-channel',*keys],
        user=owner.pw_uid,group=owner.pw_gid,extra_groups=[],env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,check=True)
    target=json.loads(configured.stdout);hosts=root/'known_hosts';hosts.write_text(target['host_key'])
    def ssh(role: str) -> list[str]:
        return ['/usr/bin/ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=sudo-relay-linux',
          '-o',f'UserKnownHostsFile={hosts}','-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
          '-i',str(root/role),'-p',str(target['port']),target[role+'_account']+'@127.0.0.1','ignored-shell-command']
    agent=subprocess.Popen(ssh('agent'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    def rpc(method,params):
        agent.stdin.write(json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params})+'\n');agent.stdin.flush()
        if not select.select([agent.stdout],[],[],15)[0]:raise RuntimeError('remote MCP timed out')
        return json.loads(agent.stdout.readline())
    try:
        assert 'result' in rpc('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'preview-ssh-test','version':'1'}})
        agent.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');agent.stdin.flush()
        request=rpc('tools/call',{'name':'request_execution','arguments':{'spec':{'command':{'kind':'argv','argv':['/usr/bin/id','-u']},'env':{},'reason':'SSH separation test','timeout_secs':5,'output_needed':False}}})
        pending=request['result']['structuredContent'];identifier=pending['envelope']['id']
        def review(value):return subprocess.run(ssh('review'),input=json.dumps(value).encode(),capture_output=True,timeout=15)
        status=review({'method':'execution_status','id':identifier});assert status.returncode==0,status.stderr
        assert json.loads(status.stdout)['value']['pending']==pending
        blocked=review({'method':'request_execution','spec':{}});assert blocked.returncode!=0
        cancelled=review({'method':'cancel_execution','id':identifier});assert cancelled.returncode==0 and json.loads(cancelled.stdout)['ok']
        hosts.write_text('')
        bad=review({'method':'execution_status','id':identifier});assert bad.returncode!=0 and b'Host key verification failed' in bad.stderr
        hosts.write_text(target['host_key'])
        wrong=ssh('review');wrong[wrong.index(str(root/'review'))]=str(root/'wrong')
        assert subprocess.run(wrong,input=b'{}',capture_output=True,timeout=15).returncode!=0
        print('PASS: SSH agent creates actual MCP request, review fetch matches, review cannot create requests, cancellation works, wrong host/client pins rejected')
    finally:
        agent.terminate();agent.communicate(timeout=10)
