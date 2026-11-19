"""Installed preview checks using a disposable software signer; run only in a test VM."""
from __future__ import annotations
import json,os,select,subprocess,sys,tempfile,time
from pathlib import Path
from typing import Any

LIB=Path('/usr/local/libexec/sudo-relay')

def main() -> None:
    if os.geteuid()!=0:raise PermissionError('root test driver required')
    enrollment=Path(sys.argv[1]);helper=Path(sys.argv[2])
    config=json.loads(enrollment.read_text())['config'];agent=config['agent_uid'];review=config['approver_uid'];gid=config['socket_gid']
    with tempfile.TemporaryDirectory(prefix='sudo-relay-preview-test-') as directory:
        root=Path(directory);os.chown(root,review,review)
        key=root/'key.pem'
        subprocess.run(['openssl','genpkey','-algorithm','Ed25519','-out',str(key)],check=True,capture_output=True)
        os.chown(key,review,review);key.chmod(0o600)
        der=subprocess.check_output(['openssl','pkey','-in',str(key),'-pubout','-outform','DER'])
        subprocess.run([str(LIB/'sudo-relay-preview'),'pair',str(enrollment),der[-32:].hex()],check=True)
        process=subprocess.Popen([str(LIB/'mcp-server'),config['socket'],str(LIB/'approval.html')],user=agent,group=gid,extra_groups=[],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env={'PATH':'/usr/bin:/bin'})
        def rpc(method: str,params: dict[str,Any]) -> dict[str,Any]:
            assert process.stdin and process.stdout
            process.stdin.write(json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params})+'\n');process.stdin.flush()
            if not select.select([process.stdout],[],[],15)[0]:raise RuntimeError('MCP response timeout')
            return json.loads(process.stdout.readline())
        def tool(name: str,value: dict[str,Any]) -> dict[str,Any]:
            result=rpc('tools/call',{'name':name,'arguments':value})
            if result.get('error') or result['result'].get('isError'):raise RuntimeError(str(result))
            return result['result']['structuredContent']
        rpc('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'preview-test','version':'1'}})
        assert process.stdin;process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');process.stdin.flush()
        spec={'command':{'kind':'argv','argv':['/usr/bin/id','-u']},'env':{},'reason':'Installed preview test','timeout_secs':5,'output_needed':True}
        try:
            pending=tool('request_execution',{'spec':spec});envelope=pending['envelope']
            payload=subprocess.check_output([str(helper),'decision-payload'],input=json.dumps({'envelope':envelope,'share_output':True,'receipt':False}).encode())
            data=root/'payload';data.write_bytes(bytes.fromhex(payload.decode()));os.chown(data,review,review)
            signature=subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-inkey',str(key),'-in',str(data)],user=review,group=review,extra_groups=[])
            proof={'method':'approve','id':envelope['id'],'key_id':'human','number':envelope['number'],'signature':signature.hex(),'share_output':True}
            client="import socket,json,sys; s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall(sys.stdin.buffer.read()+b'\\n');print(s.makefile().readline())"
            def submit(uid: int) -> dict[str,Any]:
                return json.loads(subprocess.check_output(['/usr/bin/python3','-I','-c',client,config['socket']],input=json.dumps(proof).encode(),user=uid,group=gid,extra_groups=[]))
            assert not submit(agent)['ok'],'agent approval accepted'
            assert submit(review)['ok'],'valid approval rejected'
            for _ in range(100):
                status=tool('execution_status',{'id':envelope['id']})
                if status['state']=='complete':break
                time.sleep(.05)
            assert status['state']=='complete' and status['outcome']['exit_code']==0 and status['outcome']['stdout']=='0\n',status
            assert not submit(review)['ok'],'replay accepted'
            subprocess.run(['/usr/bin/systemctl','restart','sudo-relay-'+enrollment.parent.name+'.service'],check=True)
            for _ in range(100):
                if Path(config['socket']).exists() and Path(config['socket']).stat().st_gid==gid:break
                time.sleep(.02)
            assert not submit(review)['ok'],'replay accepted after restart'
            recovered=tool('execution_status',{'id':envelope['id']})
            assert recovered['state']=='complete' and recovered['outcome'] is None,'incorrect restart outcome'
            print('PASS: service restart preserves completion/replay denial and honestly loses transient outcome')
            for path in (key,enrollment,Path(config['state_dir']).parent/'gate/internal-key.pem'):
                assert subprocess.run(['/bin/cat',str(path)],user=agent,group=gid,extra_groups=[],capture_output=True).returncode!=0
            print('PASS: installed MCP, per-sponsor context, root id-u, agent denial, replay denial and private-file isolation')
        finally:
            process.terminate();process.communicate(timeout=10)
            subprocess.run([str(LIB/'sudo-relay-preview'),'revoke',str(enrollment)],check=True)

if __name__=='__main__':main()
