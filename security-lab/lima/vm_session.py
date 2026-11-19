"""One-request human session in the dedicated VM; holds no approval private key."""
from __future__ import annotations
import importlib.util,json,os,signal,sys,time
from pathlib import Path
from typing import Any
spec=importlib.util.spec_from_file_location('mcp','/integration/test_mcp.py')
assert spec and spec.loader
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ROOT=Path('/lab')
def write(value: dict[str,Any]) -> None:print(json.dumps(value),flush=True)
def main() -> None:
    if os.getuid()!=0 or Path('/etc/machine-id').read_text().strip()!='9838ca5cac0344a2a9720e6a8a8b1ce3':raise RuntimeError('dedicated VM only')
    signal.alarm(900)
    if (ROOT/'human/key.pem').exists():raise RuntimeError('software approval private key must be absent')
    data=json.loads((ROOT/'enrollments/11001/enrollment.json').read_text());config=data['config']
    trial=m.McpSudo();trial.children=[];request_id=None
    try:
        mcp=trial.mcp(config['socket'])
        os_release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        write({'ok':True,'machine_id':config['machine_id'],'machine_name':'Astra Linux VM',
            'account':'sponsor_a','operating_system':os_release['PRETTY_NAME'].strip('"'),
            'signing_key':(ROOT/'human-public.hex').read_text(),'signing_key_id':'human',
            'known_hosts':'sudo-relay-linux '+(ROOT/'review/host.pub').read_text(),
            'transport_identity':(ROOT/'review/client').read_text(),'software_approval_key_absent':True})
        for line in sys.stdin:
            if len(line)>4096:raise RuntimeError('oversized operation')
            operation=json.loads(line)
            if operation=={'operation':'request'} and request_id is None:
                if m.fixture.command_log((ROOT/'sudo.log').read_text())['sudo_launches']!=0:raise RuntimeError('trial already used; no automatic retry')
                pending=trial.request(mcp,needed=True);request_id=pending['envelope']['id']
                write({'ok':True,'pending':pending})
            elif operation=={'operation':'status'} and request_id:
                status=trial.value(trial.tool(mcp,'execution_status',{'id':request_id}))
                write({'ok':True,'status':status,**m.fixture.command_log((ROOT/'sudo.log').read_text())})
            elif operation=={'operation':'stop'}:
                if request_id:
                    trial.client(config['socket'],'submit',{'method':'cancel_execution','id':request_id})
                write({'ok':True,'stopped':True});return
            else:raise RuntimeError('unsupported session operation')
    finally:trial.stop_all()
if __name__=='__main__':main()
