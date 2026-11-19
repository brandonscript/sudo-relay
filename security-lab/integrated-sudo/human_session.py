"""Disposable Linux side of a human trial. No human approval private key exists here."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import signal
import sys
from typing import Any

source = importlib.util.spec_from_file_location('ssh_fixture', '/integration/test_ssh.py')
assert source and source.loader
module = importlib.util.module_from_spec(source)
source.loader.exec_module(module)
fixture = module.fixture
ROOT = Path('/lab')


def read() -> dict[str, Any] | None:
    line = sys.stdin.buffer.readline(4097)
    if not line:
        return None
    if len(line) > 4096 or not line.endswith(b'\n'):
        raise RuntimeError('bounded JSON line required')
    value = json.loads(line)
    if not isinstance(value, dict):
        raise RuntimeError('object required')
    return value


def write(value: dict[str, Any]) -> None:
    print(json.dumps(value), flush=True)


def main() -> None:
    signal.alarm(900)
    if sys.argv[1:]:
        raise RuntimeError('unsupported trial arguments')
    setup = read()
    if setup is None or set(setup) != {'public_key'} or not isinstance(setup['public_key'], str):
        raise RuntimeError('public-key setup required')
    fixture.initialize_fixture(setup['public_key'])
    trial = module.SshReview()
    try:
        trial.setUp()
        mcp, _ = trial.target(ttl=300)
        config = json.loads(trial.paths['sponsor_a'].read_text())['config']
        absent = fixture.run([sys.executable,'-I','-c',
            'from pathlib import Path; assert not Path("/lab/human/key.pem").exists()'],
            user=11003,group=11003,extra_groups=[],check=True)
        assert absent.returncode == 0
        identity = fixture.run(['/bin/cat',str(trial.root/'client')],
            user=11003,group=11003,extra_groups=[],check=True).stdout.decode()
        os_release = dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        write({'ok':True,'ready':True,'machine_id':config['machine_id'],
            'machine_name':'Astra Linux trial','operating_system':os_release['PRETTY_NAME'].strip('"'),
            'account':'sponsor_a','signing_key':setup['public_key'],'signing_key_id':'human',
            'known_hosts':'sudo-relay-linux '+(trial.root/'host.pub').read_text(),
            'transport_identity':identity,'software_approval_key_absent':True})
        request_id: str | None = None
        while (message := read()) is not None:
            if message == {'operation':'request'}:
                if request_id is not None:
                    raise RuntimeError('one request per human-trial container')
                pending = trial.request(mcp,needed=True)
                request_id = pending['envelope']['id']
                write({'ok':True,'pending':pending})
            elif message == {'operation':'status'} and request_id is not None:
                status = trial.value(trial.tool(mcp,'execution_status',{'id':request_id}))
                log = (ROOT/'sudo.log').read_text()
                write({'ok':True,'status':status,**fixture.command_log(log)})
            elif message == {'operation':'stop'}:
                break
            else:
                raise RuntimeError('unsupported trial operation')
    finally:
        trial.stop_all()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        write({'ok':False,'error':str(error)})
        raise SystemExit(1)
