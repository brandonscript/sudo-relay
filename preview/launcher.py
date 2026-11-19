"""Privileged bounded preview adapter; no client-selected paths or sponsor."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import sys
from typing import Any


def protected_file(path: Path, maximum: int = 16384) -> bytes:
    if not path.is_absolute():raise ValueError('absolute protected path required')
    for parent in path.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise PermissionError('unprotected ancestor')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as file:
        info=os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o077 or info.st_size>maximum:
            raise PermissionError('private root-owned context required')
        value=file.read(maximum+1)
    if len(value)>maximum:raise ValueError('oversized context')
    return value


def main() -> None:
    if os.getuid()!=0 or os.geteuid()!=0 or len(sys.argv)!=3:raise PermissionError('root preview adapter only')
    path=Path(sys.argv[1]);operation=sys.argv[2]
    context=json.loads(protected_file(path))
    sponsor=context['sponsor'];uid=sponsor['uid']
    if type(uid) is not int or uid<=0 or path!=Path('/etc/sudo-relay')/str(uid)/'enrollment.json':
        raise ValueError('installation identity mismatch')
    if context['config']['state_dir']!=f'/var/lib/sudo-relay/{uid}/broker':raise ValueError('wrong private state')
    root=Path('/var/lib/sudo-relay')/str(uid)/'gate'
    module_path=Path(__file__).parent/'sudo_adapter.py'
    spec=importlib.util.spec_from_file_location('sudo_adapter',module_path)
    if spec is None or spec.loader is None:raise RuntimeError('missing adapter')
    adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
    adapter.ROOT=root
    adapter.APPROVAL_GATE=['/usr/local/libexec/sudo-relay/approval-gate',str(root)]
    adapter.checkpoint=lambda _stage:None
    os.umask(0o077)
    raw=sys.stdin.buffer.read(65537)
    if len(raw)>65536:raise ValueError('oversized input')
    data=json.loads(raw)
    if data['sponsor']!=sponsor or adapter.identity(sponsor['name'])!=sponsor:
        raise PermissionError('sponsor account changed')
    def argv_for(value: dict[str,Any]) -> list[str]:
        if value['command']!={'kind':'argv','argv':['/usr/bin/id','-u']} or value.get('env'):
            raise ValueError('preview supports only /usr/bin/id -u')
        return ['/usr/bin/id','-u']
    adapter.argv_for=argv_for
    if operation=='check':
        adapter.policy(sponsor,argv_for(data['spec']));print('{}')
    elif operation=='launch':print(json.dumps(adapter.launch(data)))
    else:raise ValueError('unsupported operation')

if __name__=='__main__':main()
