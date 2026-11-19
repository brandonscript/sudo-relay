"""Forced SSH entry point: distinct UID-checked MCP and review capabilities."""
from __future__ import annotations
import json,os,socket,stat,struct,sys
from pathlib import Path


def main() -> None:
    if len(sys.argv)!=3 or sys.argv[2] not in ('agent','review') or os.getuid()==0:raise PermissionError('unprivileged channel role required')
    path=Path(sys.argv[1]);role=sys.argv[2]
    if not path.is_absolute():raise PermissionError('absolute target reference required')
    for parent in (path,*path.parents):
        info=parent.lstat()
        if info.st_uid!=0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):raise PermissionError('unprotected target reference')
    if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size>8192:raise ValueError('invalid target reference')
    target=json.loads(path.read_text())
    if os.getuid()!=target[role+'_uid']:raise PermissionError('wrong channel identity')
    if role=='agent':
        os.execv('/usr/local/libexec/sudo-relay/mcp-server',['mcp-server',target['socket'],'/usr/local/libexec/sudo-relay/approval.html'])
    raw=sys.stdin.buffer.read(65537)
    if len(raw)>65536:raise ValueError('oversized review request')
    request=json.loads(raw)
    if request.get('method') not in ('execution_status','approve','cancel_execution'):raise PermissionError('review channel cannot create requests')
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10);connection.connect(target['socket'])
        _,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0:raise PermissionError('root broker required')
        connection.sendall(raw+b'\n')
        with connection.makefile('rb') as file:
            reply=file.readline(4*1024*1024+1)
            if len(reply)>4*1024*1024 or not reply.endswith(b'\n'):raise ValueError('invalid bounded broker reply')
            sys.stdout.buffer.write(reply)
if __name__=='__main__':main()
