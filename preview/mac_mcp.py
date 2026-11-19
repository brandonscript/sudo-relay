"""Unprivileged stdio MCP bridge; opens a protected reviewer, never signs proofs."""
from __future__ import annotations
from contextlib import nullcontext
import importlib.util
import json
import os
import select
from pathlib import Path
import stat
import subprocess
import sys
import threading
from typing import Any
import uuid

MAX_LINE=16*1024*1024

def protected(path: Path) -> None:
    if not path.is_absolute():raise PermissionError('absolute protected path required')
    for item in (path,*path.parents):
        info=item.lstat()
        if info.st_uid!=0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):raise PermissionError('unprotected adapter path')
        if sys.platform=='darwin':
            listing=subprocess.check_output(['/bin/ls','-lde',str(item)],text=True)
            if '+' in listing.split()[0]:raise PermissionError('extended ACL on protected path')


def load(path: Path) -> dict[str,Any]:
    protected(path)
    if path.stat().st_size>16384:raise ValueError('oversized adapter configuration')
    value=json.loads(path.read_text())
    base={'version','mcp_command','reviewer','enrollment'}
    if set(value) not in (base,base|{'carrier_command','local_port'}) or type(value['version']) is not int or value['version']!=1:raise ValueError('invalid adapter configuration')
    if 'carrier_command' in value:
        carrier=value['carrier_command']
        if not isinstance(carrier,list) or not carrier or not all(isinstance(x,str) and '\x00' not in x for x in carrier) or not Path(carrier[0]).is_absolute():raise ValueError('invalid carrier command')
        if type(value['local_port']) is not int or not 1<=value['local_port']<=65535:raise ValueError('invalid local port')
    command=value['mcp_command']
    if not isinstance(command,list) or not command or len(command)>64 or not all(isinstance(x,str) and '\x00' not in x for x in command):raise ValueError('invalid MCP command')
    for name in ('reviewer','enrollment'):
        if not isinstance(value[name],str):raise ValueError('invalid protected reference')
        protected(Path(value[name]))
    protected(Path(command[0]))
    return value


class ReviewTrigger:
    def __init__(self,reviewer: str,enrollment: str) -> None:
        self.reviewer=reviewer;self.enrollment=enrollment
        self.pending:set[str|int]=set();self.seen:set[str]=set();self.lock=threading.Lock()
        self.child:subprocess.Popen[bytes]|None=None

    def request(self,message: dict[str,Any]) -> None:
        if not isinstance(message,dict):raise ValueError('MCP message must be an object')
        params=message.get('params',{})
        if message.get('method')=='tools/call' and isinstance(params,dict) and params.get('name')=='request_execution':
            identifier=message.get('id')
            if type(identifier) not in (str,int):return
            with self.lock:
                if len(self.pending)>=128:raise RuntimeError('too many outstanding MCP requests')
                self.pending.add(identifier)

    def response(self,message: dict[str,Any]) -> None:
        if not isinstance(message,dict):raise ValueError('MCP message must be an object')
        identifier=message.get('id')
        if type(identifier) not in (str,int):return
        with self.lock:
            if identifier not in self.pending:return
            self.pending.remove(identifier)
        result=message.get('result',{})
        if not isinstance(result,dict) or result.get('isError') or 'error' in message:return
        content=result.get('structuredContent',{})
        if not isinstance(content,dict):return
        envelope=content.get('envelope',{})
        if not isinstance(envelope,dict):return
        request_id=envelope.get('id')
        if not isinstance(request_id,str) or len(request_id)!=36 or str(uuid.UUID(request_id))!=request_id:return
        if request_id in self.seen:return
        if len(self.seen)>=10000:raise ValueError('review reference limit reached; restart adapter')
        self.seen.add(request_id)
        if self.child is not None and self.child.poll() is None:
            print('A protected review is already open; cancel this request or open it manually after reviewing.',file=sys.stderr);return
        self.child=subprocess.Popen([self.reviewer,self.enrollment,request_id],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)

    def stop(self) -> None:
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()
            try:self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:self.child.kill();self.child.wait(timeout=5)


def bridge(config: dict[str,Any]) -> None:
    carrier=nullcontext()
    if "carrier_command" in config:
        path=Path(__file__).resolve().with_name("loopback.py")
        spec=importlib.util.spec_from_file_location("preview_loopback",path)
        if spec is None or spec.loader is None:raise RuntimeError("carrier unavailable")
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        carrier=module.LoopbackRelay("","preview",command=config["carrier_command"],port=config["local_port"],connections=3,idle_timeout=None)
    with carrier:
        forward(config)


def forward(config: dict[str,Any]) -> None:
    trigger=ReviewTrigger(config['reviewer'],config['enrollment'])
    child=subprocess.Popen(config['mcp_command'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    failed=threading.Event()
    def upload() -> None:
        assert child.stdin
        pending=b''
        try:
            while not failed.is_set():
                if not select.select([sys.stdin.fileno()],[],[],.1)[0]:continue
                data=os.read(sys.stdin.fileno(),65536)
                if not data:
                    if pending:raise ValueError('unterminated MCP input')
                    break
                pending+=data
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1)
                    if len(line)+1>MAX_LINE:raise ValueError('oversized MCP input')
                    trigger.request(json.loads(line));child.stdin.write(line+b'\n');child.stdin.flush()
                if len(pending)>=MAX_LINE:raise ValueError('oversized MCP input')
        except (OSError,ValueError,RuntimeError) as error:
            print('MCP input stopped: '+str(error),file=sys.stderr);failed.set();child.terminate()
        finally:
            try:child.stdin.close()
            except OSError:pass
    thread=threading.Thread(target=upload,daemon=True);thread.start()
    try:
        assert child.stdout
        while line:=child.stdout.readline(MAX_LINE+1):
            if len(line)>MAX_LINE or not line.endswith(b'\n'):raise ValueError('oversized MCP response')
            message=json.loads(line)
            sys.stdout.buffer.write(line);sys.stdout.buffer.flush()
            try:trigger.response(message)
            except (ValueError,OSError) as error:print('Protected review not opened: '+str(error),file=sys.stderr)
        if failed.is_set() or child.wait(timeout=5)!=0:raise RuntimeError('remote MCP stopped')
    finally:
        failed.set()
        trigger.stop()
        if child.poll() is None:child.terminate()
        try:child.wait(timeout=5)
        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        thread.join(timeout=5)

def main() -> None:
    if sys.platform!='darwin' or os.geteuid()==0 or len(sys.argv)!=2:raise RuntimeError('ordinary Mac account and protected adapter config required')
    if os.stat('/dev/console').st_uid!=os.getuid():raise RuntimeError('log out of the signing account and use the approving Mac console account')
    bridge(load(Path(sys.argv[1])))

if __name__=='__main__':main()
