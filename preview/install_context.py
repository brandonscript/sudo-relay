"""Installation identities derived from authenticated sudo provenance."""
from __future__ import annotations
from dataclasses import dataclass
import os
from pathlib import Path
import pwd
from typing import Mapping


@dataclass(frozen=True)
class Sponsor:
    name: str
    uid: int
    gid: int
    home: str
    shell: str

    @classmethod
    def from_record(cls, environment: Mapping[str,str], account: pwd.struct_passwd) -> Sponsor:
        try:
            uid=int(environment['SUDO_UID']);gid=int(environment['SUDO_GID'])
            name=environment['SUDO_USER']
        except (KeyError,ValueError) as error:raise ValueError('authenticated sudo identity required') from error
        if uid<=0 or uid!=account.pw_uid or gid!=account.pw_gid or name!=account.pw_name:
            raise ValueError('sudo identity does not match current account')
        return cls(name,uid,gid,account.pw_dir,account.pw_shell)


def sponsoring_account() -> Sponsor:
    if os.getuid()!=0 or os.geteuid()!=0:raise PermissionError('installer must be elevated by sudo')
    parent=Path('/proc')/str(os.getppid())
    if (parent/'exe').resolve()!=Path('/usr/bin/sudo'):raise PermissionError('actual sudo parent required')
    uids=next(line.split()[1:] for line in (parent/'status').read_text().splitlines() if line.startswith('Uid:'))
    if int(uids[1])!=0:raise PermissionError('sudo parent is not elevated')
    try:account=pwd.getpwnam(os.environ['SUDO_USER'])
    except (KeyError,ValueError) as error:raise PermissionError('current sponsoring account required') from error
    return Sponsor.from_record(os.environ,account)


@dataclass(frozen=True)
class InstallPaths:
    sponsor_uid: int

    def __post_init__(self) -> None:
        if type(self.sponsor_uid) is not int or self.sponsor_uid<=0:raise ValueError('non-root sponsor UID required')

    @property
    def configuration(self) -> Path:return Path('/etc/sudo-relay')/str(self.sponsor_uid)
    @property
    def state(self) -> Path:return Path('/var/lib/sudo-relay')/str(self.sponsor_uid)
    @property
    def socket(self) -> Path:return Path('/run/sudo-relay')/str(self.sponsor_uid)/'broker.sock'


def read_source(path: Path, uid: int, gid: int, maximum: int = 32*1024*1024) -> bytes:
    """Read setup inputs as the invoking user, never with administrator file access."""
    import subprocess
    code='''import os,stat,sys
path,limit=sys.argv[1],int(sys.argv[2])
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as stream:
 info=os.fstat(stream.fileno())
 if not stat.S_ISREG(info.st_mode) or info.st_size>limit:raise ValueError('bounded regular source required')
 value=stream.read(limit+1)
 if len(value)>limit:raise ValueError('oversized source')
 sys.stdout.buffer.write(value)
'''
    if type(uid) is not int or uid<=0 or type(gid) is not int or gid<0:raise ValueError('ordinary source identity required')
    credentials={} if os.geteuid()!=0 and uid==os.getuid() and gid==os.getgid() else {'user':uid,'group':gid,'extra_groups':[]}
    result=subprocess.run(['/usr/bin/python3','-I','-c',code,str(path),str(maximum)],
        **credentials,capture_output=True,check=True,timeout=30)
    return result.stdout
