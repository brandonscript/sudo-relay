"""Explicit full-VM lab adapter; imports the unchanged bounded container launcher."""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import stat
import subprocess

spec=importlib.util.spec_from_file_location('bounded_launcher','/integration/container_launcher.py')
assert spec and spec.loader
adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)


def contained() -> None:
    marker=Path('/etc/sudo-relay-vm-lab-id');info=marker.lstat()
    adapter.require(os.getuid()==0 and os.geteuid()==0,'root VM lab required')
    adapter.require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o022,'protected VM marker required')
    adapter.require(marker.read_bytes()==Path('/etc/machine-id').read_bytes(),'VM identity mismatch')
    adapter.require(subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True).returncode==0,'VM required')
    adapter.require((Path('/lab')/'integration-fixture').read_text()=='disposable','lab not initialized')
    os.umask(0o077)


def argv_for(value: dict) -> list[str]:
    adapter.require(value['command']=={'kind':'argv','argv':['/usr/bin/id','-u']} and not value.get('env'),
                    'VM milestone permits only /usr/bin/id -u')
    return ['/usr/bin/id','-u']


adapter.contained=contained
adapter.argv_for=argv_for
if __name__=='__main__':adapter.main()
