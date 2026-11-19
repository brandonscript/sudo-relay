"""Inject setup failure after actual account creation, then verify cleanup."""
from __future__ import annotations
import os
from pathlib import Path
import pwd
from unittest.mock import patch
import install_vm as installer

installer.require(os.geteuid()==0 and Path('/etc/machine-id').read_text().strip()==installer.MACHINE,'dedicated VM only')
original=installer.baseline()
real_run=installer.run


def fail(argv: list[str], **kw):
    if argv[0]=='chpasswd':raise RuntimeError('injected setup failure')
    return real_run(argv,**kw)


with patch.object(installer,'run',side_effect=fail):
    try:installer.install()
    except RuntimeError as error:
        if str(error)!='injected setup failure':raise
    else:raise AssertionError('injection not reached')
assert not Path('/lab').exists() and not Path('/integration').exists()
assert all(not p.exists() and not p.is_symlink() for p in installer.FILES)
for name in installer.USERS:
    try:pwd.getpwnam(name)
    except KeyError:continue
    raise AssertionError('test account remains')
assert installer.baseline()==original
print('PASS: injected setup failure removed created accounts/files and preserved original sudo/PAM')
