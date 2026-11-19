"""Ordinary-user Lima byte carrier; SSH above it authenticates the target."""
import os,re,sys
if len(sys.argv)!=3 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',sys.argv[1]) or not sys.argv[2].isdigit() or not 1<=int(sys.argv[2])<=65535:
    raise ValueError('VM name and loopback port required')
command=['/opt/homebrew/bin/limactl','shell','--workdir=/',sys.argv[1],'/usr/bin/python3','-I','/usr/local/libexec/sudo-relay/ssh_stdio.py',sys.argv[2]]
environment=dict(os.environ);environment.pop('LIMA_HOME',None)
os.execve(command[0],command,environment)
