#!/bin/sh
set -eu
cd "$(dirname "$0")"
/usr/bin/shasum -a 256 -c SHA256SUMS
printf '%s\n' 'sudo-relay: one real sudo command, inside disposable Linux only.' \
  'Docker builds/runs as your ordinary account. Administrator authentication only installs temporary reviewer files and pins.' \
  'No host sudoers, PAM, SSH daemon or launchd settings are changed.' \
  'After reviewing the native dialog, approve with Touch ID yourself. The test removes its temporary installation and container.'
exec /usr/bin/python3 -I -B "$PWD/run_trial.py"
