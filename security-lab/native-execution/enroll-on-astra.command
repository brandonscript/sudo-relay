#!/bin/sh
set -eu
cd "$(dirname "$0")"
app="$PWD/sudo-relay.app"
expected='@BINARY_SHA256@'
actual=$(/usr/bin/shasum -a 256 "$app/Contents/MacOS/sudo-relay" | /usr/bin/cut -d ' ' -f 1)
[ "$actual" = "$expected" ] || { echo 'Reviewer hash mismatch. Stop.' >&2; exit 1; }
/usr/bin/codesign --verify --strict -R '=anchor apple generic and identifier "com.sudorelay.receiptlab.astra" and certificate leaf[subject.OU] = "R86CYUZWPR" and cdhash H"@CDHASH@"' "$app"
printf '%s\n' 'Run in the ordinary Astra account, after logging out of the isolated signing account.' \
  'This creates a fresh execution-trial key. It does not pair a broker or run commands.'
exec "$app/Contents/MacOS/sudo-relay" --enroll
