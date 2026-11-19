#!/bin/sh
set -eu
cd "$(dirname "$0")"
/usr/bin/shasum -a 256 -c SHA256SUMS
identity=$(cat Signing/identity.txt)
case "$identity" in *[!0-9a-fA-F]*|'') echo 'Invalid certificate fingerprint' >&2; exit 1;; esac
[ "${#identity}" -eq 40 ]
stage=$(mktemp -d "${TMPDIR:-/tmp}/sudo-relay-execution-sign.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
stamp=$(date -u +%Y%m%dT%H%M%SZ)
unique=$(uuidgen | tr '[:upper:]' '[:lower:]')
name="sudo-relay-execution-ready-$stamp-$unique"
ready="$stage/$name"
output="$PWD/$name.zip"
[ ! -e "$output" ] || { echo "Output already exists; refusing to overwrite" >&2; exit 1; }
mkdir "$ready"
/usr/bin/ditto Unsigned/sudo-relay.app "$ready/sudo-relay.app"
/bin/cp Signing/embedded.provisionprofile "$ready/sudo-relay.app/Contents/embedded.provisionprofile"
/usr/bin/codesign --force --sign "$identity" --options runtime --entitlements Signing/entitlements.plist \
  --timestamp=none "$ready/sudo-relay.app"
/usr/bin/codesign --verify --strict "$ready/sudo-relay.app"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$ready" "$output"
printf '%s\n' 'Signed only. No app launched, key created, or command approved.' \
  "Return $output, then log out of the isolated signing account."
