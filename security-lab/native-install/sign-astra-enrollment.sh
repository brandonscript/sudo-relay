#!/bin/sh
set -eu
cd "$(dirname "$0")"
/usr/bin/shasum -a 256 -c SHA256SUMS
template=${1:-"$HOME/Downloads/ReceiptLab-signed.zip"}
expected=d5e0c4a56d8178ecb0a68fe059b191d44d7456066e1ffd3d4c50357b0fceb06f
actual=$(/usr/bin/shasum -a 256 "$template" | /usr/bin/cut -d ' ' -f 1)
if [ "$actual" != "$expected" ]; then
  echo 'Original Astra marker archive does not match the reviewed build. Stop.' >&2
  exit 1
fi
stage=$(mktemp -d "${TMPDIR:-/tmp}/sudo-relay-enrollment-sign.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
/usr/bin/ditto -x -k "$template" "$stage/template"
original="$stage/template/ReceiptLab.app"
/usr/bin/codesign --verify --strict "$original"
/usr/bin/codesign -d --extract-certificates="$stage/cert" "$original"
identity=$(/usr/bin/shasum -a 1 "$stage/cert0" | /usr/bin/cut -d ' ' -f 1)
/usr/bin/codesign -d --entitlements "$stage/claims.plist" --xml "$original"
ready="$stage/sudo-relay-enrollment-ready"
/usr/bin/ditto Ready "$ready"
/usr/bin/ditto Unsigned/ReceiptLab-protected.app "$ready/ReceiptLab-protected.app"
/bin/cp "$original/Contents/embedded.provisionprofile" "$ready/ReceiptLab-protected.app/Contents/embedded.provisionprofile"
/usr/bin/codesign --force --sign "$identity" --options runtime --entitlements "$stage/claims.plist" \
  --timestamp=none "$ready/ReceiptLab-protected.app"
/usr/bin/codesign --verify --strict "$ready/ReceiptLab-protected.app"
/usr/bin/codesign -d --entitlements - --xml "$ready/ReceiptLab-protected.app"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$ready" sudo-relay-enrollment-ready.zip
echo 'Signed only. No key created or app launched.'
echo 'Move sudo-relay-enrollment-ready.zip to the ordinary account, then log out of this isolated signing account.'
