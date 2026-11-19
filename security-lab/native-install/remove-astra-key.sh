#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
  echo 'Usage: sh remove-key.command KEY_FINGERPRINT_FROM_PUBLIC_CANDIDATE' >&2
  exit 2
fi
cd "$(dirname "$0")"
app="$PWD/ReceiptLab-protected.app"
/usr/bin/codesign --verify --strict "$app"
exec "$app/Contents/MacOS/ReceiptLab" --remove-key "$1"
