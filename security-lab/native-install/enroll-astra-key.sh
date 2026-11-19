#!/bin/sh
set -eu
cd "$(dirname "$0")"
app="$PWD/ReceiptLab-protected.app"
/usr/bin/codesign --verify --strict "$app"
exec "$app/Contents/MacOS/ReceiptLab" --enroll
