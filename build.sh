#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
    cd "$(dirname "$0")"
    if [ ! -f Cargo.toml ] || [ ! -f ui/package-lock.json ]; then
        printf '%s\n' 'Usage outside a checkout: sh build.sh ARCHIVE_URL SHA256' >&2
        exit 1
    fi
elif [ "$#" -eq 2 ]; then
    case "$1" in https://*) ;; *) echo 'Use an HTTPS archive URL.' >&2; exit 1;; esac
    case "$2" in *[!0-9a-f]*|'') echo 'Expected a lowercase SHA-256 checksum.' >&2; exit 1;; esac
    if [ "${#2}" -ne 64 ]; then
        echo 'Expected a 64-character SHA-256 checksum.' >&2
        exit 1
    fi

    work=$(mktemp -d ./sudo-relay-build.XXXXXX)
    wget --https-only -O "$work/source.zip" "$1"
    expected=$2
    cd "$work"
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s  source.zip\n' "$expected" | sha256sum -c -
    else
        printf '%s  source.zip\n' "$expected" | shasum -a 256 -c -
    fi
    unzip -q source.zip
    set -- */Cargo.toml
    if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ ! -f "${1%/*}/ui/package-lock.json" ]; then
        echo 'Expected one sudo-relay source directory in the archive.' >&2
        exit 1
    fi
    cd "${1%/*}"
else
    printf '%s\n' 'Usage: sh build.sh [ARCHIVE_URL SHA256]' >&2
    exit 1
fi

cargo build --locked
(cd ui && npm ci && npm run build)
printf 'Built sudo-relay in %s\n' "$PWD"
