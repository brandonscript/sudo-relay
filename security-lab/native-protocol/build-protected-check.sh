#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
  echo 'Usage: build-protected-check.sh OUTPUT' >&2
  exit 2
fi
output=$1
cd "$(dirname "$0")/../.."
check_dir=$(mktemp -d "${TMPDIR:-/tmp}/sudo-relay-protected-build.XXXXXX")
trap 'rm -rf "$check_dir"' EXIT HUP INT TERM
cargo build --locked --lib
swiftc -swift-version 6 -warnings-as-errors -module-cache-path "$check_dir/modules" \
  -I security-lab/native-protocol \
  security-lab/native-protocol/ProtectedReviewCheck.swift \
  security-lab/native-protocol/BrokerReview.swift \
  security-lab/native-protocol/ProtectedReceiptDecision.swift \
  security-lab/touch-id/Sources/ApprovalProbe/ReviewBoundary.swift \
  -L target/debug -lsudo_relay -framework Security \
  -framework SystemConfiguration -liconv -o "$output"
