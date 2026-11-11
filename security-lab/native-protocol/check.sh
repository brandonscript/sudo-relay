#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
check_dir=$(mktemp -d "${TMPDIR:-/tmp}/sudo-relay-native-protocol.XXXXXX")
trap 'rm -rf "$check_dir"' EXIT HUP INT TERM
cargo build --locked --features native-receipt-lab --lib --bin receipt-verifier
swiftc -swift-version 6 -warnings-as-errors -module-cache-path "$check_dir/modules" \
  -I security-lab/native-protocol \
  security-lab/native-protocol/check.swift security-lab/native-protocol/BrokerReview.swift \
  security-lab/native-protocol/DurableCheck.swift \
  security-lab/native-protocol/ReceiptPipe.swift \
  security-lab/touch-id/Sources/ApprovalProbe/ReviewBoundary.swift \
  security-lab/touch-id/Sources/ApprovalProbe/NativeReviewForm.swift \
  -L target/debug -lsudo_relay -framework Security \
  -framework SystemConfiguration -liconv -o "$check_dir/check"
"$check_dir/check" "$PWD"
