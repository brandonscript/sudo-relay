#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
check_dir=$(mktemp -d "${TMPDIR:-/tmp}/sudo-relay-key-store-check.XXXXXX")
trap 'rm -rf "$check_dir"' EXIT HUP INT TERM
swiftc -swift-version 6 -warnings-as-errors -module-cache-path "$check_dir/modules" \
  security-lab/native-protocol/KeyStoreCheck.swift \
  security-lab/native-protocol/ReceiptSigningKeyStore.swift \
  security-lab/touch-id/Sources/ApprovalProbe/ReviewBoundary.swift \
  security-lab/touch-id/Sources/ApprovalProbe/BiometricSigning.swift \
  security-lab/touch-id/Sources/ApprovalProbe/Challenge.swift -o "$check_dir/check"
"$check_dir/check"
