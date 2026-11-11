# Native protocol bridge

Receipt-only compatibility check. No command executes, no keychain is accessed,
and no biometric prompt appears.

The native reviewer should not grow another implementation of the production
CBOR format. `src/native_review.rs` exposes the existing Rust encoder through a
small C interface. It takes a bounded pending request, independently supplied
paired machine identity and current time. It validates the request and produces
JSON containing the normalized envelope and both output-sharing decision byte
strings. Swift must display that returned model and select the final sharing
choice from its trusted review UI; it must not substitute text from chat.

The bridge checks version, identity syntax, validity window, the production
command/environment limits, supplied CBOR correspondence and SHA-256 digest.
It rejects unknown JSON fields. It owns no persistent state, holds no keys,
signs nothing and creates no receipt. Errors leave the caller's output buffer
untouched. C callers must supply valid, non-overlapping memory regions.

## Run on macOS

From the repository root:

```sh
cargo test --locked --lib native_review
cargo build --locked --lib
swiftc -swift-version 6 -warnings-as-errors \
  -I security-lab/native-protocol security-lab/native-protocol/check.swift \
  -L target/debug -lsudo_relay -framework Security \
  -framework SystemConfiguration -liconv -o /tmp/sudo-relay-native-protocol-check
/tmp/sudo-relay-native-protocol-check "$PWD"
```

The Swift check compares the returned model and both CBOR decisions with the
shared fixture, verifies the public CryptoKit software-key signatures, and
checks wrong-host, expiry and insufficient-buffer failures. Rust tests additionally
reject modified payloads/digests, unknown fields, invalid metadata, forbidden
environment variables and misleading control characters, even when the input
digest and payload are internally consistent.

## Integration still required

This is not request authentication. Any local caller can manufacture a
self-consistent request and digest. The native app must authenticate the
verifier through its protected enrollment and IPC before accepting the request;
the paired machine identity must come from that enrollment. Do not expose the
biometric signer as an arbitrary-payload signing endpoint.

The current native/XPC lab still uses its separate JSON receipt format. Wiring
this bridge into that UI, preserving all displayed execution details, rechecking
expiry after review/authentication, and having the independent broker verify and
durably consume the exact approval remain open. The fixture proves byte-format
compatibility, not this end-to-end boundary or a production installation.
