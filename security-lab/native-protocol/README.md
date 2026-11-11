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
sh security-lab/native-protocol/check.sh
```

The Swift check compares the returned model and both CBOR decisions with the
shared fixture, verifies the public CryptoKit software-key signatures, and
checks wrong-host, expiry and insufficient-buffer failures. Rust tests additionally
reject modified payloads/digests, unknown fields, invalid metadata, forbidden
environment variables and misleading control characters, even when the input
digest and payload are internally consistent.

`BrokerReview.swift` decodes only the bridge's validated output into immutable
typed data, retains both exact decision byte strings and rechecks time before
returning the chosen decision. It implements the same presentation interface as
the older authenticated lab request. The existing native form now renders either
model, preserving the accepted layout and expiry behavior. Script bodies appear
unchanged in the code box with the interpreter in its label; structured arguments
use the existing quoting helper. Details include environment, agent explanation,
output hint, timeout, request identity and fixed working directory.
The Details dialog uses a scrollable text view so long environments or scripts
remain available. Its updated visual/accessibility behavior still needs a human check.

The automated fixture constructs the form without showing a window, compares
displayed argv/script content, checks details and expiry controls, and confirms
that model decisions equal the public proof vectors. Target display labels must
come from trusted enrollment, separately from the signed machine identifier;
the prototype protocol does not yet sign OS/account display metadata.

## Integration still required

This is not request authentication. Any local caller can manufacture a
self-consistent request and digest. The native app must authenticate the
verifier through its protected enrollment and IPC before accepting the request;
the paired machine identity must come from that enrollment. Do not expose the
biometric signer as an arbitrary-payload signing endpoint.

The current native/XPC lab still uses its separate JSON receipt format. Wiring
the new model into authenticated request retrieval, rechecking
expiry after authentication, and having the independent broker verify and
durably consume the exact approval remain open. The fixture proves byte-format
compatibility, not this end-to-end boundary or a production installation.
