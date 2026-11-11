# Native protocol bridge

Receipt-only compatibility check. No command executes, no keychain is accessed,
and no biometric prompt appears.

The check also launches an ordinary-user Rust verifier subprocess using temporary
state and a disposable software P-256 key. It uses the real broker's signature
verification and SQLite consumption code, but drops every returned execution job.
It never starts the broker execution transport. The `receipt-verifier` binary
requires the explicit `native-receipt-lab` build feature and environment opt-in,
refuses root, bounds messages and exits after six minutes. It is not packaged by
the release workflow. These are accident guards, not proof of human approval.

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

The subprocess test creates a broker request, passes it through `BrokerReview`,
signs its exact decision with CryptoKit, and submits it to the independent Rust
process. Changed output sharing rejects, one valid proof consumes approval, and
replay rejects before and after terminating/restarting the verifier. Reusing the
proof for a fresh request also rejects. The canary command's target file remains
absent. Temporary state is removed after child processes stop; private signing
key material exists only in the test controller's memory.

After restart the existing broker reports `uncertain`, because it cannot prove
whether a consumed execution launched. This fixture deliberately never launches
anything; it does not rewrite that production state into a success claim. The
important checked property is that restart never restores permission to replay.

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

The original native/XPC lab uses its separate JSON receipt format. The explicit
`--prepare-native-durable` variant now wires the new model into authenticated
retrieval, Touch ID and durable verification, with post-authentication expiry and
matching-request acknowledgement checks. It compiles but needs a human hardware
trial. The pipe test itself is controlled by the fixture process; it is not
authenticated production IPC. Protected enrollment, crash-before-reply handling
and rollback recovery remain unverified.

### Protected request retrieval

`BrokerReview(protectedEnrollment:requestID:)` reads the target and display labels
from a root-protected receipt-lab enrollment record. The caller supplies no command,
socket, machine pin or account label. The bridge checks the caller's effective UID,
authenticates the root socket, requires the server's receipt-only marker and
validates the returned request and decision bytes before the model renders them.
It never submits approval or falls back to a caller-supplied request.

See [receipt enrollment format](../../docs/native-receipt-enrollment.md). The
interactive lab still uses its explicit fixture mode; protected key persistence,
sponsor provenance and interactive use of this enrollment remain unfinished.
