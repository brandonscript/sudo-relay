# Protected enrollment and separate verification

Working design, November 10, 2026. This is the next implementation sequence,
not a description of protection already shipped. Current work remains receipt-only.

## What must be trusted

The agent can launch programs, submit requests and edit its own files. Therefore
neither an app bundle nor a same-user policy file is a protected enrollment store.
An allowed executable can be launched by the agent; its identity alone does not
prove a person reviewed or approved a request.

The verifier must retain its own frozen request, enrolled approving public key,
required authentication mode, machine/enrollment identity, and consumption state.
The reviewer must obtain the request from an authenticated authority and display
the exact decision it will sign. A caller supplies an opaque request reference,
never a replacement request, authority key, policy or signing payload.

The production trust store and verifier installation require protection outside
the agent account. Implement that later in disposable machines before proposing
personal-machine installation. No sudo/PAM changes are authorized by this plan.

## Next receipt-only increment

1. Reuse `AuthenticatedReview` and `ReviewReceiptVerifier`; keep their lab domain
   separate from the production protocol. Move verification into another process
   without weakening request, signature, output-choice, expiry or one-use checks.
2. Keep the existing XPC peer experiment as an independent regression suite.
   Add a side-effect-free handshake before request retrieval or proof delivery.
   A reconnect starts a new handshake; no stale authenticated flag survives it.
3. Use a fixture controller to create explicit test enrollment. The controller
   pins authority and approving public keys independently of submitted requests.
   Software-key integration tests come first; native Touch ID follows with the
   user's own gesture. Never enroll whichever key first arrives over IPC.
4. Expose only request retrieval, decision submission, cancellation and status.
   Bound message sizes before decoding, reject unknown fields and unexpected
   states, and keep parsing failures separate from denied/expired outcomes.
5. Preserve verifier state independently of the UI lifetime. Closing the UI,
   losing the connection or receiving an ambiguous reply must not trigger a new
   signature or automatic submission. Reconnect queries the original request.

The first implementation can use ephemeral fixture state, but must label that
limitation. Durable consumption and crash/rollback handling are separate gates
before production; a second process is not itself protected deployment.

## Enrollment and update rules to implement

| Event | Required behavior |
|---|---|
| First enrollment | An authenticated administrator installs the authority and approving-key pins, required mode and allowed reviewer/verifier identities. The agent cannot enroll itself. |
| Multiple hosts or sponsors | Each machine/sponsor enrollment has a distinct identifier and request/receipt namespace. Display names are not security identities. |
| New approving device | Explicit authenticated pairing; an unknown public key cannot replace the current key through an approval request. |
| Revocation | Reject new decisions under the revoked enrollment/key; cancel pending work. Define separately what already consumed work means. |
| Reviewer update | Verify the authorized release and update policy before accepting its identity. No automatic trust of a newly observed code hash. |
| Downgrade or rollback | Reject a disallowed older reviewer/policy version; restoring a receipt store must not silently restore spent approvals. Mechanism still to select and test. |
| Lost key or changed fingerprints | Stop and require authenticated recovery. Never silently switch to session mode or enroll a replacement key. |
| Account replacement | Reused username/UID does not inherit enrollment. Sponsor provenance must still bind to the account that elevated during installation. |

Exact code hashes remain useful for disposable tests. Production must choose and
review an update policy: narrow Developer ID/team plus role identifiers, explicit
approved versions/hashes, or a combination. Signing certificates, distribution
and notarization are not configured yet. Do not invent a team identity or ask the
user for a private signing key in chat.

## Acceptance cases

- Correct request and proof produce one receipt; simultaneous copies produce one.
- Unknown key, substituted authority, altered request/output/mode/host/enrollment,
  expired proof and revoked enrollment produce none.
- An agent can open the genuine reviewer but cannot obtain a biometric signature
  without the user's gesture. Opening/handshaking alone creates no receipt.
- Wrong code identity is rejected on either side before sending sensitive data;
  same account or bundle identifier does not bypass the pin.
- A replacement connection must reauthenticate; disconnects before/after receipt
  creation never refund consumption or automatically retry an approval.
- UI exit and verifier exit have separate outcomes. Restart recovery must report
  uncertainty where state cannot establish whether consumption committed.
- Enrollment/update files writable through ownership, mode, ACL or replaceable
  parent paths are rejected in the protected-deployment fixture.

The final two deployment/recovery properties cannot be established by the current
same-user lab. Keep their checks open until the protected fixture actually exists.

## P-256 compatibility increment

The broker now supports administrator-selected P-256/SHA-256 public keys alongside
legacy Ed25519 keys, signing the existing canonical CBOR v2 decision bytes. This
avoids making the native lab's JSON protocol a production authorization format.
`pair-p256` records an explicit algorithm prefix; incoming requests cannot choose
or downgrade it. DER parsing and elliptic-curve verification use
[RustCrypto p256 0.14](https://docs.rs/p256/0.14.0/p256/ecdsa/index.html), with
`ecdsa` and `std` features and default features disabled.

`ui/test/p256-fixture.json` contains CryptoKit-generated signatures over both
existing sharing decisions. Rust and Node verification pass against those exact
bytes, with changed sharing rejected. The generation script uses a disposable
software key, writes no private key, and makes no biometric claim. Broker tests
also cover wrong keys, altered request/output, malformed signatures/points,
explicit non-overwriting pairing and replay; no executor is called.

This is not complete native integration. The native reviewer must still obtain
and validate the production request through authenticated IPC, display the same
model, and sign those exact CBOR bytes. Protected enrollment must distinguish a
biometric-required reviewer from a software/session signer; a P-256 key or a
label is insufficient. WebAuthn requires its own challenge/origin/RP/UV checks,
not simply this bare-signature verification path. Optional modes remain explicit;
there is no silent fallback.

The TypeScript host adapter now accepts explicit enrolled Ed25519 or P-256
signature formats. Both use the existing CBOR decision, and neither exposes an
algorithm selector to the MCP request. Adapter tests verify P-256 signatures for
both output choices, reject altered commands/output, reject unknown algorithms
before signing, enforce signature bounds and stop submission if approval expires
while the signer is waiting. This removes the old Ed25519-only transport check;
it does not turn the generic signing callback into a protected native channel.

The [native protocol bridge](../security-lab/native-protocol/README.md) now lets
Swift reuse Rust's request validation and CBOR encoder. Its foreign-call fixture
preserves the complete request model and both sharing decisions, and checks
CryptoKit public signatures. It performs no authentication or signing. The next
UI integration must take this model only from an authenticated verifier, render
all execution-relevant fields, and retain the same immutable decision bytes
through review. Do not forward arbitrary caller bytes to the biometric signer.

`BrokerReview` now implements the existing native form's presentation interface.
It decodes the Rust-validated envelope into immutable Swift fields, displays
structured arguments or a complete script, names the script interpreter, and
provides all request details. It retains the exact two decision byte strings and
checks expiry when selecting the checkbox choice. The automated form fixture
checks both command kinds, details and expired controls without opening a window.
The old native lab's thirteen tests still pass. Authenticated production request
retrieval and separate durable consumption are not connected to this model yet;
its initializer's name is a caller contract, not an authentication mechanism.

The native protocol fixture now runs `receipt-verifier`, a feature-gated,
ordinary-user Rust subprocess that reuses `Broker::handle` and its SQLite ledger.
It drops execution jobs instead of dispatching them. A software CryptoKit key
signs the native model's exact bytes: changed sharing rejects, one proof consumes,
replay rejects, and termination/restart preserves spent state (`uncertain`, never
pending). Transferring that proof to a new request rejects as well. A canary
remains absent. This joins native parsing/signing and real durable verification
over a test-controlled pipe; authenticated XPC retrieval and protected enrollment
remain separate, unfinished integration work.

The XPC harness now joins those components in its `durable-review` case. After
the pinned read-only handshake, the client retrieves a broker request, constructs
the native model, signs with a disposable software key and submits through XPC
to the bundled Rust verifier child. One consumption, altered-sharing rejection,
replay rejection and an absent canary pass. The service never restarts a failed
child or switches verification formats. Runtime child identity, protected
installation/enrollment and hardware signing on this joined path remain open;
bundle verification in the fixture is not a substitute for those boundaries.

The durable XPC mode now additionally requires a verifier code pin, validates the
file before launch and the running child before request delivery, and clears the
inherited environment. Replacement positive/negative controls and missing-pin
rejection pass; thirteen XPC cases pass locally. This closes the unchecked-child
path in the fixture, not the protected-installation requirement: static-check to
launch replacement races and injection remain unevaluated. No code-identity check
proves that a human approved, and no protected enrollment has been installed.

The explicitly selected durable native app now connects the accepted UI and
Touch ID signer to that CBOR/XPC/ledger path. The build and acknowledgement checks
pass; fresh hardware approval/cancellation/expiry evidence is still required.
Its ephemeral public-key enrollment is non-overwriting but remains self-created
in writable lab state. Do not call this administrator-protected pairing.

The dependency and its transitive graph are locked. This increment is not a full
cryptographic dependency audit; upstream advisories and release provenance still
need the release review already listed in the backlog.

### Bounded protected file reads

Production broker configuration and approval public keys now use one bounded
reader: root-controlled ancestors, a regular root-owned file without group/world
write access, no-follow opening of the resolved final component, and a size check
both before and during reading. Limits are 64 KiB for configuration and 1 KiB for
a public key. macOS retains the conservative rejection of extended ACL entries.

The ordinary-user rejection test and lint checks pass locally. Disposable Linux
and macOS CI run 42938600587 passed valid reads, oversized files, directories, FIFOs,
writable ancestors/files and changed ownership; macOS also covered ACLs. Those root tests
are not run on the personal machine. This does not implement native enrollment
or claim atomicity against another root process changing policy while it is read.

The native client and XPC service now read `SudoRelayProtectedPeerPolicyPath` from
their bundle metadata when present. That path goes through the same root-protected
reader via a bounded C bridge. Missing, invalid or unprotected policy fails closed,
even when a valid fixture policy is available beside the app. Without that setting,
only bundles explicitly marked `SudoRelayReceiptFixture` may use fixture policy.
Both settings are sealed by the fixture's code signature. Protected deployment
must enforce the authorized bundle identity; an attacker who can substitute the
trusted binary is outside what this loader alone protects.

Local checks cover the explicit fixture positive control, absent configuration,
wrong-typed path, missing file and user-owned policy rejection without fallback.
The thirteen XPC cases still pass. C-bridge successful read/buffer-bound checks
are added to disposable root CI; local error-path checks verify untouched buffers.
This policy contains peer code requirements only. It does not protect the lab's
self-enrolled approving key or broker state, bind sponsor provenance, or constitute
a supported production installation. Those remain required work.

### Observed policy revocation

The XPC service re-reads peer policy before accepting connections and before
issuing reviews, disclosing status or accepting receipts. Any missing, malformed
or changed client/service/verifier requirement permanently invalidates that
service instance. It denies its in-memory request and stops its durable child;
restoring the old policy does not reactivate it. Cancellation remains available.

Nineteen receipt-only XPC cases pass locally, including five policy mutations on
an existing authenticated connection and one durable-ledger revocation case.
The durable request stays pending with zero consumption records and no canary.
The new C ABI positive/buffer cases also passed both disposable root CI jobs in
run 42939101885. Full macOS CI was still running when this evidence was recorded.

This is observation-based revocation, not an atomic revocation transaction. A
change and restoration between checks is not detected, and policy can change
after a check but before consumption. Persisted policy epochs, rollback across
service restart and coordination with the verifier remain open. These checks
also do not establish sponsor privilege revocation or protect fixture key storage.
