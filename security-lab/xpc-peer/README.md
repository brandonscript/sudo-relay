# XPC peer identity experiment

Test whether macOS rejects the wrong program on either side of a local XPC
connection. **No command executes and no human approval is tested.** A transport
receipt is a fixed text file. Separate signed cases use disposable test keys;
the durable case exercises real broker approval bytes only in temporary lab state.

Run as an ordinary user on macOS 13 or later with Swift 6 and command-line tools:

```sh
python3 security-lab/xpc-peer/check.py
```

The harness builds client/service processes and a receipt-only Rust child into temporary app/XPC bundles, signs
them ad hoc with the hardened-runtime option, pins their exact code-directory
hashes, and runs thirteen cases. The signed-review case creates disposable software keys
in the temporary fixture directory. It uses no signing certificate, password,
biometric prompt, network listener, sudo/PAM change or installed service.
macOS launches the bundled helper on demand. Helpers retain state across individual
connection closures, subject to OS lifecycle management, with a hard limit of six minutes (allowing a five-minute native review); each client has a ten-second deadline and the harness has
bounded subprocess timeouts. Temporary bundles and receipts are removed at exit.

The development sandbox prevented the initial positive control from running;
the successful local test ran outside it, still as an ordinary user. A timeout,
crash or failed positive control is an error, never a security pass.

## Cases and observed results

November 10, 2026, local macOS 27.2, Swift 6.4.2: all six expected outcomes were
observed. The direct-call case is an intentionally unsafe pattern, not a protective pass.
The seventh, signed-review case passed locally and in the complete [CI run for `87dfece`](https://github.com/brandonscript/sudo-relay/actions/runs/42928675258). The eighth, cancellation case and native client build also passed in the complete [CI run for `beb1c37`](https://github.com/brandonscript/sudo-relay/actions/runs/42929213733).

The six-case XPC step also passed on the GitHub macOS runner for `ec459d5`;
the complete [CI run](https://github.com/brandonscript/sudo-relay/actions/runs/42927110278)
succeeded. Hosted-runner results are separate from local hardware/UI checks.

| Case | Expected / observed |
|---|---|
| Original client and service, both pinned | Read-only handshake succeeds; one transport receipt. |
| Different client bundle, its new identity explicitly pinned | One receipt, showing the changed bundle can run. |
| Same changed client, original identity still pinned | Connection rejected; zero receipts (`NSCocoaErrorDomain 4097`). |
| Different service bundle, its new identity explicitly pinned | One receipt, showing the changed service can run. |
| Same changed service, original identity still pinned | Reply rejected during handshake; zero receipts (`NSCocoaErrorDomain 4102`). |
| Changed service, original pin, consequential call sent before handshake | Client rejects the reply **after one remote receipt was created** (`4102`). Known unsafe sequence. |
| Signed review after authenticated handshake | Altered output choice rejected, valid proof accepted once, replay rejected. |
| Cancel before submitting a valid signed decision | Zero receipts; proof rejected. |
| Second authenticated connection, then close the first | Status remains approved; replay rejected. |

Variants retain the same account and bundle identifier; a changed sealed resource
and fresh ad-hoc signature produce a different code identity. Bundle signatures
are verified before every attempt. Positive controls for both variants distinguish
peer rejection from an unrelated failure to launch.

An initial negative case exposed a harness bug: Swift inherited main-actor
isolation for the XPC error closure, which XPC invokes on its background queue.
The explicit `@Sendable` callback fixed that crash. Neither that crash nor an
earlier unexplained process termination counted as evidence of correct rejection.

## Why the first message is read-only

The client sets a service code requirement, receives and validates a harmless
`hello` reply, and only then sends the receipt operation over that same connection.
The service checks the client's code requirement before delivering messages to
its exported object. There is no retry or reconnection that inherits the earlier
identity check.

The direct-call negative control demonstrates that setting the client-side
requirement alone does not guarantee that the first outgoing call has no remote
effects. Future integration must send no command, proof or secret in the initial
handshake and must not prompt/sign/consume as a side effect of opening a channel.
A malicious service can still perform its own actions upon receiving any message;
this test cannot constrain a different program's behavior.

Apple documents [connection peer requirements](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
and [listener requirements](https://developer.apple.com/documentation/foundation/nsxpclistener/setconnectioncodesigningrequirement(_:)).
The local SDK recommends setting the requirement before resuming a connection.
This bundled XPC service sets it on each accepted connection; the listener-wide
API is not supported for `serviceListener` instances.

## Signed review across processes

The seventh case compiles the existing `AuthenticatedReview` and
`ReviewReceiptVerifier` implementation into the two processes. The service owns
its frozen request and consumption state. The client authenticates the service
before retrieving its signed request, signs the complete decision with a disposable
P-256 software key, and submits it over that same connection. The service has only
the fixture's approving public key. Changing output sharing while retaining the
original proof fails; the valid decision succeeds once and replay fails.

The returned authority key is trusted through the pinned XPC service. It is not
trusted merely because it accompanies a signature. This fixture deliberately
uses software signing for automation, even though the reused request schema says
`touch-id`: **it provides no biometric evidence** and must not be wired into the
production approval path. Receipt counts for this case reflect the verified
submission responses, not a durable audit file. Service exit discards state.

## What this does not establish

The pins live in a fixture-owned, same-user JSON file outside the signed bundles
to avoid circular resource hashes. **An agent that can edit that file can change
the trusted peer.** The harness also creates the keys/pins and trusts its own
setup; it is not protected enrollment. An exact hash is convenient for this
single-build experiment, not a settled update/rollback policy.

There is no human request review, Touch ID/passkey proof, durable approval ledger,
cross-user isolation, trusted installation or broker integration here. Calling an
allowed executable is not proof that a human approved anything. The existing
standalone native lab remains available. The new manual native client connects its
UI and hardware signer across XPC; its human trial is tracked separately below.

Next: define protected enrollment and update policy, then connect the existing
authenticated review and biometric signing flow to a separate receipt verifier.
Keep the first call read-only, authenticate both peers, bind the complete request
and output choice, and test disconnect/restart/replay before any privileged use.
Linux requires a separately evaluated mechanism; these are macOS-specific tests.

## Native reviewer trial

`python3 security-lab/xpc-peer/check.py --prepare-native` also prepares a temporary
`sudo-relay lab.app`, using the existing shield icon and native review form. It
prints the app path but does not launch it. The ordinary automated run compiles
this client without invoking biometrics. The manual app runs these steps:

1. Check Touch ID capability and create an ephemeral biometric-protected key.
   Its encrypted representation stays in memory. Write only its public key into
   the disposable fixture enrollment file before starting the service.
2. Authenticate the XPC service with the harmless handshake, then retrieve and
   verify the service's frozen request. The service pins the native client's
   exact code hash before accepting messages.
3. Show the existing review. Freeze output sharing into the decision, require
   fresh Touch ID, and send the proof to the separate verifier. No fallback.
4. Close quietly after acceptance, denial, expiry or fingerprint cancellation.
   A disconnect reports an unconfirmed outcome; it never retries signing or
   submission. Unexpected failures remain visible.

Manual checks still required for this new path: successful approval, denial,
fingerprint cancellation, expiry while authentication is open, and disconnects
before/after submission. Prior same-process hardware trials do not prove this
integration. The first unattended separate-process trial reached its six-minute deadline and
logged `native-review-timeout-outcome-unconfirmed`. No interactive signature or
receipt was logged. This is not a successful hardware trial; a fresh user-run
check remains required. It was not automatically reopened.

This enrollment is deliberately self-created by the fixture, not administrator
protected. Both processes and the public-key/policy files are agent-writable.
No durable ledger or production key exists. A new launch creates a new enrollment;
this is unsuitable for production restart/recovery. The prepared app directory
is retained for the manual run; remove that exact temporary directory afterward.

## Connection loss and status

The ninth case passed locally on November 10, 2026. It accepts one software-signed
receipt, authenticates a second connection with a fresh harmless handshake, closes
the first, and checks the original request is still approved and replay fails.
The second channel stays alive throughout; this does **not** test service restart,
a crash, or a lost submission reply. The service no longer exits just because one
of several clients disconnects. Its six-minute safety deadline remains.

Status is read-only except that observing expiry makes it terminal. Unknown request
IDs return `unknown`, never `pending`. Denial cannot overwrite approval or observed
expiry. Thirteen native tests cover these terminal states, including an earlier
clock value after expiry and a new verifier reporting an old request as unknown.
This is not persistent clock-rollback protection: no durable state survives service
exit, and an unobserved clock rollback remains outside these checks. The native UI
still does not reconnect automatically or retry an ambiguous submission.

## Durable broker path through XPC

The tenth case, `durable-review`, passed locally November 10, 2026. It completes
the read-only XPC identity handshake, requests a receipt-only broker envelope,
validates it through `BrokerReview` and the Rust encoder, signs the selected
decision with a disposable software P-256 key, and submits it over the same
authenticated channel. The service forwards bounded messages to its bundled
ordinary-user `receipt-verifier` child. The real broker ledger consumes one proof;
changed output sharing and replay reject, and status reports `consumed`. The
canary file remains absent. No executor is called.

The Rust child is built only with the lab feature, signed ad hoc and included in
the service bundle. The harness verifies the bundle before running it. This is
not protected deployment: the fixture's bundle, configuration and keys remain
same-user writable. Child identity checks are described below; replacement races
and protected installation remain open. An XPC peer check by itself does not
authenticate a subsequently launched child process.

On child communication failure the service disables that path and returns no
result. It never restarts the child, retries an approval or falls back to the
older in-memory verifier. The separate pipe test covers Rust process restart and
spent approval persistence; this tenth case does not yet test an XPC service
restart or a lost submission reply. The existing manual Touch ID app still uses
the older JSON receipt path; no new hardware claim follows from this test.

## Verifier child identity

The durable XPC mode now requires a separate `verifier` code requirement in the
fixture enrollment. Before launch it validates the executable against that pin
with [SecStaticCodeCheckValidity](https://developer.apple.com/documentation/security/secstaticcodecheckvalidity(_:_:_:)).
After launch it obtains the child's code identity by PID and validates it, then
rechecks the live identity before sending each request. The child receives only
the explicit lab opt-in environment variable, not the parent environment. Any
validation failure aborts this path; there is no unpinned fallback or restart.
The standalone pipe fixture intentionally does not claim this identity check.

Three additional cases passed locally November 10, 2026:

- Re-sign the unchanged verifier under a different identity and explicitly pin
  it: the positive control still verifies one receipt and rejects replay.
- Use the same changed verifier with the original pin: service initialization
  rejects it; no SQLite ledger exists, showing the child did not start.
- Omit the verifier pin: initialization also rejects before the child starts.

These tests exercise pre-launch mismatch rejection and successful live-process
validation. They do not simulate an exec/replacement during the validation-to-launch
interval or prove protection against process injection. Static validation alone
is unsafe if another process can concurrently replace the file. Dynamic checks
before sending a request cannot undo effects of malicious code that already ran
at launch. Protected executable/ancestor ownership, enrollment and update policy
remain required; current same-user fixtures deliberately do not provide them.

## Touch ID with the durable verifier

`python3 security-lab/xpc-peer/check.py --prepare-native-durable` prepares, but
does not open, a fresh app with the existing shield/layout. Its signed bundle
explicitly selects the CBOR broker protocol. It never falls back to the original
JSON lab after an error. The original `--prepare-native` option remains a separate
experiment; the lack of durable state described above applies to that older path.

The new app creates an ephemeral biometric key, writes only the public key to
fresh fixture enrollment without overwriting, performs the XPC handshake, and
retrieves a broker-generated request. It displays the validated model, freezes
output sharing, asks for Touch ID, checks expiry again, and submits the exact
proof. Success requires a consumed acknowledgement for the same request ID and
an absent canary file. There is no extra success dialog. Denial, fingerprint
cancellation and expiry should close quietly. A submitted-but-unconfirmed proof
is never automatically retried or cancelled as though it were still pending.

Build and software regression checks pass; hardware behavior on this new path
is unverified. Coordinate with the participant before opening the app, then test
approval, denial, fingerprint cancellation and expiry during authentication on
separate fresh bundles. Inspect logs and the temporary ledger afterward without
launching an executor. The child deadline is six minutes to allow the five-minute
review. A reopened bundle refuses to overwrite its enrolled public key; prepare
a fresh fixture rather than replacing it or keeping a private signing key.

This remains self-enrollment in an agent-writable fixture. It is not production
pairing, a protected installation, or proof that the reviewing app cannot be
compromised. No actual sudo command or personal authentication policy is changed.

### Peer-policy source

Fixture bundles explicitly set `SudoRelayReceiptFixture` in their sealed metadata.
A configured `SudoRelayProtectedPeerPolicyPath` takes precedence and must name a
root-protected regular file of at most 4096 bytes; failure never falls back to the
fixture file. Client and service use the same reader. This protects loading of
peer code requirements when deployed with protected bundles; it does not turn the
same-user test key enrollment or receipt ledger into protected production state.

The service rechecks policy on each request and new connection. Once it observes
a changed, missing or invalid policy it stops accepting receipts for the rest of
that process lifetime, including after the old file is restored. The 19-case
harness covers existing connections and the durable ledger. This does not make
policy updates atomic with receipt consumption or prevent rollback on restart.
