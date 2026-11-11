# XPC peer identity experiment

Test whether macOS rejects the wrong program on either side of a local XPC
connection. **No command executes and no human approval is tested.** A transport
receipt is a fixed text file, not an approval or a signature usable by the broker.

Run as an ordinary user on macOS 13 or later with Swift 6 and command-line tools:

```sh
python3 security-lab/xpc-peer/check.py
```

The harness builds two small processes into temporary app/XPC bundles, signs
them ad hoc with the hardened-runtime option, pins their exact code-directory
hashes, and runs eight cases. The signed-review case creates disposable software keys
in the temporary fixture directory. It uses no signing certificate, password,
biometric prompt, network listener, sudo/PAM change or installed service.
macOS launches the bundled helper on demand. Helpers exit on disconnection or
after six minutes (allowing a five-minute native review); each client has a ten-second deadline and the harness has
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
integration. The initial separate-process hardware trial is pending.

This enrollment is deliberately self-created by the fixture, not administrator
protected. Both processes and the public-key/policy files are agent-writable.
No durable ledger or production key exists. A new launch creates a new enrollment;
this is unsuitable for production restart/recovery. The prepared app directory
is retained for the manual run; remove that exact temporary directory afterward.
