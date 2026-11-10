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
hashes, and runs six cases. It uses no signing certificate, password, persistent
key, biometric prompt, network listener, sudo/PAM change or installed service.
macOS launches the bundled helper on demand. Helpers exit on disconnection or
after 15 seconds; each client has a ten-second deadline and the harness has
bounded subprocess timeouts. Temporary bundles and receipts are removed at exit.

The development sandbox prevented the initial positive control from running;
the successful local test ran outside it, still as an ordinary user. A timeout,
crash or failed positive control is an error, never a security pass.

## Cases and observed results

November 10, 2026, local macOS 27.2, Swift 6.4.2: all six expected outcomes were
observed. The last is an intentionally unsafe pattern, not a protective pass.

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

## What this does not establish

The pins live in a fixture-owned, same-user JSON file outside the signed bundles
to avoid circular resource hashes. **An agent that can edit that file can change
the trusted peer.** The harness also creates the keys/pins and trusts its own
setup; it is not protected enrollment. An exact hash is convenient for this
single-build experiment, not a settled update/rollback policy.

There is no request review, Touch ID/passkey proof, durable approval ledger,
cross-user isolation, trusted installation or broker integration here. Calling an
allowed executable is not proof that a human approved anything. The existing
native review lab remains a separate same-process experiment.

Next: define protected enrollment and update policy, then connect the existing
authenticated review and biometric signing flow to a separate receipt verifier.
Keep the first call read-only, authenticate both peers, bind the complete request
and output choice, and test disconnect/restart/replay before any privileged use.
Linux requires a separately evaluated mechanism; these are macOS-specific tests.
