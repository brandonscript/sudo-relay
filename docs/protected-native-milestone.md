# Protected native approval milestone

Agreed scope: November 10, 2026. One end-to-end macOS receipt flow, then stop for
review. No execution, sudo/PAM changes, remote-host work, Linux UI, release work
or icon changes belong to this milestone.

## Done means

- The native reviewer receives only a protected enrollment reference and request ID.
  It fetches the frozen request from an authenticated, separate verifier; the
  displayed command, target and signed output-sharing choice refer to that request.
- Installed reviewer/verifier code and enrollment cannot be replaced by the agent.
  Signing material is available only to the authorized reviewer. An agent-readable
  wrapped-key file is not accepted as evidence of protected signer storage.
- A new Touch ID gesture signs each approval. There is no session/software-key
  fallback in the interactive application, nor silent key creation or repair.
- A separate verifier checks its own enrolled key and pending request, persists
  one consumption and acknowledges it. The receipt domain cannot authorize an
  execution-mode broker. No executor is connected.
- Human checks cover success, denial, fingerprint cancellation, expiry before
  approval and expiry during authentication. Automated checks cover altered
  request/output, wrong signer/target, replay, concurrent duplicate submissions,
  missing/replaced enrollment and disconnect before/after consumption.
- Denial/cancellation/expiry creates no receipt. A lost acknowledgement is reported
  as unconfirmed, never retried. Success and deliberate cancellation close quietly.
- Evidence identifies the exact build and environment, records the ledger count
  and absence of execution, and separates hardware observations from software tests.
- The fixture has documented teardown. No personal-machine installation occurs
  until its concrete files, privileges and removal steps have been reviewed.

## Stop point

Stop once the checks above pass and present their evidence for review. If the
required protected hardware environment or signing identity is unavailable, stop
at that dependency with an explicit incomplete result; do not substitute an
unprotected demo or unrelated backlog work.

## Starting evidence

The headless Swift protected fetch/sign/submit path and independent broker passed
Linux/macOS disposable CI. The native UI and Touch ID have passed separate lab
checks. They are not yet one protected interactive system. See
[the current boundary map](protected-enrollment-plan.md).

A prior uncommitted change to the older XPC client's disconnect notice is retained
in the worktree; it is not part of the new protected flow's evidence. The approved
icon replacement is deferred until after this milestone review.

## Integration built for this milestone

`ProtectedNativeApp.swift` joins the existing native panel to the protected
`BrokerReview` fetch, one-attempt `ProtectedReceiptDecision`, Touch ID signer and
receipt submission bridge. It only reads an existing data-protection Keychain
item named by the SHA-256 digest of the protected public-key pin, under service
`sudo-relay.receipt-signer.v1`. Missing/inaccessible items fail; there is no file
fallback, key creation, enrollment tool or software-signing mode in this app.

The executable builds but is not installed, launched, signed for distribution or
paired. The Keychain restriction is a deployment requirement, not a verified
property of this source code: the selected signing identity/access group and
other-process denial tests must establish it. Build success does not prove it.

The same decision coordinator is used by the disposable root CI software helper.
It tests wrong-key rejection before signing, expiry after signing, refusal to
attempt signing twice and a successful protected receipt. C cancellation is
exercised against the separate root verifier; subsequent cancellation rejects.
CI results must be recorded before these additions are counted as passing.

Apple describes storing Secure Enclave encrypted key representations as Keychain
generic-password items in [Storing CryptoKit keys](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain).
This is storage guidance, not evidence that our app's enrollment/access policy works.

## Final test prerequisites

Before hardware testing, record the chosen Mac, OS, reviewer build/signing identity,
Keychain access group, protected installation/enrollment paths, approver UID and
verifier launch/teardown commands. Verify that a different ordinary process cannot
retrieve the signer item and cannot replace the installed code or enrollment.
Do not infer this from a successful legitimate-key lookup.

Enrollment must explicitly create a biometric-current-set Secure Enclave key in
the authorized reviewer and publish only its public key for administrator pairing.
This app currently has no enrollment action; provisioning is unfinished. An
existing test wrapped-key file must not be imported as a shortcut around those
checks. The user selected preparation of a narrowly scoped install on this Mac for
review. The [installation proposal](native-install-review.md) records the footprint
and unresolved signing gates. Nothing has been installed or written to the
personal Keychain by this milestone.

Local results for the first integration: Swift 6 warnings-as-errors builds pass
for the interactive app and headless helper; Rust lint and nine bridge tests pass;
existing native protocol checks pass. First disposable CI exposed a fixture-order
error (new request after a consumed receipt); commit `5ca3e37` moves cancellation
before consumption and adds cancelled-signing/no-retry checks. Full replacement CI 42950490558 passed for `5ca3e37`: all six jobs, including
both protected-account fixtures and the interactive-app build. These are software
and build results; no hardware prompt or protected Keychain setup was exercised.
