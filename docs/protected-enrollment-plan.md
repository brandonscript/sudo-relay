# Protected enrollment and separate verification

Status: November 10, 2026. All experiments described here are receipt-only.
The protected software-signing path works in disposable Linux/macOS CI. The
interactive Touch ID path still uses separate, writable fixture enrollment.
**Those two results do not establish a protected interactive approval system.**

## What works now

The protected fixture follows this path:

1. A root test controller installs a bounded enrollment record with the machine,
   socket, approving UID, public signing key, key ID and display labels. The agent
   cannot pair itself. The native caller supplies only its record path and request ID.
2. The Rust bridge checks the protected record and authenticates the root socket
   before sending a status request. It validates the returned request ID, machine,
   canonical bytes, digest, receipt-only mode and validity window.
3. The Swift model displays that immutable request and checks the loaded signing
   key against the protected public-key pin. Its output-sharing choice selects
   the exact canonical bytes to sign. The CI helper uses a disposable software key.
4. Submission rereads enrollment, fetches current pending status and verifies the
   proof locally. The separate broker independently checks its enrolled key,
   revocation, request, sharing choice and expiry before consuming once.
5. Success requires a matching receipt-only acknowledgement. A lost or invalid
   reply is unconfirmed, even if consumption committed. Neither layer retries
   signing or submission automatically.

Receipt signatures use `sudo-relay/receipt-decision/v1` and `approve_receipt`.
The execution broker rejects this method; relabeling it as `approve` also fails
signature verification. Receipt consumption returns no execution job.
See the [record and API boundaries](native-receipt-enrollment.md).

Broker key revocation and pairing serialize with consumption in SQLite. Revocation
persists denial before file cleanup; pairing stays blocked until its file is
durable and enrollment commits. Both retire pending requests. Already-consumed
work is outside that guarantee. Process-kill tests do not prove physical power-loss
or restored-backup safety.

## Evidence and its limits

| Check | Evidence | What it does not prove |
|---|---|---|
| Protected files, socket and separate approving UID | `tests/privileged.rs`; disposable Linux/macOS CI | Production installation, sponsor provenance or UID-reuse protection |
| Swift fetch, signer pin, software proof, submission and replay | Full CI 42946565284; `ProtectedReviewCheck.swift` | Protected hardware key, native UI or human approval |
| Receipt/execution domain separation | Full CI 42946166927; protocol and broker tests | Integration with a real sudo launch |
| Lost reply before/after consumption, malformed acknowledgement and actual socket close | Full CI 42947279181; `native_review::tests` | Every possible crash, filesystem failure or user-visible disconnect |
| XPC client/service/verifier code pins and observed policy revocation | Nineteen local cases; `security-lab/xpc-peer` | Atomic policy revocation, protected installation or rollback prevention |
| Touch ID, denial, cancellation and expiry during authentication | [Native review runbook](native-review-boundary.md) | The newer cross-process protected flow; those hardware results came from the earlier lab |
| Reopening a saved key without silently replacing it | Build and software fixture tests; full CI 42945677976 | Hardware restart behavior, protected Keychain persistence or other-process isolation |

CI IDs refer to historical passing runs, not an assertion about every later commit.
The root fixtures run on disposable workers, never as a service on the personal Mac.

## Next implementation gates

1. **Protect the persistent signer.** Use a signed/hardened reviewer with a reviewed
   Keychain access policy, administrator-pinned public key and protected installation.
   Test another process, replaced code, missing/corrupt state and changed fingerprints.
   Failure must require explicit recovery, never a replacement key or session fallback.
2. **Join the interactive path to protected enrollment.** Reuse `BrokerReview` and
   the protected submission bridge. Run the full flow in a disposable macOS environment
   before proposing a personal-machine install. The current XPC native client and
   protected headless helper are separate fixtures, not interchangeable evidence.
3. **Make policy changes authoritative at consumption.** Persist enrollment/policy
   generations and coordinate updates with the verifier transaction. Define which
   approvals an update cancels; test old policy restoration and service restart.
   Current XPC revocation is observation-based: a change restored between checks
   can be missed, and a check-to-consumption race remains.
4. **Bind the sponsor.** Derive it from authenticated installer elevation, not a
   caller-selected username. Distinguish the approving account from the sponsoring
   sudoer; test account deletion, replacement, UID reuse and privilege revocation.
5. **Finish recovery and distribution.** Select authorized code-update/rollback
   rules, explicit device pairing/revocation, lost-key recovery, interrupted upgrades
   and removal. Signing identity, notarization and release installation remain open.

Exact code hashes work for disposable fixtures. Production still needs an explicit
update policy: narrowly scoped signing identity and role identifiers, approved
versions/hashes, or both. Never trust a new identity merely because it appeared.
Reopening a Secure Enclave key does not attest its biometric policy to the verifier;
that assurance depends on protected enrollment and the reviewed key-creation path.

## Acceptance cases before protected deployment

- Correct proof creates one receipt; concurrent copies and restart replay cannot
  create another. Changed request, output choice, mode, host or enrollment rejects.
- Unknown/revoked keys, replaced authority, expired requests and malformed/oversized
  messages reject. Parsing failure is not presented as a user denial.
- An agent may launch the genuine reviewer but cannot obtain a biometric signature
  without the person's gesture. Opening or handshaking alone creates no receipt.
- Authenticate each new connection before delivering requests, proofs or secrets;
  no stale trust survives reconnect. Reject substituted client/service/verifier code.
- Disconnects before or after consumption never refund it or trigger another approval.
  Closing the UI does not imply the verifier rolled back. Report uncertain outcomes.
- Reject writable ownership/modes/ACLs and replaceable parent paths. Test launch
  replacement races and runtime injection separately from file-read checks.
- Preserve per-machine/per-sponsor isolation, including duplicate display names and
  request IDs. Keep target identity in the signed request; labels alone are not identity.

Passkeys remain optional. Session-only mode has weaker assurance; inline-only
presentation closed one observed automation route, not all routes. A code signature,
app icon, hidden card field or P-256 public key alone is not proof of human approval.
