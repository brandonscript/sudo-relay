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
