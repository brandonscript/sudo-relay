# Approval experiment results

November 10, 2026. The research prototype works with optional passkeys and a session-only alternative. A separate native Mac experiment also demonstrated two Touch ID approvals. **None of these experiments can execute a command.** They do not establish that sudo-relay is ready for privileged use in ChatGPT.

## What we verified

| Research requirement | Evidence | Limit |
|---|---|---|
| Optional passkeys in an unprivileged prototype | The [browser lab](../security-lab/approval-host/README.md) selects passkey or session mode at startup and refuses root. P1 verifies a passkey approval; P2 rejects missing proof and request-level downgrade. The user completed a real 1Password approval, and the page reported one receipt. | Disposable enrollment; no production account or broker pairing. |
| A usable non-passkey route | Session mode supports command review, number entry, Enter, output preference and terminal approval state. S3 exercises that flow at 390px. The [design](chat-approval-design.md#optional-authentication-policy) specifies protected enrollment policy and a separate signing host. | Session takeover permits approval. S1 demonstrates this rather than claiming to prevent it. Phone-sized layout is not mobile integration. |
| Binding to the approved request | P3 rejects changed output, request ID and injected command fields, then accepts the original proof. P4 rejects altered assertion fields. The native T1 test rejects changed request, command, machine, output and key. | Does not freeze executable dependencies or prove the user saw correct review text. |
| Replay and failure handling | P5 submits eight concurrent copies of one proof and accepts only one, then rejects replay. P6–P10 cover superseded challenges, expiry, denial, wrong numbers and missing verification/presence. R1 preserves receipts and invalidates pending work/session across restart. | These are lab receipts, not root launches; power-loss and rollback behavior remain unverified. |
| Real host/authenticator evidence | Real approval succeeded in ChatGPT's browser with user-reported 1Password use. The [native probe](../security-lab/touch-id/README.md) rejected both no-interaction attempts and verified two signatures; the user confirmed a separate Touch ID approval for each. | Not an MCP card, protected chat-host event or production signing helper. The successful 1Password phone-versus-desktop path was not specified. |
| Explicit trust boundaries | C1 demonstrates a compromised browser displaying different command text despite a valid assertion. S1 demonstrates automated session approval. Both are documented limitations. The host API review distinguishes documented rendering/authentication from unverified human-consent provenance. | No claim that an absent API proves impossibility, or that cryptography proves what a person saw. |
| No privileged installation or host authentication changes | Browser lab contains no execution path; native probe signs fixed experiment data using a temporary key representation held only in memory. Neither installs services, changes sudo/PAM, enrolls fingerprints or saves a persistent key. | The real passkey created by the user can remain in their credential provider until they remove it. Existing CI root fixtures are separate tests on disposable hosted runners. |

All five [CI jobs for code commit `5297989`](https://github.com/brandonscript/sudo-relay/actions/runs/42876985265) passed. The logs report **19 browser cases** and **3 native software-key/logging checks**, alongside existing Rust/TypeScript and disposable broker checks. The subsequent commits only record documentation and the user's hardware observations. The browser and native catalogues distinguish automated tests, manual observations and untested cases.

## Recommended direction

Keep passkeys optional. On Mac, native Touch ID is a promising way to avoid fetching a phone or opening a password manager. A locally available passkey may also give that experience without a native helper; it depends on the browser and credential provider. Session mode remains available to people who accept its weaker consent guarantee. Never switch to it automatically after failed authentication.

The next implementation decision is the trusted review boundary. A native helper must fetch an authenticated, frozen request and show the exact decision it signs; it must not accept arbitrary bytes from the agent. If review stays entirely in chat, first establish a protected host confirmation mechanism. A hidden key and a two-digit number do not provide that separation.

Production integration still needs authenticated sponsor enrollment, a versioned verification format for WebAuthn/P-256 alongside the existing Ed25519 format, protected policy and recovery, native sudo policy enforcement, and real desktop/mobile handoff tests. The [production acceptance matrix](chat-approval-design.md#work-order-and-acceptance-tests) remains open. Cancellation/lockout on real biometric hardware and credential-provider recovery also remain untested.

This completes the research-and-prototype deliverable. It does not certify security, implement the production host, or authorize installation on a personal machine.
