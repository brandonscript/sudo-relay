# Chat approval: research and proposed next step

November 10, 2026. Production design proposal with an isolated, unprivileged experiment. Checked against main commit `41dd810`, the installed MCP Apps types, and the official sources linked below. The experiment does not implement a production signing boundary.

## Recommendation

Keep passkeys optional. The [approval experiment](../security-lab/approval-host/README.md) now offers passkey and session modes, with no command-execution path. For the eventual integration, keep command preview/status in chat and test a separate trusted review page. Start with a review environment the agent cannot operate or modify.

This is the most promising fallback found in this research, not a verified ChatGPT integration. It changes the original all-inline experience: the person may briefly leave the card and confirm with their authenticator. No sudo password enters chat. If entirely inline approval is essential, it remains blocked on a demonstrated host capability that protects both review and authorization.

The immediate deliverable is a fake-command approval receipt and a compatibility record. Nineteen local browser cases now pass, including two that deliberately reproduce weaker guarantees; see the experiment's verification record. Native sudo integration follows only after the selected mode's boundary is understood and tested in the real host.

## Optional authentication policy

| Enrollment choice | Protection promised | What the user accepts |
|---|---|---|
| Passkey | A fresh request-bound assertion with required user verification, plus request binding and one-use consumption. | The authenticator, enrollment and review environment still need to be trustworthy. A valid assertion does not prove which text was displayed. |
| Session, without a passkey | Authorization through the enrolled approval host's authenticated session, plus request binding and one-use consumption. | A stolen session or agent-controlled review browser can approve without the person. The number and button do not prove human presence. |

For production, choose the policy during authenticated enrollment and store it outside agent control. Show it in the approval UI and audit record. Bind it into the next protocol version alongside enrollment identity. A command request cannot select weaker protection. An unavailable or cancelled passkey must never silently fall back to session mode; changing policy requires the enrollment's administrative flow.

Session mode still needs an isolated approval host, authenticated users, CSRF/origin protection, request binding, expiry and durable consumption. Retain the existing host-signature design for this route: the isolated service attests a session-authorized decision with its protected key, and the broker checks that key's enrollment and permitted mode. This attests the service's decision, **not independently verified human presence**. There must be no model-callable generic signing API. The lab's one-use setup link is not a substitute for production login.

The absence of a documented signing API does not prove safe inline approval is impossible. A host could expose a protected, authenticated confirmation event that an isolated service binds to the frozen request. Before relying on that, verify the actual host's caller authentication, event provenance, freshness, decision binding and behavior under model calls, direct HTTP calls and browser automation. Native forms or UI-only tools are candidates to investigate, not established substitutes. No test suite can establish immunity to every exploit.

## What the sources establish

| Question | Evidence and consequence |
|---|---|
| Can ChatGPT render the card and open a review page? | Yes: the [UI reference](https://developers.openai.com/plugins/reference) documents MCP Apps integration and `openExternal`. It also documents tools restricted to the UI. These are useful interfaces; they do not establish that a human reviewed a particular command. |
| Does it expose our required signing host? | No equivalent to `TrustedHost.signHumanApproval` was found in the reviewed UI reference or [extension guide](https://developers.openai.com/plugins/build/extensions). This is a bounded documentation finding, not proof that no private or future capability exists. Native forms and confirmation prompts are not documented as a signed, broker-verifiable approval of our bytes. |
| Is account authentication sufficient? | The [authentication guide](https://developers.openai.com/plugins/build/auth) describes OAuth credentials and token validation. Our inference: a linked account authorizes access to tools; it does not independently prove fresh human consent for each root command. Keep those permissions separate. |
| Can a passkey work inside the card? | Unverified. [WebAuthn permissions](https://www.w3.org/TR/webauthn-3/#sctn-permissions-policy) require cross-origin iframe permission. Installed `@modelcontextprotocol/ext-apps` permission types do not declare a WebAuthn capability. Neither that absence nor adding a nested frame proves what ChatGPT actually permits. A top-level review page avoids depending on that delegation. |
| Can ChatGPT reach a private MCP without our own hosted relay? | [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) documents outbound connectivity to private stdio/HTTP MCP servers. It requires account/workspace association and tunnel permissions; availability in the intended account has not been checked. It is transport, not human authorization, and still uses OpenAI infrastructure. |
| Does this solve public distribution or phone connectivity? | No. The [connection guide](https://developers.openai.com/plugins/deploy/connect-chatgpt) distinguishes private testing from public plugin submission, which requires a public HTTPS endpoint. An MCP tunnel does not by itself host a phone-accessible approval website. Test that website over an explicitly configured private HTTPS route; do not silently add a public service. |

These sources do not establish working desktop or mobile support for sudo-relay. Browser dimensions in the preview are not evidence of phone integration.

## The proposed approval boundary

The requesting agent may submit commands, read authorized status/output, and cancel pending work. It must not control enrollment, the trusted review page, its browser, or the authenticator. A compromised review page can show command A while requesting approval of B; cryptography alone cannot fix that.

For passkey mode, use WebAuthn with the standard [assertion verification procedure](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion). Require user verification and presence, the enrolled credential, expected origin/RP identity, and a fresh challenge. Ordinary passkeys do not provide a trusted display of our command, and user verification is not necessarily a fresh biometric prompt on every platform. Verify actual behavior; do not promise otherwise. Synced credentials also must not be described as necessarily confined to one hardware device.

Proposed passkey flow (session mode substitutes its isolated host authorization for the authenticator ceremony):

1. The broker freezes the request and assigns a fresh nonce, expiry, machine identity and enrollment identity. The chat card displays a preview. The agent's explanation stays separately labeled.
2. A protected approval service fetches the authoritative request through an authenticated broker connection. The review URL contains only an opaque lookup identifier, not command text, output, a private key, or a bearer approval. Opening it cannot approve anything.
3. The trusted page displays the full command, target machine, sponsor, limits and output choice. It reuses the existing presentation helpers and two-digit confirmation. Pressing Enter requests the authenticator ceremony; it does not bypass it.
4. Freeze the complete decision. Generate a cryptographically random challenge in the verifier and persist its one-to-one association with the digest of the canonical decision bytes, enrollment, credential and expiry. A changed output choice or command requires a new ceremony. Do not accept a digest supplied by the page as authoritative.
5. Verify the assertion against that stored challenge and the broker's independently reconstructed decision. Atomically consume the pending request before launch. Parallel submissions, expired requests and reconnects cannot yield another launch. The prototype stops at a durable fake receipt.
6. Return status through the existing MCP polling flow. A return URL or page message is a navigation hint, never proof of approval. Status and output remain subject to enrollment authorization and the signed sharing choice.

The remembered output preference stays a convenience default. Every individual decision includes its explicit value. OAuth sessions, the two-digit number, UI-only tool visibility, CSRF protection and `postMessage` origin checks do not independently prove fresh human approval. Session mode deliberately accepts that limitation.

### Fit with the existing protocol

The current adapter requires a 64-byte Ed25519 signature over the v2 CBOR decision. A WebAuthn assertion is not that signature. Do not squeeze it into the existing field or add a browser-held key to make the types fit.

For the passkey route, prefer broker-side verification using a maintained WebAuthn library, a versioned approval format and updated shared vectors. That avoids depending on an intermediate service's general-purpose Ed25519 signing key for passkey assurance. Rust library selection and review remain implementation prerequisites. The approval service can relay assertions, but an HTTP session alone must never satisfy passkey policy. Session-mode host signatures must not be accepted as passkey proofs.

Retain deterministic encoding and include the enrollment identity in the next request/decision version. Bind challenges to the credential and enrollment; define one transaction for verification-state changes and approval consumption. Do not rely on an authenticator signature counter as the replay ledger. Old clients must fail closed rather than downgrade authentication.

An authenticated TLS connection to the paired approval service/broker is also necessary: re-hashing a request supplied by an attacker proves internal consistency, not its origin. The existing `verifyPending` check is not broker authentication. Keep service code, TLS credentials and pairing state outside agent-writable storage. No generic URL proxy or signing endpoint is needed.

## Enrollment and native execution follow-up

Keep the original requirement: the sponsor is the account actually authenticated for installation, with no account selector. The next Linux design must demonstrate OS-authenticated installer provenance, rather than trust a username argument or an environment variable. Give each enrollment a fresh identity and separate credentials, policy and ledger access; a numeric UID alone cannot identify a recreated account.

Check sponsor eligibility when creating a request and enforce current sudo policy during launch as that sponsor. Execute the approved command through native sudo with the independent one-use broker gate. Root is the target execution identity; the sponsor must remain the attributable invoker in audit records. Removing permission after approval must deny a later launch.

The fixture's replacement global PAM stack is not an installation recipe. Scoped authentication integration, policy enforcement for exact argv/scripts, installation rollback, stale group membership and account replacement still need a production design and disposable tests. The [pre-trial review](pre-trial-review.md) remains authoritative about those blockers. No change to the real Mac's authentication is part of this research.

## Work order and acceptance tests

First build the fake receipt experiment and test it in a normal browser. Then connect a read-only preview/status MCP to the intended ChatGPT account and test the handoff on desktop and phone. Only then select the production credential format, settle enrollment, and integrate the native Linux gate. macOS comes after the integrated Linux path passes.

The cases below remain **production host acceptance criteria**, not completed host verification. The experiment exercises portions of H1–H5 and H7; its catalogue identifies the exact coverage. H6 deliberately fails under a compromised review DOM/session. A virtual authenticator can test protocol rejection but cannot prove physical human presence or isolation from computer-use tools.

| ID | Test | Required observation |
|---|---|---|
| H1 | Fetch the approval URL, call APIs directly, forge parent messages, and submit the matching number without an assertion. | No receipt and no execution. A valid human ceremony is the positive control. |
| H2 | Try an unknown/revoked credential, wrong RP/origin, missing verification/presence, malformed assertion, and expired challenge. | Rejected without consuming unrelated pending work; bounded parsing and response sizes. |
| H3 | Change argv, environment, script, limits, machine, enrollment or output choice after the ceremony starts. | The old proof cannot approve the changed decision. Rendered data, stored decision and receipt correspond exactly. |
| H4 | Replay one assertion sequentially and concurrently; restart around consumption and retry. | At most one receipt, no automatic replay; ambiguous crash outcomes reported. |
| H5 | Deny/cancel, close the page, disconnect, or let the request expire during verification. | No late approval; reconnect shows the authoritative terminal state. |
| H6 | Use the agent's real tool/automation access against the proposed review environment. | For a human-presence claim, it cannot modify review or supply authorization. Session mode must disclose the weaker guarantee; passing request-binding tests does not remove it. |
| H7 | Exercise desktop and phone handoff, accessibility, long commands, Enter, output preference and return navigation. | Full review remains possible; unsupported authenticator/browser states fail closed; no automatic approval on return. Record OS/browser/client versions. |
| H8 | Lose, replace or revoke an approving credential; attempt cross-enrollment access and replay after account recreation. | No implicit recovery through chat, no inherited authorization; recovery requires authenticated administration. |
| H9 | Exceed the tunnel request deadline while human approval remains pending. | Request creation returns promptly; later polling observes the same request. No long-held MCP call or duplicate creation. |
| H10 | Inspect URLs, redirects, logs and model-visible results with output sharing off. | No authentication secret or withheld command output; endpoints enforce enrollment access. |

The existing [security test catalogue](../security-lab/test-cases.md) covers broker/fixture tests and links the new experiment results. Do not count this production-host matrix toward passing coverage.

## Where human help is needed

Research, design, the fake-command fixture and automated negative cases can proceed without credentials from the user. Later, a person must enroll their authenticator, perform the real approval/denial gestures and confirm the phone experience. Connecting the target ChatGPT account also depends on its actual permissions.

Before adopting the fallback, decide whether a brief trusted review page outside chat is acceptable. Session mode remains an explicit option for people who do not want passkeys; it must not inherit claims of independent human-presence verification. If all-inline approval is required, verify the real host's confirmation boundary before connecting it to root execution. Never present a conveniently hidden private key as proof of human consent.

Not checked here: real ChatGPT capability probes, physical authenticator behavior, tunnel account access, production Rust WebAuthn library suitability, installer provenance or native authentication changes. The local experiment does not clear the project for live root use.
