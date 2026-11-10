# Touch ID and the approval fallback

November 10, 2026. Research with an isolated [native signing experiment](../security-lab/touch-id/README.md). No production helper or authentication changes have been implemented.

The intended experience is review in chat, enter the number, and confirm. A phone or separate browser should not be necessary for every request. Passkeys remain opt-in. An enrolled strong mode must never silently downgrade when its prompt fails.

The authenticator belongs to the approving device, not necessarily the execution machine. A paired Mac could approve a Linux server's request with Touch ID; the Linux server would verify the proof and would not need a fingerprint scanner. That requires an authenticated connection and machine-bound approval, neither of which this loopback experiment demonstrates remotely.

## Two ways to use Touch ID

**Try a local passkey first.** Touch ID can authorize a passkey on the Mac without fetching a phone. Apple documents this in its [Mac passkey guide](https://support.apple.com/en-ie/guide/passwords/mchl4af65d1a/mac). This reuses the existing WebAuthn experiment, but the enrolled credential must be available to the chosen browser/provider. The application cannot assume the browser will offer Touch ID or that user verification always means a new fingerprint scan. ChatGPT card support remains unverified.

**A native helper is the more controlled option.** A small signed macOS app could retrieve the frozen request from the paired broker, show its own authoritative review, and use Touch ID to authorize a signature over that decision. It would need a protected key-use operation, not an `authenticated: true` message from JavaScript. A native confirmation sheet could avoid a browser or password-manager detour, but we have not demonstrated that handoff from ChatGPT.

Apple's [Secure Enclave API](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave) supports non-exportable P-256 signing keys. That requires a versioned verifier alongside the current Ed25519 protocol; it is not a drop-in key replacement. The proposed access control combines private-key use with [the current biometric enrollment](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset), which invalidates access when enrolled fingers change. Enrollment, recovery and revocation must account for that.

Use a fresh authentication context for each decision and invalidate it afterward. Apple's [Touch ID reuse setting](https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration) defaults to zero; do not opt into reuse of a recent device unlock. This is a candidate design, not evidence that every signing operation prompts on real hardware. Test context reuse and consecutive requests explicitly.

Apple distinguishes [biometric-only authentication](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometrics) from authentication that permits the macOS account password. Cancellation, unavailable hardware and lockout should end the attempt. Any password alternative needs a separate, explicitly enrolled policy and OS-owned entry; it must not turn into session approval automatically.

The helper must authenticate its broker connection and fetch requests by ID, rather than sign arbitrary caller-provided bytes. Protect its installation, pairing and IPC boundary. Its trusted review must include the actual command, machine, sponsor and output choice. Touch ID proves authentication; it does not prove the person saw the correct command in an agent-controlled card. Code signing or a non-exportable key alone does not settle that problem. A short native review may remain necessary unless the chat host supplies a verified protected review surface.

## Review of the session fallback

The current lab permits a session-only mode selected at startup. Production would need authenticated enrollment and protected policy storage. It remains an explicit weaker option, not recovery for a failed passkey or Touch ID request.

| Boundary | Current evidence |
|---|---|
| Passkey policy cannot be bypassed with the number or session endpoint | P2 rejects missing proofs and mode downgrade. |
| Basic session access checks | S2 rejects anonymous calls, wrong origins, missing CSRF and oversized input. |
| Human consent in session mode | S1 demonstrates that automation controlling the authenticated session can approve. The number and Enter do not distinguish the person from the agent. |
| Accurate review under browser compromise | C1 demonstrates that changing the DOM can mislead the person even when a valid passkey authorizes the server's original request. |

These four existing tests passed again locally in **2.8 seconds** on November 10. S1 and C1 reproduce limitations; passing them does not establish protection. The experiment only creates receipts. It does not test privileged execution or a real ChatGPT signing adapter.

For production session mode, isolate the approval service and its key from the agent, authenticate the approving session, retain request binding and durable one-use consumption, and disclose the remaining browser/session takeover risk. Do not describe it as preventing an agent with control of that session from approving. If that protection is required, an independently protected confirmation mechanism is necessary.

## Manual test record and next checks

The user successfully enrolled a passkey in ChatGPT's browser. The first approval eventually opened the native phone/security-key chooser, without offering the user's 1Password credential there. The page later reported a timeout or disallowed operation and an expired request; no successful receipt was observed. This is a finding about that attempt, not a general claim that 1Password is unsupported.

The retry succeeded: the user reported that it worked with 1Password, and the page showed Approved, a disabled Approved button with Deny hidden, and exactly one test receipt. Output sharing was on. The receipt digest was `2f5dd13cf09c4f6a662559546a4b9556baaa094dec6df9ace0be2da8a1f741d9`. This confirms a real passkey approval in this lab; the user did not specify whether the successful path used the phone QR or the desktop provider, so that transport remains unconfirmed. [1Password documents](https://support.1password.com/ios-autofill/#sign-in-on-another-device) using its iPhone passkey through another device's QR prompt. The phone must have the enrolled credential available. Scanning the authenticator QR is distinct from opening the localhost website on the phone; this trial does not make the lab listener publicly accessible or validate a mobile chat integration.

| Case | Required observation before claiming support |
|---|---|
| Phone QR | User completes the ceremony; server returns Approved and one receipt. Cancellation, expiry and repeat submission create no extra receipt. Record browser, phone and provider. |
| Local passkey with Touch ID | Real enrollment and approval on supported Mac hardware, without a phone; record what verification was actually requested. |
| Native key enforcement | A direct signing attempt without permitted biometric authentication fails. Cancellation, lockout and no enrolled fingerprint produce no signature or receipt. |
| Fresh native approval | Two immediate requests require independent confirmation; an already-unlocked Mac or reused authentication context cannot authorize the second implicitly. |
| Request integrity | Changed command, output choice, machine or sponsor invalidates the proof; replay and concurrent submission create at most one receipt. |
| Enrollment and recovery | Fingerprint changes, key deletion, revoked pairing and account replacement cannot silently restore access or choose session mode. |
| Host isolation | Agent tools cannot replace the review, modify protected policy, extract the key, or obtain a valid approval by forging an IPC result. Test with the actual deployed agent permissions. |

The isolated native probe has now rejected two noninteractive signing attempts and verified two interactive signatures on real Mac hardware. User confirmation of distinct fingerprint prompts is pending. The wider native acceptance cases above remain open: this does not validate production enrollment, recovery, host isolation or privileged execution. No sudo/PAM settings, persistent Keychain items or biometric configuration were changed. Linux would need a separately evaluated authenticator integration; this proposal makes no Linux biometric-support claim.
