# Approval host experiment

Try approval with or without a passkey. Both modes create a test receipt; **neither executes a command, connects to the broker, or produces a broker-compatible signature**. The command shown is a fixed example.

This runs as your ordinary account, listens on loopback, and uses a temporary SQLite ledger. It refuses to start as root. It does not read passwords, Keychain contents, production keys, or system authentication configuration. Automated tests use a fresh browser profile and virtual credentials.

## Try it

Use Node.js 24 or later. From the repository root:

```sh
cd ui
npm ci
cd ../security-lab/approval-host
npm ci
npm start
```

Open the one-use setup link printed in the terminal. Select **Set up test passkey**, complete your authenticator's prompt, and select **New test request**. Enter the displayed number and press Enter or **Approve once**. The result should say that a receipt was created and nothing executed. Try **Deny** on another request.

Keep using the browser/profile where you opened that setup link. A bare localhost URL in another browser has no authenticated session. Controls stay hidden until the session and mode load; an error asks you to use the setup link. Loading the page does not enroll a passkey.

To try the mode without a passkey, stop the process with Ctrl-C and run:

```sh
APPROVAL_MODE=session npm start
```

The mode is fixed at startup. A request cannot switch modes, and cancelling a passkey prompt never falls back to session approval. Five minutes is the experiment's fixed request lifetime; the existing broker's configurable lifetime is unchanged.

The output checkbox remembers its preference in this browser origin and binds the explicit choice to each receipt. A new run normally uses a different port, so that preference need not survive between runs. The lab has no output stream to capture.

Ctrl-C removes the temporary ledger and session. Enrollment is intentionally temporary: a new run needs a new setup link and enrollment. A real passkey created in your authenticator may remain there after the server exits; remove the **sudo-relay experiment** credential from your credential provider when finished. Cancelling enrollment currently requires restarting setup.

This is a local desktop experiment. A phone-width viewport is not a phone test; there is no HTTPS/remote deployment or real ChatGPT adapter here. Do not expose the listener through a public tunnel.

## What the modes mean

| Mode | What authorizes a receipt | Tradeoff |
|---|---|---|
| Passkey (experiment default) | Authenticated lab session, matching number and a verified assertion from the enrolled credential, bound to this request and output choice. | Harder to approve using a stolen browser session alone. Still depends on trustworthy enrollment, browser, review page and authenticator. It does not prove the person saw the right command. |
| Session | Authenticated lab session and matching number. | No separate credential ceremony. Anyone controlling that session or its browser can approve, including automation. The server cannot distinguish that from a human clicking. |

The setup link bootstraps a disposable session; it is **not production login or authenticated installer enrollment**. Anyone who obtains the unused link can claim the session and enroll their own test passkey. Same-origin/CSRF checks restrict ordinary cross-site requests, but do not protect against an agent with access to the setup token, browser session or server process. Localhost is not a human-authentication mechanism.

Passkey support uses [SimpleWebAuthn](https://simplewebauthn.dev/docs/packages/server) for verification, rather than a handwritten signature verifier. Only ES256 registration is requested in this experiment. The broker still uses Ed25519; integrating these is separate work. User verification need not mean a fresh biometric prompt on every platform, and synchronized passkeys need not be confined to one hardware device.

## Run the tests

From this directory:

```sh
npm run check
npx playwright install chromium
npm test
```

Playwright opens isolated Chromium profiles. Where the browser cache is restricted, set `PLAYWRIGHT_BROWSERS_PATH` to a writable temporary directory for both installation and testing. Browser startup may also require permission to run outside a restricted process sandbox; it still runs as your ordinary account.

The suite also builds the UI and runs four [desktop probe](../mcp-host-probe/README.md) card checks through a synthetic MCP Apps bridge: Enter/Approved, denial, invalid metadata and server rejection. These are separate from the passkey/session cases below and do not test the actual ChatGPT host.

| Case | What it checks | What it does not establish |
|---|---|---|
| G1 | A fresh browser without the setup session shows an error and no enrollment/request controls. | Production account login or cross-browser session sharing. |
| G2 | Controls remain hidden while authenticated mode is loading; passkey setup appears afterward with no enrolled credential. | Every network or client failure mode. |
| G3 | With authenticator presence held back, the page explicitly says it is waiting and creates no receipt; after reload, a completed ceremony succeeds. | Visibility or behavior of a real password manager's prompt. |
| P1 | Valid passkey flow, Enter, Approved state, hidden Deny button, remembered output choice. | Physical human presence or real device behavior. |
| P2 | Correct number alone, missing assertion and attempted mode downgrade fail. | Every possible client bypass. |
| P3 | Changing output choice or request ID, or injecting a replacement command, fails; original proof succeeds. | Mutations of every stored request field or mutable command dependencies. |
| P4 | Changed signature, origin, challenge, RP hash, credential ID and cross-origin context fail; original succeeds. | Independent cryptographic library audit. Mutated signed fields also invalidate their signature. |
| P5 | Eight concurrent submissions and later replay yield exactly one receipt. | Multiple server processes, disk faults or power loss. |
| P6 | Starting another ceremony invalidates the previous challenge. | All browser/reconnection interleavings. |
| P7 | Expiry after assertion creation blocks consumption. | Clock rollback. |
| P8 | Denial is terminal, renders Denied, hides Approve, and old proofs cannot authorize a fresh request. | All cancellation races. |
| P9 | Three wrong numbers end the request. | Denial-of-service resistance. |
| P10 (two cases) | Authenticator responses lacking user-verification or user-presence flags fail, followed by successful controls. | Hardware attestation or fresh biometric gestures. |
| C1 — limitation | Changing the review DOM can display misleading text while the valid assertion authorizes the server's original decision. | This intentionally demonstrates a missing protection when the review browser is compromised. |
| S1 — limitation | An automated API call using the authenticated session approves without a human; replay still fails. | This intentionally demonstrates session mode's weaker consent guarantee. |
| S2 | Anonymous, wrong-origin, missing-CSRF and oversized requests fail; a valid call still works. | Protection from a process able to forge headers and obtain session credentials. |
| S3 | Enter, preference persistence and no horizontal overflow at 390px. | Actual phone, screen-reader or ChatGPT support. |
| R1 | Reopening a ledger preserves receipts, cancels pending work and invalidates old session credentials. | Crash/power-loss durability or rollback resistance. |

C1 and S1 are characterization tests: their passing result means the limitation was reproduced. They are not security successes. These findings apply to this lab, not a claim that ChatGPT's real approval mechanisms have been bypassed.

## Verification record

November 10, 2026: all **16 cases passed in 7.2 seconds** on local macOS arm64, Node 24.16.0, Playwright 1.65.0 and Chromium 158.0.8127.18. Strict TypeScript checking passed. The new package's `npm audit` reported zero known vulnerabilities after replacing the initially selected Zod version; this is not a dependency audit of the entire repository. Browser tests needed to run outside the process sandbox because macOS denied Chromium's bootstrap IPC.

Later that day, a reported button flip was reproduced when session loading failed or remained pending: the old page hid enrollment but left the disabled request button visible. G1/G2 failed against that behavior, then all **18 cases passed in 8.8 seconds** after hiding the controls until authenticated state is available. Strict TypeScript checking and all five [CI jobs for the fix](https://github.com/brandonscript/sudo-relay/actions/runs/42870441789) passed. The original report was traced to opening the bare lab URL in ChatGPT's in-app browser while the setup session existed in Chrome. The in-app browser showed the missing-session error; no automatic enrollment was observed. A fresh setup session opened directly in the in-app browser correctly displayed enabled passkey setup and a disabled request button.

Manual enrollment subsequently succeeded in ChatGPT's in-app browser, confirmed by the user and the page's enrollment result. The first approval attempt looked finished to the user, but the page still showed disabled pending controls and an accessibility notice that 1Password sign-in options were available. No receipt or Approved state was observed. G3 reproduced the missing waiting feedback with a virtual authenticator. After adding explicit waiting/verification messages, all **19 cases passed in 8.4 seconds**, with strict type checking. The fix does not establish why the real prompt was initially not visible to the user. A subsequent retry succeeded with 1Password according to the user; the page independently showed Approved and exactly one test receipt, with output sharing on. The successful phone-versus-desktop provider path was not specified. This local browser test is not MCP card integration.

All five [GitHub CI jobs](https://github.com/brandonscript/sudo-relay/actions/runs/42868522346) passed for commit `0becec2`, including the new Linux browser job and the existing Linux/macOS checks and privileged broker fixtures. The approval experiment itself launched no command. The pre-existing privileged jobs are separate broker tests on disposable hosted runners, not a passkey-to-root integration. Real passkey approval completion was subsequently observed as recorded above. MCP handoff, mobile chat use, production enrollment and the native sudo path remain unverified here.

The [design document](../../docs/chat-approval-design.md) describes how these findings affect implementation. Passkeys remain optional; claims about protection must match the selected mode.

The [Touch ID and fallback review](../../docs/biometric-approval.md) records the subsequent native-chooser timeout, the phone retry, candidate macOS integration, and planned hardware tests. P2, C1, S1 and S2 were rerun on November 10: all four passed in 2.8 seconds, including the two documented limitation cases. All five [CI jobs for the waiting-feedback change](https://github.com/brandonscript/sudo-relay/actions/runs/42872087585) also passed. A separate [native receipt-only lab](../touch-id/README.md) subsequently verified real Touch ID signing, cancellation and expiry rejection. Integration of that native reviewer with this browser lab or the production broker remains unimplemented.
