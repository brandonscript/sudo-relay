# Touch ID signing experiment

Try two native approvals on a Mac with Touch ID. **Nothing executes.** This program has no network listener, broker connection, sudo integration or password field. Its signatures cannot authorize sudo-relay commands.

The question is narrow: can we sign each test request with a biometric-protected Secure Enclave key, while rejecting a signing attempt that cannot show an authentication prompt? A successful run still needs the person to report whether each request actually asked for Touch ID.

## Run

Requires macOS 13 or later, Swift 6, a supported Secure Enclave and enrolled Touch ID. From this directory:

```sh
swift test
swift run touch-id-probe --check
swift run touch-id-probe --run
```

`--check` only queries capability. It creates no key and requests no authentication. Missing hardware or enrollment is a test limitation; do not add a fingerprint just for this experiment.

`--run` shows the complete, fixed JSON request in a native dialog. Choose **Sign test request** yourself, then complete any Touch ID prompt. A second dialog tests a second request immediately afterward. Use **Cancel** to stop. Report whether both requests prompted, whether any password alternative appeared, and the final result. Do not put a password or recovery code into chat.

The first accepted dialog creates a new P-256 key protected by `privateKeyUsage` and `biometryCurrentSet`. Only its encrypted Secure Enclave representation is kept in process memory; the program does not save it or add a persistent Keychain item. It never loads existing keys or fingerprints. Exiting discards its references. No installation or removal step is needed.

For each request, the program first attempts signing with interaction forbidden, then signs with a fresh authentication context with device-unlock reuse disabled. It invalidates each context afterward. If noninteractive signing succeeds, it stops and reports failure. An error alone does not prove that biometrics enforced the boundary: a successful interactive signature is the required positive control.

The program never calls a general authentication success callback and treats that as approval. The signature operation itself is protected. It verifies the result against the displayed bytes and rejects expired requests. A failed attempt ends the experiment rather than switching to passkeys, a password or session mode.

## Checks and limits

| Case | Evidence |
|---|---|
| T1: request binding | Automated software-key test accepts the original, rejects a new request ID, a wrong public key, and changed command, machine and output choice. |
| T2: expiry | Automated software-key test accepts just before expiry and rejects at expiry. |
| T3: no-interaction signing | Manual hardware run must return no signature with interaction forbidden, then succeed interactively. Repeated before each of two approvals. |
| T4: fresh confirmation | Person must observe independent confirmation for both successive requests. A successful signature alone cannot establish a fresh fingerprint gesture. |
| T5: cancellation and unavailable biometrics | Cancel the review or OS prompt; no successful result for that request, no fallback and no later request. Also test a machine without available Touch ID. |
| T6: error-log minimization | Automated test ensures authentication errors report only domain and code, omitting descriptions and metadata. |

Automated tests use disposable software keys, not the Secure Enclave. They do not test hardware access controls. `swift test` builds the executable but never runs the interactive experiment. CI runs these tests on macOS without enrolling credentials.

November 10, 2026: the two initial automated tests passed on local macOS arm64 with Swift 6.4.2. The capability query initially failed to reach the authentication service inside the process sandbox (`NSCocoaErrorDomain 4099`); outside that sandbox it reported Secure Enclave, biometric authentication and Touch ID all available. No key is created by that query.

The first real run completed with exit 0: both noninteractive signing attempts were rejected with `com.apple.LocalAuthentication -1004`, and both interactive signatures verified. Nothing executed. The user confirmed that both requests separately prompted for Touch ID and that they approved both successfully. This is observed behavior for this run, not a guarantee for every hardware/OS configuration. The original diagnostic output included unnecessary OS authentication metadata. Error reporting was subsequently restricted to domain and code, with T6 added to prevent that metadata from entering future logs. All three automated tests then passed with compiler warnings treated as errors. Cancellation was subsequently tested in the native review flow below. Lockout and changed enrollment remain untested.

This is a local, development executable with no production signing identity, protected installation or trusted IPC boundary. Its review and verifier are in the same ordinary-user process; it does not establish resistance to code replacement, injection or agent control of the host. The lab format is sorted JSON, not the broker's CBOR protocol. It has no durable consumption ledger, enrollment or recovery implementation and makes no at-most-once execution claim. Existing broker/passkey replay tests remain separate evidence.

Do not change fingerprint enrollment or Keychain configuration to test invalidation on a personal machine. Those recovery tests belong on a dedicated device. The [design review](../../docs/biometric-approval.md) lists remaining production requirements and the session fallback's weaker consent guarantee.

If a restricted development shell cannot write compiler caches, use temporary cache paths:

```sh
CLANG_MODULE_CACHE_PATH=/private/tmp/sudo-relay-swift-modules \
SWIFT_MODULECACHE_PATH=/private/tmp/sudo-relay-swift-modules \
swift test --disable-sandbox \
  --cache-path /private/tmp/sudo-relay-swift-cache \
  --scratch-path /private/tmp/sudo-relay-touch-id-build
```

This disables SwiftPM's manifest sandbox for this local package; it does not change system authentication. Run the resulting `.build/debug/touch-id-probe` (or the scratch directory's `debug/touch-id-probe`) with `--check` or `--run`.

## Authenticated native review trial

`touch-id-probe --review-boundary` adds a receipt-only authority → native review → signature → verification flow. Review data is authority-authenticated before display; the complete request and selected output choice are bound to the signature. The verifier uses its own request/key and accepts one receipt. The [design, test cases and manual runbook](../../docs/native-review-boundary.md) separate what this tests from the missing protected deployment. No command runs, and the existing inline probe is unchanged.

Seven new automated cases cover native layout/command rendering, authority forgery, misleading input, request/choice/mode substitution, wrong keys, concurrent replay, cross-enrollment reuse, denial and late signatures. Together with the three original native checks, ten tests passed locally. Software-key tests do not exercise biometrics. After correcting layout and async lifecycle issues, both the participant screenshot and process output confirmed a real native review/Touch ID receipt with replay rejected; see the runbook for evidence and remaining negative hardware checks. The simplified Touch ID review no longer requires number entry; technical data is available under Details.

The new native flow closes after successful verification or denial. It does not add a success dialog; the process records receipt evidence. The original `--run` two-trial experiment retains its final researcher notice. Cancelling the OS fingerprint prompt also closes quietly, with zero receipts and a cancellation result in the log. Other errors remain visible and never trigger a fallback. A focused cancellation-classification test brings the native suite to eleven passing tests; the participant also confirmed the revised cancellation behavior on hardware.

After approval expires, Approve is disabled and Deny becomes Close. Closing an expired review logs expiry rather than denial. The participant verified the disabled approval controls after a real five-minute wait; the Close label has automated coverage and awaits a fresh visual check.
