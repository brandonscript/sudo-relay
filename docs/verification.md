# Verification record

Local verification on November 9, 2026. This is implementation evidence, not an independent security audit.

## Initial verification

- macOS: Rust formatting, Clippy with warnings denied, 19 non-privileged Rust tests, strict TypeScript checks including the end-to-end harness, eight TypeScript tests, and UI build.
- Real stdio MCP integration: initialize, list exactly three non-approval tools, read the inline resource, create a request, reconstruct CBOR in TypeScript, sign with a throwaway Ed25519 key, consume once, return output, reject replay, and reject approval after cancellation.
- Disposable Linux Docker container: non-root Rust suite and real root broker. Separate UIDs exercised request/approval roles, denied foreign peers and agent approval, verified private state and a separate approving UID’s private signing-key file cannot be read or modified by the requesting client, executed a signed harmless command as root, and rejected replay.
- Browser: reference host at desktop and 390 × 844 viewport. Complete JSON request rendered as text; wrong number left the button disabled; reviewed matching number enabled it; one development-only approval returned success. No host root execution occurred. The temporary viewport override was reset.
- macOS launchd property list passes `plutil -lint`.

## Review corrections

A bounded Ponytail review found and fixed:

- A writable symlink path could initially resolve to a trusted executable and later switch to another one. Production now checks the original path's ancestors too; argv executable resolution is frozen before display and signing. Regression tests cover frozen resolution and the production protected-path rejection.
- Escaped stdout/stderr could exceed the response limit. The bounded client response limit now accommodates the worst-case JSON encoding of both streams, and framing uses buffered reads with a wall-clock deadline.
- Cancel/request loops could grow the root ledger indefinitely. New requests stop at 10,000 stored records, with administrator rotation documented.
- Splitting UTF-8 across socket chunks could corrupt a pending request. The TypeScript client now decodes incrementally.
- A second process could recover the first broker's live state. The state store is locked before startup recovery. Lock teardown explicitly unlocks before closing, so a concurrent fork inheriting the descriptor cannot cause a spurious restart lock failure.

The documentation pass compared the owner's Shrinx/fixm4b README structure with this README, checked implemented CLI forms and service paths, separated installation from protocol internals, and removed claims of generic client support. Examples requiring administrative installation remain instructions rather than actions performed on the host.

## Not verified at initial review

No privileged installation on the user's Mac, systemd/launchd service lifecycle test, real mobile device, existing commercial chat-client adapter, release workflow execution, artifact signing, or public publication. The CI matrix schedules Linux and macOS checks including disposable root tests, but a local workflow file is not evidence that hosted CI ran.

The approving host/browser must remain outside agent process and computer-control access. The reference same-user demo does not provide that isolation. Independent review and a verified production host integration remain prerequisites for release artifacts.

## Approval window and presentation follow-up

Added backward-compatible `approval_ttl_secs` configuration (300 seconds by default, 1–86,400 seconds allowed). Tests cover custom windows, defaulting old configurations, invalid limits, timestamp overflow, signed-expiry tampering, and rejection exactly at expiry. Existing request/tool schemas and CBOR layouts are unchanged.

Readable command presentation uses POSIX display quoting, with exact argument JSON available to expand. A round-trip shell test verifies spaces, empty strings, quotes, literal pipe characters, substitution syntax, backslashes, and Unicode remain separate literal arguments. The shell is used only by that test; production argv execution is unchanged. Signed expiry drives the visible remaining time. A single numeric input paints two digit slots without adding a second focus target.

The inline concept was updated to mirror these controls, including a preview-only approval-window selector. These visual changes have not been inspected inside a live ChatGPT host.

## Confirmation simplification

Removed the review checkbox and its SDK/host acknowledgement parameter. Approval still requires the matching number, explicit button click in the trusted host, correct machine, valid expiry, and signature verification; the broker wire protocol and signed envelope are unchanged. Updated the SDK callers, reference host decision validation, integration harness, and signing tests together.

Removed the command JSON disclosure; POSIX display quoting and wrapping remain. Moved the agent explanation above the command. The inline concept includes a relative-path example with always-visible working directory, plus a long-command example. Production still rejects relative executable paths and uses fixed cwd `/`; no relative execution capability or unsigned cwd field was introduced.

## Live replay and completed actions

A fresh development request was explicitly approved by the user in the reference host. A test-only Unix-socket proxy captured the exact signed approval bytes. Replaying those bytes three times returned `request is not pending` each time. The persistent audit contained exactly one `running` event for that request. Resubmitting the identical command produced a new pending request; changing the old approval's ID to the new ID failed signature verification. The new request was cancelled without execution.

Browser inspection confirmed the successful action remained as a disabled **Approved** button and the **Deny** button disappeared. Two DOM tests cover the matching **Denied** state, errors leaving actions available, and stale request responses being ignored. Labels change only after a successful host acknowledgement. The live test ran as the ordinary user, not root; no installed ChatGPT integration was exercised.

## Baseline review fixes

The reference HTTP host no longer loads a key or signs approvals; all approval submissions return HTTP 403. Production configuration rejects equal agent/approver UIDs. Added regressions cover both boundaries. Rust: 20 tests passed, two privileged helpers ignored. TypeScript: 10 tests passed; strict checks and UI build passed. No privileged integration test or production signer attestation was performed. Earlier live reference-host approval demonstrations describe the previous implementation.

## Disposable fixture integrity and secrecy checks

Ran five standard-library tests against the production-mode Linux broker as agent UID 10001: unapproved request stays pending, protected-file reads fail, protected-file write opens fail, matching-number self-approval fails at the peer-identity check, and cancellation leaves no execution. All five passed in 0.635 seconds. No private file contents were read, no approval was signed, and no command was launched by the broker. The container was removed afterward. Full cases and exclusions are recorded in `security-lab/test-cases.md`.

## Approved-command replay and substitution

Ran the seven Docker fixture tests successfully: five existing agent tests (0.766 seconds) and two new replay/substitution tests (1.816 seconds). Each new case first verified a successful disposable signed execution and exactly one audit launch. Three exact replays were rejected; approval transplantation to a new identical-command request and to a different-script request failed signature verification, with zero launches for the new requests. Fixture signing and approval submission ran under UID 10002; command requests ran under UID 10001. The container and its ephemeral credentials were removed afterward. No production signing capability was enabled.

## Command substitution with the same request identity

Added `test_same_request_cannot_substitute_command`. A valid approval for `/usr/bin/printf approved` rejects an injected replacement `spec`. Test signatures over payloads changing only the executable or only its argument fail signature verification, while the request ID, nonce, number and other envelope fields stay fixed. Each rejection leaves zero launches and pending status. The original approval remains usable and prints exactly `approved` with one launch. All eight fixture tests passed: five agent checks in 0.579 seconds and three replay/substitution checks in 1.911 seconds. Disposable runtime removed afterward; production signing unchanged. This does not test changes to executable files or external dependencies after approval.

## Per-request output sharing

Added a default-off output-sharing checkbox. The reference parent remembers the last human choice in browser local storage, with off as the fresh-host fallback when storage is unavailable. An agent's signed `output_needed` hint is advisory and never disables the choice. Production signing is still absent from the preview host.

Protocol version 2 signs the complete frozen request plus a mandatory sharing boolean. The broker commits the choice with consumption. Off drains/discards stdout and stderr; the broker also strips stream data and raw diagnostics before caching results. Status retains exit code and execution flags. Sharing on retains the existing bounded, memory-only output behavior. Older ledgers migrate to withholding; version 1 signatures are rejected. Update broker and adapters together.

Final verification:

- Rust: 25 tests passed (23 security tests, two transport tests); two privileged helpers remained ignored. Includes changed/missing consent, changed output-needed hint, both choices across both agent hints, executor discard, diagnostic redaction, restart and legacy-ledger migration. Shared Rust/TypeScript vectors cover both signed choices.
- TypeScript: 14 tests passed; strict checks and build passed. Includes checkbox on/off, default/saved choice, advisory hint, denial, malformed consent, signed bit changes, and reference-host persistence across reloads. Wrong-source and malformed preference changes are ignored; denied storage defaults off. Model-supplied sharing fields do not set the checkbox preference.
- Docker: all eleven cases passed, five agent checks in 0.634 seconds and six replay/output cases in 4.426 seconds. A fake root-only secret was emitted to both streams with exit code 7 across all four hint/consent combinations. Only approved sharing disclosed it; repeat reads and later opt-in did not disclose earlier withheld output. Ledger contained no output. Containers and throwaway runtime keys were removed.
- Real MCP stdio integration passed three consecutive runs, including output-needed execution approved without sharing and a completed MCP status containing no private stream markers.
- Rust formatting, Clippy with warnings denied, strict TypeScript checks and UI build passed. Reviewed connected protocol, execution, preference and test callers; documentation updated for the final behavior and version change.

Integration exposed a macOS Unix-socket race: changing a read timeout after peer close can fail with EINVAL even when a complete reply is buffered. The new buffered-peer-disconnect regression failed before the fix and passes afterward. Reads now wait for readiness with poll against the same absolute deadline rather than changing socket timeouts repeatedly. A disconnected client can no longer terminate the server through its initial timeout setup; that setup is handled per connection. Existing size/deadline framing tests also pass.

Not verified: macOS privileged deployment, a production trusted human UI/signing integration, real-browser visual/accessibility review of the new checkbox, memory scraping, or external exfiltration by approved root code. This sharing control governs the broker response, not arbitrary root-code behavior. The older adversarial harness was updated for the signed-decision API but remains historical and was not rerun.

## sudo-relay source alpha

The project is now named `sudo-relay`. Renamed the Rust package/imports, private TypeScript package, MCP resource/name, service paths, documentation, and signing domains together. Regenerated the shared CBOR fixture. Pre-alpha signatures use the old domain and are not compatible; update broker and adapter together and create fresh requests.

After the rename, all 25 non-privileged Rust tests, 14 TypeScript tests, strict type checks, formatting, Clippy, UI build and the real MCP stdio integration passed locally. All eleven disposable Linux fixture tests passed (five agent checks, six replay/output checks); the container and throwaway runtime credentials were removed. The launchd plist passes syntax validation. No privileged commands were tested on the personal Mac.

The rename review traced the protocol domains through both encoders, shared vectors, integration resource URI and fixture signer, and checked service paths against installation/removal instructions. The documentation pass removed naming placeholders and retained the alpha limitations. Private vulnerability reporting was enabled and read back as enabled for `brandonscript/sudo-relay` before pushing source.

Preliminary naming checks found an unrelated three-file JavaScript/Gun relay at `rip-monkey-nko/sudo-relay`. The chosen owner/repository path was available. npm returned no package at the exact name; the crates.io lookup was blocked (HTTP 403). These checks are not trademark clearance. No registry packages or signed release artifacts are being published.

Hosted checks exposed three test-fixture assumptions, now corrected: unprivileged peers could not traverse the runner's private checkout, clearing groups after setting GID left the macOS peer in group 0, and root's macOS temporary directory was private rather than world-writable. The fixture now copies its helper into its root-owned test directory, sets groups before dropping UID and asserts the resulting GID, and creates an explicitly writable ancestor for the symlink case. No broker authorization or socket permissions were relaxed. CI requires exactly one root test executable and lets both OS jobs finish independently.

Both privileged jobs passed on [GitHub-hosted Linux and macOS runners](https://github.com/brandonscript/sudo-relay/actions/runs/42763629898) at commit `d843894`. Both normal jobs also passed formatting, Clippy, Rust tests, TypeScript checks/tests/build and MCP integration; all four jobs finished successfully. The privileged jobs exercise a real root broker, separate peer identities, protected-key access, signed execution, replay rejection and unsafe-path rejection. They do not install systemd/launchd services, verify macOS ACL handling, or supply a production human approval/signing integration. The source alpha is public; registry packages and signed release artifacts remain unpublished.
