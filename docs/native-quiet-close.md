# Quietly closing a stale native review

The November 14 inline-display test cancelled its request through MCP while the
native review window was open. Closing that window sent another cancellation.
The native bridge required a pending request before handling any operation, so
it rejected the already-cancelled request and showed a misleading error dialog.

The native bridge now handles close separately from approval preparation. A
pinned, authenticated status confirming the same execution request is cancelled
or expired permits a quiet close. A pending request gets one cancellation attempt.
If that attempt fails, one read-only status check can confirm cancellation or
expiry; otherwise the original error remains visible. There is no second write,
approval attempt, signing operation or execution retry. Broker policy is unchanged.

Both the title-bar close button and Deny return the native panel's cancellation
result and reach this path. Fetch and approval still require a valid pending,
unexpired request. Receipt responses, other request IDs, running/consumed/complete
states and unresolved transport errors do not become successful cancellations.
Execution error notices no longer reuse receipt-test titles or claim that nothing
can execute. Unconfirmed approvals still warn that the command may have run.

## Automated regression checks

Run from the repository root:

```sh
cargo test --locked --lib --features native-execution-lab native_execution::tests
cargo clippy --locked --lib --features native-execution-lab -- -D warnings
cargo fmt --check
swift test --package-path security-lab/touch-id
```

- Already cancelled or expired: one status read, quiet success, no decision write.
- The same terminal states still reject fetch and approval.
- Pending request: exactly one cancellation, matching acknowledgement required.
- Cancellation/expiry races: failed cancellation followed by matching terminal
  status closes quietly, without retrying the cancellation.
- Wrong ID, receipt status, pending/running/consumed/complete state, unavailable
  status or invalid acknowledgement: error remains; no approval or execution call.
- Existing approval-signature binding and lost-acknowledgement tests still pass.
- Swift notice tests preserve visible unexpected failures and uncertain-execution
  warnings while retaining quiet expiry and deliberate Touch ID cancellation.

## Astra acceptance after signing

Use the disposable Linux target and existing protected key. No host sudo/PAM
changes or new key enrollment are needed. Install only a verified signed build.

1. Open a pending native review, cancel its request through MCP, then click its
   title-bar close button. Expect no extra dialog; status remains cancelled and
   outcome is null. Repeat using Deny instead of the close button.
2. Leave a fresh review until expiry, then use Close or the title-bar close button.
   Expect no Touch ID prompt or extra dialog; status remains expired, no outcome.
3. Close a still-pending review normally. Expect one cancellation and no dialog.
4. Keep genuine transport failures and unconfirmed approval errors visible.
   Automated injected-error checks cover these without disrupting the live host
   or requesting another execution.

Software tests do not prove AppKit button behavior or protected hardware behavior.
The signed native build must be tested on Astra before this fix is called deployed.

## November 14 results

The two new stale-close/race regressions failed against the original implementation
with `not pending execution`, then passed after the fix. All eight native Rust
tests and 16 Swift tests pass; Rust formatting and clippy with warnings denied
also pass. The complete native execution app compiled successfully for the
signing kit. Existing signature binding, expiry, replay and uncertain-approval
checks remain green. No interactive authentication or command execution was
requested by these tests.

The returned signed app was verified against that exact build: strict Apple/team/
bundle signature, exact entitlements without debugging access, matching resources
and provisioning profile, and normalized executable correspondence all pass.
Binary SHA-256:
`bfdc13b594be1739c7182035b1e8f7570fbc3f427843c190447e3ed46a429e77`.
Administrator replacement is prepared for the ordinary approving account; it
checks the previous installed executable before removing only that target's Mac
files. No new Keychain enrollment or Linux policy change is involved.

User-run replacement succeeded and read-back matched the corrected executable
digest. The first live checks did not establish quiet-close: the MCP adapter had
not been restarted and still listened on its old local port (60857), while the new
enrollment referenced port 62790. Native fetch failed before showing the review.
The repeat request remained pending and was explicitly cancelled, with no outcome.
Installation instructions now require stopping/restarting the MCP connection around
replacement. Live close/Deny/expiry checks remain pending after client refresh.

## November 18 live result

After profile renewal, reviewer replacement, and Codex restart, the native review
opened on Astra. MCP cancellation of request `aa286d5e-106b-4731-8ffc-228bdd372cf8`
returned state `cancelled` with a null execution outcome. The user clicked the
red title-bar close button and confirmed the window closed without another dialog.
Deny after remote cancellation also closed without another dialog (request
`28cf3b1d-64e5-4758-8f10-31ce219c0fa0`, state `cancelled`, null execution
outcome). The red X also closed a still-pending review quietly and cancelled
request `31a4ded0-d3d4-4fd0-912f-3c0bec88130f`, with a null execution outcome.
After idle expiry, the user clicked Close and confirmed the review dismissed
without another dialog. Request `acc1944b-4e92-4a27-bb34-9404bf6e01bb` was
`expired` with a null execution outcome. All four live quiet-close checks passed.
