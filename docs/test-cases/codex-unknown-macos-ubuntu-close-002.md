# Deny after remote cancellation

Case ID `codex-unknown-macos-ubuntu-close-002`

## Prerequisites

Use the [Touch ID setup guide](../../preview/README.md) to prepare a paired Ubuntu VM and a verified signed reviewer on a Touch ID Mac. Install the reviewer in the ordinary approving account, and restart the Codex MCP connection after any replacement. Record both OS versions, architectures, the full Codex version, source revision, and reviewer hash. The historical client major version is unrecorded.

## Procedure

1. Request `/usr/bin/id -u` through Codex and leave the native review open. Record its request ID.
2. Cancel that request through `cancel_execution` and confirm `execution_status` reports `cancelled` with a null outcome.
3. Click Deny in the native review. Record whether any additional dialog appears.
4. Read `execution_status` again for the same ID and compare it with the expected result below.

## Expected result

Window closes quietly, request stays cancelled, and execution outcome is null.

## Cleanup

Cancel any request left pending, dismiss remaining review windows, and check its final status. If this was a temporary installation, follow [Revoke, inspect and remove](../../preview/README.md#revoke-inspect-and-remove). Preserve the evidence before removing the VM.

## Recorded results

✅ A passing historical run is documented in the [evidence report](../native-quiet-close.md#november-18-live-result). That report retains its original scope and failure history. This runbook was written from the existing case and source; it has not been rerun as part of this documentation change. Missing historical version or artifact metadata remains unrecorded.

For a new result, record the date, result, exact software/client/OS versions, architectures, source revision, relevant artifact hashes, command output, and cleanup outcome. Include sanitized request IDs and audit counts where applicable. Link that evidence here and update the tables when reviewed. See the [registry](../verification-cases.md#recording-a-run-or-vulnerability) for reporting guidance.
