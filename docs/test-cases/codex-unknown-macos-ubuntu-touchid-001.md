# Approve once

Case ID `codex-unknown-macos-ubuntu-touchid-001`

## Prerequisites

Use the [Touch ID setup guide](../../preview/README.md) to prepare a paired Ubuntu VM and a verified signed reviewer on a Touch ID Mac. Install the reviewer in the ordinary approving account, and restart the Codex MCP connection after any replacement. Record both OS versions, architectures, the full Codex version, source revision, and reviewer hash. The historical client major version is unrecorded.

## Procedure

1. Open Codex with the installed MCP connection enabled. Ask it to request `/usr/bin/id -u` on the paired Ubuntu VM. Record the returned request ID.
2. Compare the host, account, and command in the protected native window with the intended target. Enable output sharing and approve with Touch ID yourself before expiry.
3. Ask Codex to call `execution_status` for that same request. Save the sanitized response.
4. Through the VM administrator connection, inspect the protected audit for that request. Count consumption and launch transitions and compare them with the expected result below.

## Expected result

Status is complete, exit code is 0, stdout is `0\n`, and the audit records exactly one consumption and launch.

## Cleanup

Cancel any request left pending, dismiss remaining review windows, and check its final status. If this was a temporary installation, follow [Revoke, inspect and remove](../../preview/README.md#revoke-inspect-and-remove). Preserve the evidence before removing the VM.

## Recorded results

✅ A passing historical run is documented in the [evidence report](../developer-preview-milestone.md#human-approved-actual-mcp-execution--november-13). That report retains its original scope and failure history. This runbook was written from the existing case and source; it has not been rerun as part of this documentation change. Missing historical version or artifact metadata remains unrecorded.

For a new result, record the date, result, exact software/client/OS versions, architectures, source revision, relevant artifact hashes, command output, and cleanup outcome. Include sanitized request IDs and audit counts where applicable. Link that evidence here and update the tables when reviewed. See the [registry](../verification-cases.md#recording-a-run-or-vulnerability) for reporting guidance.
