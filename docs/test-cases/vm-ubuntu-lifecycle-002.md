# Restart and replay

Case ID `vm-ubuntu-lifecycle-002`

## Prerequisites

Use a dedicated Ubuntu 24.04 VM with systemd, a trusted administrator connection, and a recorded source revision. Follow the [preview prerequisites](../../preview/README.md#what-you-need). These steps install, restart, revoke, or remove privileged services inside that VM. Keep its administrator recovery connection available.

## Procedure

1. Use a dedicated installed Ubuntu VM and paired reviewer. Complete one approved `/usr/bin/id -u` request and retain its exact signed approval in the test harness. Record the request ID, outcome, and audit launch count.
2. Replay that approval through the configured approver channel. Confirm it is rejected and the launch count does not increase.
3. Restart the broker service identified by the installed enrollment. Reconnect MCP and query `execution_status` for the completed request.
4. Submit the same retained approval again through the approver channel. Confirm rejection and an unchanged launch count. Compare the recovered state and outcome with the expected result below.
5. The existing [installed VM driver](../../preview/check_vm.py) automates this sequence with a temporary software signer. It takes the enrollment path and the decision-payload helper path as its two arguments, pairs a temporary key, restarts the service, and revokes that key afterward. Use it only in a dedicated VM prepared for software-signer checks; preserve its output as evidence. Protected Mac approval remains a separate case.

## Expected result

Completed/consumed state survives, replay fails, and transient output is unavailable.

## Cleanup

Follow [Revoke, inspect and remove](../../preview/README.md#revoke-inspect-and-remove) for any remaining installation. Preserve baseline comparisons and cleanup output. The Mac removal retains its Keychain approval key and original transport keys; the guide describes their separate handling.

## Recorded results

✅ A passing historical run is documented in the [evidence report](../developer-preview-milestone.md). That report retains its original scope and failure history. This runbook was written from the existing case and source; it has not been rerun as part of this documentation change. Missing historical version or artifact metadata remains unrecorded.

For a new result, record the date, result, exact software/client/OS versions, architectures, source revision, relevant artifact hashes, command output, and cleanup outcome. Include sanitized request IDs and audit counts where applicable. Link that evidence here and update the tables when reviewed. See the [registry](../verification-cases.md#recording-a-run-or-vulnerability) for reporting guidance.
