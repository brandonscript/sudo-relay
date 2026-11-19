# Revoke and remove

Case ID `vm-ubuntu-lifecycle-003`

## Prerequisites

Use a dedicated Ubuntu 24.04 VM with systemd, a trusted administrator connection, and a recorded source revision. Follow the [preview prerequisites](../../preview/README.md#what-you-need). These steps install, restart, revoke, or remove privileged services inside that VM. Keep its administrator recovery connection available.

## Procedure

1. Use a dedicated installed Ubuntu VM, retain its baseline sudo/PAM hashes, and verify an approved request succeeds before testing revocation.
2. Follow [Revoke, inspect and remove](../../preview/README.md#revoke-inspect-and-remove) to revoke the approving key. Attempt a fresh request/approval with the revoked key and verify there is no launch.
3. For the sponsor-policy variant, use the VM administrator to remove the sponsor's sudo permission, then attempt execution through that enrollment. Verify it fails. Restore access through the VM administrator before removal, and record the policy changes.
4. Follow the removal guide on Linux and, if installed, on the Mac. Check relay services, role accounts, and per-sponsor files against the expected result. Shared binaries may remain if another sponsor is installed.
5. Compare stock sudo/PAM files with the original hashes and verify ordinary sudo still works for an authorized account. Record retained Keychain and original transport keys separately from removed service files.

## Expected result

Revocation prevents execution. Removal cleans relay state/services/accounts/policy, original files match, and ordinary sudo works.

## Cleanup

Follow [Revoke, inspect and remove](../../preview/README.md#revoke-inspect-and-remove) for any remaining installation. Preserve baseline comparisons and cleanup output. The Mac removal retains its Keychain approval key and original transport keys; the guide describes their separate handling.

## Recorded results

✅ A passing historical run is documented in the [evidence report](../developer-preview-milestone.md). That report retains its original scope and failure history. This runbook was written from the existing case and source; it has not been rerun as part of this documentation change. Missing historical version or artifact metadata remains unrecorded.

For a new result, record the date, result, exact software/client/OS versions, architectures, source revision, relevant artifact hashes, command output, and cleanup outcome. Include sanitized request IDs and audit counts where applicable. Link that evidence here and update the tables when reviewed. See the [registry](../verification-cases.md#recording-a-run-or-vulnerability) for reporting guidance.
