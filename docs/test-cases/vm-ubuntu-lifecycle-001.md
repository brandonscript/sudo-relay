# Install and identify sponsor

Case ID `vm-ubuntu-lifecycle-001`

## Prerequisites

Use a dedicated Ubuntu 24.04 VM with systemd, a trusted administrator connection, and a recorded source revision. Follow the [preview prerequisites](../../preview/README.md#what-you-need). These steps install, restart, revoke, or remove privileged services inside that VM. Keep its administrator recovery connection available.

## Procedure

1. Start a fresh Ubuntu 24.04 VM with systemd and an existing sudo-enabled account. Record its OS release, architecture, source revision, sponsor UID, and baseline hashes of the stock sudo/PAM files described by the installer.
2. Follow [Build and install on Linux](../../preview/README.md#build-and-install-on-linux) as that account. Preserve the installer output and protected enrollment information.
3. Compare the recorded sponsor with the account that actually invoked sudo. Confirm the separate agent and reviewer identities and protected paths exist.
4. Follow [Prepare the Mac transport identities](../../preview/README.md#prepare-the-macs-transport-identities) to configure the channel. Record its machine identity, role accounts, loopback port, and SSH host fingerprint.
5. Compare the resulting identities and channel configuration with the expected result below. Record any installer rejection or partial state as a failed or inconclusive run.

## Expected result

Installer binds the invoking sponsor, creates separate role accounts, and starts the protected loopback channel.

## Cleanup

Follow [Revoke, inspect and remove](../../preview/README.md#revoke-inspect-and-remove) for any remaining installation. Preserve baseline comparisons and cleanup output. The Mac removal retains its Keychain approval key and original transport keys; the guide describes their separate handling.

## Recorded results

✅ A passing historical run is documented in the [evidence report](../developer-preview-milestone.md#clean-installation-and-signed-reviewer-checkpoint--november-13). That report retains its original scope and failure history. This runbook was written from the existing case and source; it has not been rerun as part of this documentation change. Missing historical version or artifact metadata remains unrecorded.

For a new result, record the date, result, exact software/client/OS versions, architectures, source revision, relevant artifact hashes, command output, and cleanup outcome. Include sanitized request IDs and audit counts where applicable. Link that evidence here and update the tables when reviewed. See the [registry](../verification-cases.md#recording-a-run-or-vulnerability) for reporting guidance.
