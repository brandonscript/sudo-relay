# Receipt-only installation proposal for this Mac

Prepared November 10, 2026. **For review, not installation approval.** The user
selected this Mac for a narrowly scoped test. Nothing below has been installed,
signed with a personal certificate, enrolled in Keychain or launched as root.

## What you would be approving

A temporary native reviewer and a manually started, receipt-only verifier. The
reviewer shows one fixed test request and asks for Touch ID. The verifier records
approval; it has no command-launch path exposed by its entry point. There is no
sudo permission grant, sudo password storage or change to PAM/sudoers.

Use no LaunchDaemon, LaunchAgent, login item, background updater, TCP listener,
new user account or new group. Start the verifier explicitly for the test; stop it
at the end or after a short lifetime. A consumed receipt deliberately blocks new
work in the current fixture, so each scenario needs its own disposable ledger.

## Proposed footprint

| Location | Contents and access | Removal |
|---|---|---|
| `/Library/PrivilegedHelperTools/sudo-relay-receipt-lab/` | New root-owned directory, mode 0755. Signed reviewer `.app`, receipt-only controller/verifier and a manifest of their hashes. Every descendant remains root-owned and not group/world writable. | Stop its verified process, then remove only the manifest-listed installation. Refuse an unexpected pre-existing path. |
| `/private/var/db/sudo-relay-receipt-lab/` | New root-owned parent, mode 0755; root-only state subdirectory, mode 0700; public enrollment, mode 0644; socket subdirectory, mode 0755. Socket mode 0660, group `staff` on this Mac. No command output saved. | Remove the named scenario ledgers, enrollment and socket after stopping the verifier. Keep an optional redacted result report in the repository. |
| Approver's data-protection Keychain | One new, non-synchronizing item per explicitly enrolled test key. Service `sudo-relay.receipt-signer.v1`; account is SHA-256 of the enrolled P-256 public key. Wrapped Secure Enclave representation only, never a sudo password. Reviewer-specific authorized access group required. | The same signed reviewer deletes only this exact service/account/group after user confirmation. No broad Keychain deletion or fingerprint changes. |

No files are placed in `/etc`, `/Library/LaunchDaemons`, `/Library/LaunchAgents`
or `/Applications`. No changes to Accessibility, Screen Recording or computer-use
permissions. Do not install the production `broker serve` binary as this verifier.

## Process identities

Read-only inspection found approving account `brandon` (UID 501, GID 20), an
existing `nobody` account, one Apple Development signing identity and no Developer
ID Application identity. One local macOS provisioning profile was inspected;
none matches the proposed receipt-lab identifier. These are observations, not
authorization to use a key.

The broker requires distinct requester and approver UIDs. For this fixed-command
experiment, the reviewed controller would spawn a short-lived requester, drop
supplementary groups and switch to existing `nobody`, retaining only the explicitly
needed socket group. It would submit a compiled-in receipt-only test request and
exit. It must verify its dropped identities before contacting the socket. It must
not run a shell, accept arbitrary commands or become a reusable identity-switching
helper. This avoids creating an account or relaxing the broker's identity rule.

This fixture does not establish normal MCP-to-broker routing on this Mac. Other
processes using `nobody` could attempt requests; that account is not a dedicated
security identity. The public-key proof remains required for approval. The
requester controller is still to be implemented and tested before installation.

## Signing and Keychain gates

The existing interactive app only reads a pre-enrolled item; it does not create
one. Provisioning remains unfinished. Apple requires provisioning-profile authority
for the entitlements used by the data-protection Keychain; a certificate or an
ad-hoc signature alone is insufficient. See [Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).

Use a dedicated bundle identifier, proposed `com.sudorelay.receiptlab`, and a
single reviewer-specific Keychain group authorized by its profile. Sign with
hardened runtime and without debugger, unsigned-executable-memory or disabled
library-validation exceptions. Verify the final signature, profile, entitlements,
expiry and recorded hashes before copying anything into protected locations.
No notarization or public distribution is proposed for this local trial.

The signing key must not be usable by the agent to sign an impersonating app with
the same Keychain entitlement. Root-owning the installed copy does not prevent
that separate attack. We have **not** tested the current certificate's private-key
access policy or used it for signing. This is a gate, not a cosmetic warning.

Enrollment must run explicitly inside the authorized reviewer, create a new
biometry-current-set key and expose only its public pin for administrator pairing.
Then verify a different ordinary process cannot retrieve the Keychain item;
missing/replaced key state must stop instead of creating a replacement or using
session approval. No import of the earlier agent-readable fixture key.

## Order of operations after preparation

1. Settle the signing profile and private-key access boundary. Build the exact
   candidate, verify it and publish its manifest for review.
2. Review the installer, bounded manual launcher and exact-item removal code.
   Exercise them on disposable CI where possible. No generic privileged service.
3. Obtain approval for those concrete artifacts and changes. The user performs
   required administrator authentication; no password enters chat or MCP config.
4. Install, explicitly enroll a fresh key, pair its public pin and run the
   other-process access/replacement checks before requesting a test approval.
5. Run the milestone's success/cancellation/expiry/replay/disconnect scenarios,
   inspect the ledger and stop. Remove the fixture after the user reviews results.

The installer/launcher and enrollment/removal actions are not yet complete, so
there is deliberately no `sudo ... install` command to run from this proposal.

## Read-only preflight

From the repository root, run:

```sh
python3 security-lab/native-install/preflight.py
```

It reports current identities, source hashes and path collisions. It reads only
code-signing identity metadata, not private-key material; it does not sign, launch
the app, request biometrics, install files or alter Keychain. `install_ready` stays
false until the remaining gates are implemented and verified. The generated
report is local evidence, not a deployment permission or security certificate.
