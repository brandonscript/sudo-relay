# sudo-relay developer preview

Request one `/usr/bin/id -u` execution through MCP, review the exact request on a
Mac, and authorize it with Touch ID. Linux evaluates the installing user's current
sudo policy when executing. Removing that user's sudo rights blocks the relay too.

This is an experimental developer preview for an Ubuntu VM and a Mac approving
device. Fresh-VM installation/lifecycle checks and an actual Codex MCP request
approved through the protected Mac reviewer with Touch ID have passed. The command
returned root UID 0; the protected audit recorded one consumption and one launch.
See [the milestone evidence](../docs/developer-preview-milestone.md) for limits and
the separate inline-display issue.
This source-only alpha candidate requires a local build and separate Mac signing.
It ships no signed reviewer, installer binary, or signing credentials. The lab
reviewer was signed with an isolated Apple Developer Personal Team, with the
signing key kept outside the agent’s reach. That build passed the Touch ID
flow. The included kit expects the lab bundle ID and team. Self-service signing
and enrollment with a new team and bundle ID have not been tested.

## What you need

- An Ubuntu 24.04 VM with systemd, working hostname resolution and existing sudo
  access. Use a disposable VM. The installer refuses non-VM deployment in this preview.
- Rust, Node.js 24 and npm, Python 3, OpenSSL, OpenSSH server/client, a C compiler,
  and pkg-config.
- A Touch ID Mac with the protected reviewer signed for its approving account.
  Signing needs a certificate/profile the agent cannot use to impersonate the app.
- For this first supported transport, Lima on the approving Mac hosts the VM.
  Docker and macOS sudo/PAM configuration are not changed.

Lima's bootstrap account has passwordless administration. That remains an existing
route to VM root; this tool does not block it. The relay creates different Linux
agent and reviewer accounts. Its approval boundary is the protected signing key
and explicit human authentication, not possession of a local TCP port.

## Build and install on Linux

From the source checkout:

```sh
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev openssl openssh-server python3
npm --prefix ui ci
npm --prefix ui run build
cargo build --release --locked --features developer-preview --bin sudo-relay-preview --bin mcp-server
cargo build --release --locked --manifest-path security-lab/sudo-prototype/Cargo.toml
sudo /usr/bin/python3 -I -B preview/admin.py install
```

Install as the account that will sponsor execution. There is no sponsor selector:
the installer verifies its actual sudo parent and binds the current invoking
account. It must already be allowed to run id-u as root. No new command permission
is added. The installer creates separate system accounts and protected paths under
`/etc/sudo-relay/UID`, `/var/lib/sudo-relay/UID`, and `/run/sudo-relay/UID`.

The additional PAM service is scoped to that sponsor and replaces stock password
authentication only for a valid one-use grant. Ordinary password fallback remains.
Custom common-auth/MFA modules, custom sudo authentication includes and existing
sudo PAM-service overrides are rejected rather than bypassed. The installer leaves `/etc/pam.d/sudo`, common PAM stacks and `/etc/sudoers` unchanged.
Only the internal one-use grant key is generated on Linux. Approving private keys
are never installed there. Another sudoer can install an independent instance;
shared binaries must match exactly. Upgrades that change them require review.

If sudo reports slow policy checks, first confirm `getent hosts "$(hostname)"`
works. Plain Lima cloud images may need their hostname added to the guest's
`/etc/hosts` by the administrator. The relay does not silently rewrite that file.

## Prepare the Mac's transport identities

In your ordinary Mac account, from the same source checkout:

```sh
/usr/bin/python3 -I preview/mac_setup.py keys "$HOME/Downloads"
```

This prints a uniquely named directory containing separate `agent` and `review`
SSH identities. Copy only the two-field public keys from the `.pub` files to the
Linux administrator. Keep the private files on your Mac. They authenticate the
transport; they are not approval-signing keys and cannot authorize execution.

On Linux, as the sponsor, use the printed public keys (without comments):

```sh
sudo /usr/bin/python3 -I /usr/local/libexec/sudo-relay/admin.py configure-channel 'ssh-ed25519 AGENT_BASE64' 'ssh-ed25519 REVIEW_BASE64'
```

The command prints the machine UUID, sponsor, actual role accounts, loopback port
and host key. Preserve that output through the trusted administrator connection.
The endpoint has forced commands, no shell/PTY/forwarding/password login, and
separate MCP and review identities. Stock sshd configuration is unchanged.

## Mac reviewer signing and enrollment

The remaining Mac steps require a verified, signed execution reviewer and its exported public-key candidate. The included signing kit reuses a previously provisioned app, certificate, and profile from the isolated signing team. It is not a self-service setup for a new Apple Developer team or bundle ID. A new installation cannot complete Touch ID setup from this archive alone without adapting and verifying that signing configuration.

The [execution reviewer notes](../security-lab/native-execution/README.md#signing-handoff) describe that handoff. [package-signing-kit.py](../security-lab/native-execution/package-signing-kit.py) prepares it from the existing signed template. The native execution app's `--enroll` mode creates an execution-purpose device-local key after explicit Touch ID confirmation and exports only its public candidate. Enrollment runs in the ordinary approving account after leaving the isolated signing account. It does not pair the Linux broker.

If an execution-purpose key already exists, keep its exported public candidate and use it for pairing below. Replacing the reviewer binary does not require re-enrollment. The receipt-only Xcode project uses a different entry point and key purpose; use the execution reviewer for command approval.

## Pair the approving key

Export the existing protected reviewer's **public** P-256 candidate on the Mac.
Compare its fingerprint through your trusted setup channel, then on Linux:

```sh
sudo /usr/bin/python3 -I /usr/local/libexec/sudo-relay/admin.py pair 'p256-sha256:UNCOMPRESSED_PUBLIC_KEY_HEX'
```

The broker validates the key, refuses silent replacement, and cancels pending
requests when pairing or revoking. A public candidate alone does not prove private
key possession; the first signed approval verifies that. Never pair a published
test fixture key for a real approving device. Do not re-enroll an existing key
merely because the reviewer binary changed.

## Install the Mac target

The Mac setup takes the reviewed signed `.app`, a target plan JSON and the transport
key directory. The plan pins Linux's machine UUID, sponsor, host key, SSH role
accounts, public approval key/fingerprint and reviewed code identity. It names the
Lima VM but contains no sudo password or approving private key.

```sh
sudo /usr/bin/python3 -I preview/mac_setup.py install /path/to/sudo-relay.app /path/to/target-plan.json /path/to/transport-directory
```

Stop the MCP connection before removing or replacing an existing Mac target.
Restart that connection after installation (restart the client if necessary).
The adapter loads configuration at startup; a replacement may select a new local
port. A still-running adapter must not be used with the new reviewer configuration.

This creates a protected directory under `/Library/Application Support/sudo-relay/`
for that target UUID. It verifies the signed app and executable digest, validates
transport-key correspondence, and writes the enrollment and MCP configuration.
It neither launches the reviewer nor creates a Keychain key. It changes no sudo
policy and installs no launchd daemon. It prints the exact MCP command to use.
Generate the plan in your ordinary Mac account from the Linux connection JSON,
the existing execution public-key candidate, the reviewed signed app, and the
Lima VM name:

```sh
/usr/bin/python3 -I preview/mac_setup.py plan /path/to/connection.json /path/to/public-candidate.json /path/to/sudo-relay.app LIMA_VM_NAME "$HOME/Downloads"
```

The command verifies signing and Keychain/debugging entitlements and creates a
uniquely named plan directory. Compare the fingerprint, machine/account and SSH
host key with the Linux administrator output before installing it. The signed
reviewer must declare `linux-developer-preview-v1` support; an older lab reviewer
is rejected. A valid signature does not replace reviewing the source/build.
The documented protected installation and human approval flow were exercised on
the test Macs/VM; that does not establish compatibility with every Mac or client.

## Use the MCP

Configure the printed stdio MCP command in your client. `request_execution` returns
its ordinary request result and opens the protected native reviewer for that UUID.
The chat view itself cannot sign. Review host, account, command and output-sharing
choice, then authorize with a fresh fingerprint. The broker binds the signature
to the complete request and sharing choice. Use `execution_status` for the result.

Only id-u is supported in this preview. Approval expiry defaults to five minutes;
execution timeout is separately bounded at five seconds. Output stays in memory
and is withheld unless the signed decision enables sharing. Restart preserves
completed/consumed state but loses transient outcomes; never infer an exit code
from a durable state alone. Disconnect does not undo committed execution.

## Revoke, inspect and remove

Run these as the installing sponsor on Linux:

```sh
sudo /usr/bin/python3 -I /usr/local/libexec/sudo-relay/admin.py revoke
sudo /usr/bin/python3 -I /usr/local/libexec/sudo-relay/admin.py status
sudo /usr/bin/python3 -I /usr/local/libexec/sudo-relay/admin.py remove
```

Removal stops the broker and channel, removes their files and role accounts, and
checks the original sudo/PAM hashes. Shared binaries remain if another sponsor is
installed. Read a removal error before manually deleting anything. If sponsor or
role identities changed, use administrator recovery rather than transferring the
old enrollment. An empty root-owned administrative lock under `/run` may remain
until reboot; it contains no key or authorization. Consumed approvals are not refunded or automatically retried.

On the Mac, stop the MCP connection, then remove that target as its approving account:

```sh
sudo /usr/bin/python3 -I '/Library/Application Support/sudo-relay/TARGET_UUID/mac_setup.py' remove TARGET_UUID
```

The existing Keychain approval key is retained. Original transport key files are
also retained; remove those separately when no longer needed.

## What is still experimental

No arbitrary commands, scripts, production installer, independent audit, MFA or
directory-provider compatibility claim. Storage/power failures, snapshots and UID
reuse remain open risks. A VM administrator controls the broker, and approved root
code could establish persistent access. This preview is not a sandbox or a way to
remove other administrative routes.
