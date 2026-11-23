# Repeatable developer preview

Status: developer-preview acceptance passed November 13.
Clean-VM installation/lifecycle checks and the actual client/native-review/sudo
flow are verified below. This is fixed-command experimental evidence, not release
readiness or an independent security audit.

## Done means

A clean Linux VM and a Mac approving device can follow one documented path from a
clean source checkout to setup, public-key pairing, MCP request, protected native
review, result/status, revocation, restart and uninstall. Keep the executable
allowlist at `/usr/bin/id -u`. Human Touch ID is still a required final check.

The preview must:

- Bind its sponsor to the real account elevating the installer; never accept a
  caller-supplied sponsor UID/name. Keep separate agent and review identities.
- Use dedicated protected installation/state/socket paths, with no `/lab`,
  `/integration`, fixed account numbers, Astra hostname or Lima machine-ID constants.
- Keep stock sudo/PAM unchanged. Any additional PAM service and sudoers defaults
  must be scoped to the sponsor. Preserve ordinary password authentication.
- Keep approving private keys on the Mac; Linux receives only the public key.
- Pin target identity, sponsor and transport independently of agent explanations.
- Connect an actual MCP request ID to the protected native reviewer, with normal
  status retrieval and no one-shot root orchestrator fabricating the user flow.
- Allow an unprivileged agent to request/open review, never produce approval.
  The root-owned reviewer still freezes and signs the exact request after fresh
  biometric authentication. Opening a prompt is not an authorization boundary.
- Recover after service restart without retrying consumed requests; disclose
  unavailable transient results instead of inventing an exit code.
- Revoke a device and sponsor rights, preserve denied state across restart, and
  remove the installation without retaining privileged test grants or keys.

## Implementation order

1. Extract validated installation configuration and sponsor provenance from the
   bounded VM experiment. Keep the old experiment as evidence, not as the installer.
2. Move the sudo adapter/PAM grant paths into that protected installation context;
   retain exact command/process/one-use checks and opt-in preview build selection.
3. Provide separate pinned MCP and review channels and a local Mac adapter that
   opens only the administrator-installed reviewer for the returned request ID.
4. Build documented install/pair/revoke/status/remove commands and automated
   clean-VM acceptance. Then perform the final human approval check.
5. Reconcile README/security status, review privileged changes and record limits.

## Verification gates

Installation identity forgery, path/UID collision and partial install rollback;
ordinary password fallback and agent denial; missing/wrong pins and peer identity;
exact request display/signature; replay, altered command, expiry and cancellation;
key/sponsor revocation; service reboot and uncertain result handling; complete
removal. Existing coverage may be reused only where the finished path is exercised.

## Containment and publication

Use Astra's disposable full Linux VM for execution tests. Docker and macOS sudo
policy remain untouched. Mac administrator installation and signing changes are
prepared for user review and performed by the user. No arbitrary command support
or claim of production readiness is part of this preview milestone.

Do not label this milestone complete because individual lab tests pass. The
README procedure and actual MCP entry point must both be tested end to end.

## Implementation checkpoint

Added typed sponsor provenance and per-sponsor installation paths; three unit
checks pass. The PAM verifier and independent pre-launch gate now share explicit
installation-root support: private root-owned ancestors, no writable ancestors,
no symlink roots, no relative contexts. Existing container calls retain their lab
default for regression coverage. Two PAM context/argument checks pass. Grant
signature, process identity, separate release/redemption receipts and durable
consumption remain in the shared implementation.

The Python execution adapter now resolves its internal signing key under its
installation root and accepts an administrator-selected gate invocation internally;
no agent request can select either. Next wiring must select those protected paths
from the install context, install the service/PAM defaults, then exercise the new
path on a clean VM. These APIs alone do not establish a working preview install.

### Installed-path checkpoint — November 13

The preview now has an explicit `developer-preview` feature and dedicated broker
binary, per-sponsor enrollment, root-owned installed launcher, scoped PAM service,
and reversible administrator commands. Paths derive from the sponsor UID rather
than lab constants. Install does not grant new sudo command rights. Runtime stays
restricted to id-u. Installation reports success only after the root service and
socket are ready.

On Astra's existing full Linux VM, installation derived sponsor the test sponsor
from its actual sudo parent, allocated agent/review IDs through the OS, and used
`/etc/sudo-relay/UID`, `/var/lib/sudo-relay/UID`, `/run/sudo-relay/UID`. The real MCP
server accepted one software-test-signed request; id-u returned 0, agent approval
and replay were denied, and agent reads of private keys/enrollment failed.

A second dynamically allocated sponsor installed through password-required sudo
and passed the same MCP checks using its own context. Its signed execution also
used the scoped PAM service with no supplied command password. Removing that
installation preserved the first sponsor's shared binaries and service.

Two real lifecycle bugs were exposed and corrected: missing broker key directory,
and private role-group cleanup order leaving an empty group that blocked reinstall.
The old installation was removed and reinstalled successfully after correction.
The test owner/policy for the password-required case was removed. Test signing keys
were temporary and revoked by the test driver. No human signing key was used.

Local checks: preview broker builds; three identity tests and two PAM-context
checks passed. Live installed-path checks are software-signing evidence on the
existing VM, not clean-VM README acceptance or a protected human approval result.
First preview service remains installed with test approval key revoked while MCP
adapter integration is developed. Docker and macOS sudo were not modified.

### MCP/review channel checkpoint — November 13

Implemented separate forced SSH agent and review roles for each installed sponsor.
Transport public keys must be distinct Ed25519 keys. The endpoint binds only to
loopback, disables password/interactive auth, forwarding and PTYs, and checks the
actual process UID before entering MCP or the restricted review socket protocol.
Stock sshd configuration is unchanged. Role account passwords are unrecorded
random values, not empty passwords; the dedicated channel accepts only keys.

Live existing-VM checks passed: SSH agent starts actual MCP and creates a request;
review retrieves the same pending envelope and cancels it; review cannot create a
request; missing host pin and wrong client identity are rejected. No approving
private key was used. This test leaves a restricted channel with now-discarded
test transport private keys; installation is for ongoing development only.

The Mac stdio adapter correlates request_execution RPC responses, passes protocol
output back promptly, and opens only the configured protected reviewer with a
canonical request UUID and protected enrollment reference. It never signs or
submits approval. Tests verify matching response, no duplicate trigger, unrelated
methods, error replies and injected references. The adapter's complete stdio path
and protected Mac installation still need integration testing.

Native enrollment adds `linux-developer-preview-v1` and an explicit validated SSH
review account for that purpose. Legacy lab enrollments keep their old default.
Four native protocol tests, two trigger tests, one transport-key validation test,
and three install-identity tests passed. The new native executable has not yet
been signed or human-tested. Do not reuse the old signed reviewer for this purpose.

### Clean installation and signed reviewer checkpoint — November 13

A separate fresh Lima VM, `sudo-relay-preview-clean-20261113`, built the preview
from source and passed installed MCP execution, agent isolation, replay rejection,
durable state after broker restart, restricted SSH transport and removal checks.
A second password-required sponsor passed independent installation/execution and
removal without changing the first sponsor's installation. Temporary software
approval keys were revoked. These are automated fixture results, not human approval.

The install now rejects custom authentication stacks rather than silently replacing
MFA with a signed grant. Administrator operations are serialized; setup source files
are read with the invoking user's permissions. Removal and reinstall exposed and
fixed role-group cleanup, and root key validation now uses private permissions
before making the installed transport keys readable to the approving account.
All 12 local Python preview tests pass.

The returned Personal Team reviewer passes strict code-signature, entitlement,
resource/profile and normalized executable comparison against the signing kit.
Its binary SHA-256 is
`1d8a7436eb6f301688da19b777d47e1e933811b1ecd220576ef8a14ff31a0d77`;
its provisioning profile expires November 18, 2026 at 18:15:04 UTC. The clean VM
is now paired with the existing human public key and separate transport public
keys. No human-approved execution has been requested on this installation.

Pending: user-performed protected Mac setup, actual client MCP connection and
fresh Touch ID approval with authoritative status retrieval. Setup artifacts have
unique ZIP and extracted-directory names. Neither signing verification nor these
fixture results closes that final acceptance gate. Docker and macOS sudo/PAM
policy remain untouched.

### Mac installation acceptance findings

The first administrator install rejected an otherwise matching transport key
because OpenSSH retained a comment. Compare the algorithm and encoded key, not
the comment; regression checks still reject a different key or algorithm. The
failed installation removed its target directory. The corrected installation
succeeded under the ordinary approving account; installed paths passed ownership,
permissions and ACL checks, and the installed executable matched the signed build.

The actual MCP preflight then exposed an OpenSSH configuration parsing bug:
`UserKnownHostsFile` treats an unquoted path containing `Application Support` as
multiple paths, even when supplied as one process argument. The connection failed
closed before any execution request. Quoting the option value made the same
installed channel complete MCP initialization with strict host checking retained.
Both the Python agent transport and native review transport now quote that path;
the native path formatter rejects quote, backslash and control characters.

That remote failure also exposed a Python shutdown crash: a daemon thread held
the buffered stdin lock while the interpreter finalized. Input now uses stoppable
file-descriptor reads and the bridge joins the reader on shutdown. A subprocess
regression verifies failure exits normally even while client stdin remains open.
Fourteen Python checks and five native execution checks pass. A replacement native
build has been prepared for isolated signing; final client/human acceptance is
still pending. No command request was created by either MCP initialization check.

The corrected returned reviewer passed the same signature, entitlements,
resources/profile and normalized executable comparison. Its binary SHA-256 is
`24d42672882d5fe0d832f846802fe3dcb40909ad2c3a43d1a372dd91b1be54f1`.
Replacement setup is prepared for the approving user; it verifies the previous
installed executable before removing that target's Mac files. It retains the
Keychain key, transport source keys and Linux pairing. Installation of this
replacement and final MCP/Touch ID acceptance remain pending.

The user installed the replacement successfully. Read-back verified every target
path with the installed ownership/permissions/ACL validator, confirmed ordinary
console UID 501, and matched the corrected executable digest above. The installed
stdio command completed actual remote MCP initialization and tools/list through
the pinned SSH channel; the bridge exited with status 0 and no shutdown crash.
Codex registration is present, but the current chat has not loaded its tool list;
client refresh and the human-approved id-u request remain outstanding. No execution
request was sent by this preflight. SSH emits a harmless missing role-home warning;
the forced channel still starts and exits normally.

### Human-approved actual MCP execution — November 13

After Codex refreshed its registered connection, its actual `request_execution`
tool created request `b61d3dc6-4781-4da4-b721-46953f7d7d28` for `/usr/bin/id -u`
with a five-second limit, empty environment and output requested. The installed
adapter opened the protected native reviewer on Astra. The user confirmed the
host/OS/account display and completed Touch ID with output sharing enabled.

The same client's `execution_status` returned `complete`, exit code 0, stdout
`0\n`, empty stderr, output_shared=true, no timeout, no truncation, no execution
error and no cleanup error. A read-only query of the protected VM SQLite audit
showed exactly `pending`, `consumed` by key `human`, `running`, `complete` for this
request. There was one consumption and one launch transition. This is actual
client/native-biometric/Linux-sudo evidence, not a software fixture signature.

The chat renderer separately timed out: preview/approval.html was a static page
without an MCP Apps initialization handshake. Native approval remained pending
and succeeded independently. A read-only SDK-backed notice is being verified to
replace that page; it has no approval input or signing route. Its rendering failure
must not be presented as evidence that execution failed or that retry is safe.

The replacement notice now uses the existing MCP Apps SDK, advertises inline-only
display and contains no form, input, approval button or signing route. TypeScript
checks, bundle build and a focused initialization/no-controls regression pass.
It was installed in the clean VM without restarting the broker or altering the
completed request. Its next render in Codex remains a separate visual follow-up;
the current connection caches the earlier HTML. No new sudo execution is required
for that check. The core developer-preview milestone stops here for user review.

November 14 visual follow-up: after refreshing Codex, request
`77f4fa33-b94a-40c7-88d0-d106906ba868` exercised the corrected notice. It was
immediately cancelled through MCP; authoritative status was `cancelled`, with no
outcome and no pending request. The user's screenshot confirms “Review on your
approving Mac” and the explanatory text render inline, with no timeout or approval
controls. This closes the display follow-up without another sudo execution.
