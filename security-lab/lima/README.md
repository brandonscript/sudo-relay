# Separate Linux VM on Astra

This is a full Ubuntu VM for testing installation and normal sudo/PAM coexistence.
It is separate from Colima's Docker VM. The lab service was installed, tested and
removed; no sudo-relay service remains.

Configuration: `sudo-relay-lab.yaml`, Lima 2.3.0 on Astra, Apple Virtualization,
2 CPUs, 4 GiB RAM, 24 GiB sparse disk. Plain mode disables host-folder mounts,
dynamic application-port forwarding and guest containerd. SSH agent forwarding
and importing personal SSH public keys are disabled. Lima manages its own SSH key.
Network access remains available; this is not a hostile-code containment guarantee.

On Astra, with ordinary Lima defaults (do not set LIMA_HOME to Colima's directory):

```sh
limactl list
limactl shell sudo-relay-lab
limactl stop sudo-relay-lab
limactl start sudo-relay-lab
```

To permanently discard this VM after review:

```sh
limactl stop sudo-relay-lab
limactl delete sudo-relay-lab
```

The instance lives under `/Users/TEST_ACCOUNT/.lima/sudo-relay-lab`. Colima's config and
Docker context are not modified. The source configuration was copied to
`/Users/TEST_ACCOUNT/Downloads/sudo-relay-lab.yaml` on Astra.

Lima creates a bootstrap user with passwordless sudo. That is a VM-management
convenience, not evidence that password-required sudo/PAM works with the relay.
The next installation milestone must use separate test identities and exercise
password-required policy, revocation, restart and uninstall. Do not reuse the
bootstrap user's privilege as proof of agent isolation.

## Provisioning result — 2026-11-12

Verified over authenticated SSH to Astra:

- Host has 64 GiB RAM and 341 GiB available disk at preflight.
- `sudo-relay-lab` is running Ubuntu 24.04.5 LTS, aarch64.
- PID 1 is systemd; system state is `running`; no failed units reported.
- `/usr/bin/sudo` exists; no relay modifications made to guest sudo/PAM yet.
- Root disk has 21 GiB available; no virtiofs, 9p or SSHFS mounts reported.
- Management SSH is loopback-only at `127.0.0.1:51828` on Astra.
- Docker context remains `colima`, same server ID
  `2d824cb0-f884-447b-95b6-b3f831fe1646` before and after provisioning.
- Colima configuration SHA-256 before/after:
  `9b32823c6e658d2ad6a4d96be45252ebc28172141950e06f0c0daf1212bfb3bc`.
- Docker configuration SHA-256 before/after:
  `e571511dcad08e8ed4ff46ef069cdba01d63ddd0ee4dbe06cb6d331d0bf6bce4`.
- No macOS sudo command or sudo-policy modification was performed.

The resolved Ubuntu image is the 20261017 arm64 cloud image, digest
`sha256:50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e`.
This completes VM provisioning only. Relay installation, revocation, persistence,
PAM coexistence, restart and uninstall testing remain the next milestone.


## Installation/security milestone — completed for review

The original disposable VM run passed 30 live assertions, plus
normal uninstall, injected setup-failure rollback and a negative build-mode check.
All privileged commands in this milestone ran inside the VM, never on macOS.
Docker context, server ID and the two configuration hashes above remained unchanged.

The implementation is explicitly experimental. `vm-sudo-lab` is a separate Cargo
feature; the ordinary container-lab build still refuses execution in this VM.
The VM build checks a protected machine-ID marker and a VM runtime check. The
installer is pinned to this exact VM, rejects occupied paths/UIDs, and installs
root-owned binaries, a systemd unit, private state, and separate test identities.
The launcher permits only `/usr/bin/id -u`. Production builds do not select this
adapter through configuration or MCP input.

Only `sponsor_a` selects the experimental PAM service through a user-scoped sudoers
setting. The new service preserves Ubuntu's account/session rules and password
authentication fallback. `/etc/sudoers`, `/etc/pam.d/sudo`, and all existing
`common-*` PAM files retain their original hashes. An unrelated test sudoer uses
the stock stack throughout. Both users rejected wrong passwords and accepted
throwaway passwords. No real password or human private key was used.

Verified through the real MCP server and root Unix socket:

- Agent cannot read approval/private adapter keys or enrollment, submit approval,
  or use sudo directly.
- Altered-command proof, replay, cancellation and expiry are rejected.
- Approved native sudo returns UID 0; output is shared or withheld as approved.
- Sponsor-policy revocation blocks pending execution and new requests.
- Key revocation blocks pending approval and fresh approval after service restart.
- Full VM stop/start restores the service without replaying commands; old proof
  stays rejected and completed state remains durable.
- Normal uninstall removes service, policy additions, module, keys, state and test
  identities. Injected failure after actual account creation also rolls back.

### Findings and exclusions

The first request failed closed because the new VM hostname was missing from
`/etc/hosts`; sudo's policy check took 10 seconds and hit the five-second limit.
Adding `127.0.1.1 lima-sudo-relay-lab` inside the guest fixed resolution. No timeout
was relaxed. This guest hostname entry remains as VM configuration.

A reboot assertion initially expected an exit code in the recovered outcome.
Source review confirmed that outcomes are intentionally memory-only. The test now
requires durable `complete` state and absent transient outcome; this limitation
must be represented honestly in client status after restart. No output persistence
was added merely to make the test pass.

This is **software test approval**, not a human Touch ID trial in the full VM.
The earlier Astra-to-container Touch ID success is separate evidence. Before a
human VM trial, prepare authenticated target pairing and pin the exact native
reviewer to this VM; do not silently substitute it for the container target.

Not covered: MFA/directory identity providers, malicious VM administrators,
account deletion/UID reuse, arbitrary commands, escaped descendants, power loss,
filesystem failure/snapshot rollback, interrupted upgrades, production packaging,
or independent audit. The rollback test injects a Python exception after account
creation; it does not simulate a power cut. The bootstrap user retains Lima's
passwordless administration and must not be confused with the restricted agent.
The guest retains build dependencies and source; relay-specific privileged
installation artifacts and test keys/accounts are removed.

### Reproduce on this dedicated VM only

Build as the ordinary guest user in the copied source directory:

```sh
~/.cargo/bin/cargo build --locked --features vm-sudo-lab --bin integrated-sudo-lab --bin mcp-server
~/.cargo/bin/cargo build --locked --release --manifest-path security-lab/sudo-prototype/Cargo.toml
sudo /usr/bin/python3 -B security-lab/lima/install_vm.py install
sudo /usr/bin/python3 -B security-lab/lima/test_vm.py
sudo /usr/bin/python3 -B security-lab/lima/test_lifecycle.py before-reboot
```

Stop/start only `sudo-relay-lab` from Astra with Lima. Then inside the guest:

```sh
sudo /usr/bin/python3 -B security-lab/lima/test_lifecycle.py after-reboot
sudo /usr/bin/python3 -B security-lab/lima/test_lifecycle.py key-revocation
sudo cat /lab/test-results.json
sudo /usr/bin/python3 -B security-lab/lima/install_vm.py remove
sudo /usr/bin/python3 -B security-lab/lima/test_rollback.py
```

Do not run these installers on another machine or remove their VM guards.
The reported 30 checks include the separate fresh-key-revocation test. The current
main test also includes that assertion for future full runs, so counts may grow.
Stop for review before preparing the native human-approval handoff.
