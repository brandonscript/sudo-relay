# Disposable security lab

For a small, idle environment with no attack runner, use the [disposable broker fixture](fixture/README.md). The older harness below contains pre-fix exploit expectations and is not the default fixture.

Attack the experimental broker without installing it on your machine.

This lab copies an allowlisted source context into a disposable Linux image, builds the broker and reference host, and attacks real processes running as different numeric UIDs. A successful unapproved execution runs as root **inside the container**, not on the Mac. It never uses your login password, Keychain, SSH keys, or real signing keys.

This is an adversarial evaluation of the current implementation, not a certification. The harness deliberately reports vulnerabilities with exit code 1. Do not treat a successful build as a security pass.

## Isolation

Run the attack phase with no host directories or Docker socket mounted, no published ports, no external network, a read-only image, bounded tmpfs storage, and process/memory/CPU limits. Keep Docker's default seccomp/AppArmor policies. Do not use `--privileged`, host networking, host PID namespaces, `SYS_ADMIN`, `SYS_PTRACE`, or extra mounts.

The limited capabilities below let the root fixture create separate UIDs, assign fixture ownership, and stop its child processes. They do not grant those capabilities to the unprivileged attacker. Network is permitted only while building dependencies; the running lab has loopback only. Source is copied into the image rather than mounted during attacks. The `.dockerignore` uses an allowlist and excludes private keys.

Container isolation depends on the Linux kernel and container runtime. It is not proof against a kernel/runtime escape. For hostile exploit binaries or kernel testing, use a fresh dedicated VM with no shared folders, clipboard, credentials, or host integration; do not run that work in this lab. This lab tests our application, not the kernel.

## Run

From the repository root:

```sh
docker build -f security-lab/Dockerfile -t sudo-relay-security-lab:local .
docker run --rm --network none --read-only \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add FOWNER --cap-add KILL \
  --security-opt no-new-privileges \
  --pids-limit 128 --memory 768m --cpus 2 \
  --tmpfs /lab:rw,nosuid,nodev,noexec,size=128m,mode=0755 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  -e PE_DISPOSABLE_LAB=1 sudo-relay-security-lab:local
```

A restricted build environment can redirect Buildx's local metadata using `BUILDX_CONFIG=/private/tmp/sudo-relay-buildx`; this does not change the runtime security boundary.

Output contains one JSON record per case, followed by `LAB_RESULTS=...`. Exit 0 means implemented cases passed, 1 means a vulnerability was demonstrated, and 2 means at least one test could not complete. A negative result applies only to the tested cases and assumptions. Retain results before deleting the image if you need evidence.

## Roles and evidence

- **Broker:** root, production mode, private ledger and public trust keys.
- **Agent:** UID 10001, socket access but no signing-key access.
- **Approver:** UID 10002, private random Ed25519 key and reference signing host.
- **Negative control:** a separate broker permitting identical agent/approver UIDs.
- **Fake password:** a random canary in a root-only file. A digest match demonstrates access without printing its contents. It is not a real account password or a model of macOS Keychain.

All attack requests run in real unprivileged subprocesses. JSON UID fields cannot substitute for kernel peer identity. The lab controller can act as the approver only in explicitly labelled positive controls. It also attempts the signer HTTP attack as the agent, without reading the private key or involving a human.

See [the case catalogue](test-cases.md) and [recorded verification](../docs/verification.md). Neither replaces an independent security audit.
