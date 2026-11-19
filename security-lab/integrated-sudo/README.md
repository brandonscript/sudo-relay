# Broker approval through native sudo

A disposable Linux integration milestone. This fixture connects the current
broker's canonical CBOR approval verification and durable one-use consumption to
the earlier native-sudo experiment. It runs only fixed harmless commands:
`id -u`, `touch` of either of two markers in the container's private fixture,
and a fixed synthetic stdout/stderr probe.

**Never install this fixture's PAM stack or launcher on a real machine.** The
normal broker binary is unchanged and still launches directly as root. This is
an integrated test adapter around the real broker library, not a production MCP
execution transport or a finished installer.

## Run

From the repository root, with Docker running:

```sh
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml build
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml run --rm --no-deps integration
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml down --volumes --remove-orphans
```

Runtime has no network, ports, host mounts, Docker socket or persistent volumes.
The image is read-only; temporary keys, sudoers rules, timestamps, logs and
ledgers live on tmpfs. Container removal deletes them. Build layers remain in
Docker's cache. Setuid is intentionally available inside the container for sudo;
`no-new-privileges` would prevent this test. `SYS_PTRACE` lets the root installer
inspect its nondumpable sudo parent inside the container PID namespace. No host
PID namespace, privileged-container mode or host authentication access is used.

## What connects to what

1. Each of two locked-password accounts invokes the fixed installer through
   actual sudo. There is no sponsor argument. The installer requires root real
   and effective IDs, an elevated `/usr/bin/sudo` parent, and matching sudo UID,
   GID and account metadata. Forged caller environment values are overwritten by
   sudo. This fixture enables sudo I/O logging so sudo retains a monitor process;
   this parent check is **not** a portable installer design for all sudo modes.
2. Each enrollment gets a root-only directory, independent broker configuration,
   random signed enrollment/machine identifier and ledger. A disposable approving
   account has the software signing key; the agent and sponsors cannot read it.
   Administrator fixture setup pairs its public key through `Broker::pair_key`.
3. The root-only controller checks the enrolled sponsor's current command policy,
   then calls `Broker::handle_current` to freeze the request. The fixture signer
   signs the broker's exact CBOR execution-decision bytes. Receipt-decision
   signatures are rejected. No Astra key or previous receipt is reused.
4. Only a returned `Job` from successful broker approval can enter the launcher.
   The broker has already committed consumption. The adapter uses that stored
   job's arguments, never a second command supplied with approval. It checks
   sponsor identity, policy and expiry, and starts a waiting sponsor process
   with freshly resolved groups and a cleared environment.
5. A separate root-only **internal** key issues a short-lived, process-bound PAM
   ticket. This ticket is not human approval: authority comes from the consumed
   broker decision. The reused independent gate verifies/consumes that ticket
   before release, even if NOPASSWD means PAM will not run. The child executes
   exactly `sudo -k -S -u root -- COMMAND ARGS`; native sudo checks command policy
   as the sponsor and logs its identity. Identity/groups and expiry are rechecked
   just before release. Nothing feeds a password to sudo.
6. The fixture records completion, or leaves an interrupted consumed decision
   uncertain on restart. There is no queue that resumes execution and no retry.

The controller's stdin is a **trusted root test-driver interface**, not an
agent-accessible server. It assigns simulated peer roles when exercising the
real broker library. The existing production Unix socket/MCP transport, actual
human signing UI and production output delivery are outside this milestone.
Only root test diagnostics report whether `id` returned zero; no command stream
is sent to an agent. Output-sharing privacy is not newly established here.

## Real MCP/socket mode

The later [real MCP milestone](../../docs/mcp-sudo-milestone.md) adds a `serve`
entry point to the same lab binary. It uses the actual production socket framing
and kernel peer identity, then the same sudo adapter. `mcp-server` runs as the
agent and a separate software approver signs and submits proofs. The stdin role
simulation described above remains only for the original regression suite.

Run the MCP suite in a fresh container after building:

```sh
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml run --rm --no-deps --entrypoint python3 integration -I /integration/test_mcp.py
```

MCP mode returns bounded command streams only under the signed sharing choice.
The output probe exposed a short-output issue with sudo's I/O-logging pipe path;
the adapter now captures into anonymous RAM files. Fixed probe sizes bound this
fixture, not arbitrary programs. See the report before reusing this code.

## SSH review transport

The [SSH transport checkpoint](../../docs/ssh-review-channel.md) adds a pinned,
forced-command review connection entirely inside the disposable container. It
uses fixture keys, not the native Touch ID reviewer. Run it with:

```sh
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml run --rm --no-deps --entrypoint python3 integration -I /integration/test_ssh.py
```

The container additionally grants `SYS_CHROOT` for sshd privilege separation.
There are still no published host ports or host authentication changes.

## Tests and limits

See [the milestone report](../../docs/integrated-sudo-milestone.md) for the test
matrix, measured run and remaining gaps. Fault checkpoints are root-owned
fixture files; no client protocol can request a crash or skip a gate.

The Linux PAM module and independent gate under `../sudo-prototype` are restored
unchanged from repository commit `751e259`. Their earlier JSON ticket format is
retained for the internal ticket only; human approvals use the current broker's
CBOR protocol. No dependency was added to the main crate.
