# Pinned SSH review channel

November 11, 2026. This is a transport checkpoint toward the Astra human-approval
milestone, not completed Touch ID integration.

The user confirmed Docker works on Astra. The intended trial keeps the native
reviewer and Linux container on that Mac, using loopback. No Astra listener or
host configuration has been installed by this checkpoint.

## What runs now

The disposable Linux image runs OpenSSH on its own loopback interface, under
`network_mode: none`. No host ports, mounts or Docker socket are exposed. The SSH
client also runs inside that container, with generated fixture keys only.

An authenticated SSH session is forced into `integrated-sudo-lab review-channel`
as the unprivileged approver. It reads a root-protected target record and uses
the existing root-peer-authenticated Unix socket transport. Only status,
cancellation and execution-proof submission are allowed. Request creation and
receipt-proof submission are rejected. Approval still requires the broker's
paired signing key; the SSH client key alone cannot approve a command.

The test client ignores user SSH config and agents, pins the server key, disables
connection sharing and uses one explicit identity. The server disables password
authentication, root login, PTYs and forwarding. The disposable approver account
is unlocked for SSH public-key login; both sponsor accounts retain locked
passwords. `SYS_CHROOT` is added solely for the container sshd's privilege
separation. The ordinary host SSH daemon and sudo/PAM configuration are untouched.

## Reproduce

From the repository root:

```sh
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml build
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml run --rm --no-deps --entrypoint python3 integration -I /integration/test_ssh.py
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml down --volumes --remove-orphans
```

## Observed results

Five SSH test methods passed in 4.035 seconds on local Docker, Debian trixie,
ARM64, sudo 1.9.16p2:

| Case | Observed result |
| --- | --- |
| Pinned status, approval and replay | Remote pending request matched MCP; one valid signed approval returned UID 0; reuse rejected |
| Wrong or missing host pin | SSH rejected the host before submission; request remained pending and effect marker absent |
| Requested shell command and forged proof | Forced review channel handled status instead; shell marker absent; forged signature, request creation and receipt submission rejected |
| Cancel then submit valid proof | Cancellation confirmed; later approval rejected; state cancelled |
| Writable target or oversized input | Channel rejected both inputs |

The eight existing actual-MCP test methods also passed in 17.124 seconds after
adding SSH. The nine native-sudo regression methods passed in 11.251 seconds.
Scoped Rust lint, formatting and diff whitespace checks passed; all test containers
were removed. CI includes the SSH suite; hosted CI has not been run for this change.

## What this does not establish

- No native execution-review app, fresh execution key, administrator pairing or
  Touch ID interaction participated. The signer is still a disposable fixture.
- The receipt reviewer and receipt keys remain separate; this channel does not
  turn a receipt into execution authority.
- Loopback across the Astra host/container boundary is not yet tested. The
  future trial needs a pinned host key, protected enrollment and signed reviewer.
- SSH forwarding is disabled in configuration, but forwarding attempts have not
  yet been exercised. Network outage and SSH resource-exhaustion tests remain.
- An actor controlling Docker can replace the entire test broker/container.
  This fixture cannot prove isolation from its Docker administrator. It tests
  the protocol under the stated trusted-broker assumption.
- A host pin authenticates a server, not its display labels or a human's intent.
  The native reviewer must use administrator-paired machine/account identity,
  display the frozen command and sign those exact bytes with fresh Touch ID.
- Nothing here establishes production readiness or changes the documented
  limitations of the native sudo adapter and output capture.
