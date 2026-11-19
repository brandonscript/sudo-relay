# Real MCP to sudo in disposable Linux

November 11, 2026. The milestone connects the actual unprivileged MCP server to
the actual Unix socket transport, the broker's signed approval/ledger logic and
the container-only native-sudo adapter. No host sudo/PAM configuration is changed.

## Boundary

The MCP process runs as agent UID 11004. A separate software test approver runs
as UID 11003, reads the broker-provided pending envelope, signs its canonical
execution decision and submits it over the same socket. The broker uses Linux
`SO_PEERCRED` to identify each caller. Unlike the earlier stdin adapter test,
this path does not assign a caller's role from its requested operation.

The fixture's root process manages setup and faults; it never supplies a fake
peer UID to the server. Its public-key setup and sudo-enrolled sponsors are the
same as the [previous milestone](integrated-sudo-milestone.md). Requests pass
through real JSON-RPC `initialize`, `tools/list` and `tools/call` messages to the
existing `mcp-server` binary. There is no approval tool.

`serve_sudo_lab` is an explicit feature-gated server entry point. It reuses the
production socket framing, peer checks, approval dispatch, execution worker and
status storage, replacing only the request policy check and execution adapter.
It is Linux/container-only, not selectable through configuration or a wire request.
The normal `broker` binary still uses its existing execution path.

## Acceptance tests

| Test | Required result |
|---|---|
| Actual MCP and socket identity | MCP exposes only request/status/cancel. Request remains pending until separate approval. A valid proof submitted by the agent UID is rejected; an unrelated UID with socket access is also rejected. The approver succeeds, native sudo records the correct sponsor, and MCP receives UID 0 output when sharing was approved. |
| Signed output choice | Flipping the sharing boolean after signing fails in both directions. With sharing off, both streams are empty and neither canary appears in MCP status, even with `output_needed=true`. With sharing on, stdout is capped at 1 MiB, stderr matches its canary and truncation is reported. Five off/on cycles cover the short-output regression. |
| Altered / receipt / cross-enrollment proofs | Signing altered command bytes, supplying a receipt-decision proof, or copying approval to another enrollment cannot execute either marker. |
| Concurrent approval | Two approver processes submit the same valid proof concurrently. Exactly one succeeds and sudo's marker-command launch count increases by one. |
| Cancellation and expiry | MCP cancellation makes later approval fail. An expired request remains expired without an outcome or launch. |
| Revocation and NOPASSWD | Revocation after request creation prevents launch and produces a failed outcome in MCP status; new requests fail the early check. NOPASSWD still requires a valid independent broker approval. |
| Approver disconnect and MCP reconnect | Approver sends one valid proof and closes without reading a reply. MCP disconnects/reconnects. The request completes once; replay fails without increasing native sudo's launch count. |
| Broker loss before launch | Pause after durable consumption, kill broker/adapter, observe MCP failure, then restart. State is uncertain, no marker exists and the approval cannot be reused. |

A consumed-approval reply is not a successful execution result. Completion and
any launch error are read separately through `execution_status`.

## Output capture finding

The first full run failed the output-length assertion: sudo exited successfully,
but only 1,032,192 bytes arrived from a fixed probe that emits 1,048,590 stdout
bytes. A bounded diagnostic reproduced short output in 4/15 MCP runs and 2/15
plain-sudo runs with I/O logging enabled. This places the observed loss before
MCP serialization; the exact upstream cause has not been established.

The container adapter now uses anonymous Linux RAM files (`memfd_create`) for
stdout/stderr instead of output pipes, then reads at most the output cap plus one
byte. These files have no persistent pathname and are closed after the request.
Fifteen diagnostic runs after this change each returned the expected 1 MiB cap,
13 stderr bytes and a true truncation flag. No sleep, relaxed assertion or retry
was added to hide missing output.

This is deliberately limited to fixed, bounded synthetic commands. A memory file
is not a general resource limit: arbitrary output-producing programs would need
an independently enforced memory/output policy before this adapter could ship.
The fixture enables sudo I/O logging separately; those administrator logs can
contain output even when sharing with the agent is off. The sudo project's
[upgrade notes](https://github.com/sudo-project/sudo/blob/main/docs/UPGRADE.md)
describe its interposed pipes when I/O logging is enabled; that documentation does
not independently confirm the cause of our observed short output.

## Reproduce

From the repository root:

```sh
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml build
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml run --rm --no-deps integration
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml run --rm --no-deps --entrypoint python3 integration -I /integration/test_mcp.py
docker compose -p sudo-relay-integrated -f security-lab/integrated-sudo/compose.yaml down --volumes --remove-orphans
```

Both suites run in fresh containers. Runtime has no network, ports, host mounts,
Docker socket or persistent volumes. See the [fixture README](../security-lab/integrated-sudo/README.md)
for the capability and installer-provenance restrictions. CI now runs both suites;
local success is not a hosted CI result.

## Still outside this milestone

- No human interaction, Codex/ChatGPT UI, Touch ID, passkeys or mobile host. The
  software signer is test-only; the resource HTML is an explicit inert fixture.
- No production switch to sudo, permanent installation, ordinary-host PAM/MFA
  coexistence or macOS sudo implementation.
- No new proof of portable installer provenance, UID/account-replacement safety,
  group-revocation atomicity, clock/snapshot rollback or power-loss recovery.
- No arbitrary commands, scripts, detached descendants or general memory bounds.
  The original three harmless commands plus one fixed output probe are allowed.
- Disconnect does not undo a consumed approval. Before commitment, a transport
  failure may leave a pending request; it does not grant approval. The tested
  approver-disconnect case deliberately sends a complete signed message first.
- No independent security audit. The earlier Astra receipt-only evidence remains
  separate; receipt-only signatures cannot authorize execution in this path.

## Final result

**Passed locally; stopped for review.** The final Linux arm64 / Debian trixie
run used sudo 1.9.16p2 and image
`sha256:97556cacf9cff22bbcb7946f36d674c711d67663ec544d014ad01855928dd107`.

- 8 real-MCP test methods passed in 15.821 seconds, including ten signed
  output-sharing requests and concurrent approval submissions.
- All 9 previous native-sudo integration methods passed again in 10.244 seconds.
- 15 existing Rust library tests passed with both lab features enabled; one
  standalone subprocess worker was intentionally ignored.
- Default binaries compile; formatting, scoped Clippy with warnings denied and
  `git diff --check` passed. No new dependencies were added.
- Hosted CI is configured for both container suites but has not run for these
  uncommitted changes.

All runtime containers were removed. Compose teardown and a project-label
inventory found no remaining containers. Runtime keys, ledgers, logs and RAM
capture files disappeared with the containers; build images/cache remain.
No host sudo/PAM configuration, real signing keys or installed services changed.

The next decision is a protected human-approval integration milestone, not a
personal-machine sudo installation. Do not promote the software test signer or
the bounded RAM capture adapter into production based on this result.
