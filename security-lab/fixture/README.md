# Disposable broker fixture

A small Linux sandbox for future security tests. It starts the real broker in production mode, with fresh throwaway keys and two numeric user identities. Starting it submits no commands and runs no tests.

Requires Docker Engine and Docker Compose. Run these commands from the repository root. The first build downloads dependencies and compiles Rust; later starts reuse the image.

```sh
docker compose -p approval-fixture -f security-lab/fixture/compose.yaml up --build -d --wait
```

## Use it

Read the fixture's paths and identities:

```sh
docker compose -p approval-fixture -f security-lab/fixture/compose.yaml exec -T sandbox cat /lab/fixture.json
```

Send a request as the agent, using the small JSON socket client:

```sh
docker compose -p approval-fixture -f security-lab/fixture/compose.yaml exec -T --user 10001:10001 sandbox \
  python /fixture/rpc.py '{"method":"execution_status","id":"example"}'
```

With no such request, the broker returns an error. The helper prints the response; future tests must assert its contents. It does not sign approvals or retry requests.

Use `--user 10001:10001` for agent actions and `--user 10002:10001` for approver actions. Omitting `--user` runs the fixture controller as container root; that role can inspect all fixture data and must not be used to simulate an agent.

| Item | Location or identity |
|---|---|
| Agent | UID 10001, group 10001 |
| Approver | UID 10002, group 10001 |
| Broker | Container root, production mode |
| Socket | `/lab/run/broker.sock` |
| Private signing key | `/lab/approver/key.pem`, approver-owned, mode 0600 |
| Paired public key | Key ID `fixture` in the broker trust store |
| Private state | `/lab/state`, root-only |
| Fake secret | `/lab/fake-secret`, root-only random text |
| Agent workspace | `/lab/agent`, agent-owned |

No account passwords are set. Keys and the fake secret are generated inside the container and discarded when it stops. There is no approval UI or signing service. The replay tests use the approver's key only for explicitly authorized controls; agent actions remain under the agent UID.

## Run the fixture tests

With the fixture running:

```sh
docker compose -p approval-fixture -f security-lab/fixture/compose.yaml exec -T --user 10001:10001 sandbox \
  python /fixture/test_smoke.py
```

The standard-library suite runs as the agent UID and checks:

- An unapproved marker-creation request stays pending without creating its file.
- The agent cannot open the signing key, fake secret, configuration, ledger, or trust key for reading.
- The agent cannot open those files for writing, either. No bytes are written.
- Knowing the matching number does not let the agent submit an approval; the broker rejects the peer identity before signature validation.
- Cancelling a request leaves it cancelled with no execution result or marker.

Each command-bearing case uses a unique marker and cancels any remaining pending request. A failed assertion returns a nonzero exit code. No approval is signed or granted. The file-permission cases require `PermissionError`; a missing accessible file is a failure, not a pass.

## Check enrollment without an execution service

This separate run does not start the broker listener, submit commands, create
private signing keys or use sudo. It invokes only `init`, `pair` and `revoke` in
a fresh container with the same isolation settings:

```sh
docker compose -p enrollment-check -f security-lab/fixture/compose.yaml build
docker compose -p enrollment-check -f security-lab/fixture/compose.yaml run --rm --no-deps -T --entrypoint python sandbox /fixture/test_enrollment.py
docker compose -p enrollment-check -f security-lab/fixture/compose.yaml down --volumes --remove-orphans
```

Five cases check that both unprivileged roles cannot pair/revoke, pairing refuses
to overwrite an existing key, administrator revocation removes it, writable
configuration/parent paths and agent-owned trust directories are rejected, and
pairing cannot overwrite a file through a pre-existing key symlink. Positive
controls check the installed public key's owner/mode and contents. A public test
vector replaces credentials. All five passed locally on Linux arm64 on November
10, 2026. The dedicated enrollment job also passed in [CI for `f1eb714`](https://github.com/brandonscript/sudo-relay/actions/runs/42929599816); this records that job, not completion of the whole run.

These establish specific CLI and filesystem checks, not protected human pairing,
sponsor provenance, live revocation enforcement, ACL handling, replacement races,
code-update policy or macOS behavior. The initial ownership test exposed a cleanup
error because container root lacks DAC override; the test now restores ownership
before inspection/cleanup. No container permission was broadened.

## Run approval replay and output tests

These tests need the fixture controller to launch subprocesses under both identities. Omit `--user` for this test file only:

```sh
docker compose -p approval-fixture -f security-lab/fixture/compose.yaml exec -T sandbox \
  python /fixture/test_replay.py
```

The controller submits requests as UID 10001. A subprocess under UID 10002 uses OpenSSL and the disposable approver key to sign the broker-provided payload and submit approvals. The controller does not read the private key. No signing endpoint or production signer is added.

The first two replay cases execute one approved, harmless script inside the container and verify exactly one appended marker line and one audit launch record. Then:

- Replaying the exact approval three times is rejected. A fresh request for the identical command also rejects the previous signature, even when its request ID and confirmation number are updated.
- A fresh request for a different script rejects the previous signature and creates no second marker file.

The third replay case keeps the same request ID, nonce, number and all other fields. Adding a replacement command to the valid approval message is rejected by the wire schema. Separate signatures for a changed executable and a changed argument both fail against the original stored request, with zero launches. Finally, the original approval succeeds and prints exactly `approved`. This isolates command binding from request-ID binding.

The output cases approve a script that reads the fake root-only secret into stdout/stderr, across all four combinations of sharing on/off and `output_needed` on/off. They check repeat status reads, nonzero exit status, no output in the ledger, rejected sharing-bit changes, rejected missing/non-boolean choices, and rejection of agent-supplied sharing in a request. The fixture-only `fixture-approval-payload` binary encodes the signed decision using the project's Rust CBOR library; it contains no key and exposes no service.

Rejected fresh requests remain pending with zero audit launch records, then are cancelled during cleanup. Marker files are also removed. Run the two test files sequentially because the broker allows only one pending request.

## Tear it down

```sh
docker compose -p approval-fixture -f security-lab/fixture/compose.yaml down --volumes --remove-orphans
```

This removes the container; no data volume exists. The build image/cache remains for fast reuse. Stopping or restarting discards tmpfs data, so every start generates new identities for the machine and signing key. Keep a container running to test broker restarts against the same ledger; container restarts are fresh fixtures.

For scripts, use a unique `-p` project name for each run and register `down` in a shell `trap` or your runner's `finally` block. Docker Compose's `--wait` returns only after the broker socket exists. Logs are available with `docker compose ... logs sandbox`.

## Setup verification

Checked creation, readiness, an agent-UID status request, and teardown. The missing-request status returned the expected broker error; no execution request was submitted. The built ARM64 image was about 206 MB, and the idle container used about 2 MiB of memory with one process. These are observations, not resource guarantees. All eleven fixture tests passed: five agent checks, three replay/substitution checks and three output-policy checks. The latter exercise successful approval, signature rejection from the approver account, and sequential replay protection. They do not cover concurrent replay, crashes, file replacement races, or process-memory inspection.

## Limits

Runtime limits: one CPU, 128 MiB memory, 64 processes, and 24 MiB of writable tmpfs. No network, published ports, host mounts, persistent volumes, or Docker socket. The filesystem is read-only except for the disposable mounts; only the capabilities needed by the fixture and broker are retained. The runtime contains Python, OpenSSL and the broker, with no Rust compiler, Node, or UI dependencies. These tools are intentionally available to future test cases.

This is a Linux application fixture, not a macOS test or a kernel-escape sandbox. Docker shares its Linux kernel; use a separate disposable VM for kernel/runtime testing. Fixture readiness is not a security verdict.
