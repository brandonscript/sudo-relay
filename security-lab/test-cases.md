# Security test cases

## MCP host boundary

The [runbook](../docs/mcp-host-boundary-runbook.md) separates host permission prompts, custom cards and external pages, with manual H0–H9 cases and explicit inconclusive outcomes. `scripts/integration.mts --boundary-only` checks the current real MCP contract without approving or executing a command: confirmation number visible, no approval tool, request remains pending and is cancelled during cleanup. It does not test ChatGPT host isolation.

## Optional passkey approval experiment

The [approval host catalogue and verification record](approval-host/README.md#run-the-tests) covers 19 browser cases: passkey assertions, session approval, request/output binding, replay, expiry, denial, restart and UI behavior, including loading/unauthenticated states and waiting for the authenticator. It has no execution path. Two cases intentionally reproduce limitations: an authenticated session can be automated, and compromised review text can mislead despite valid passkey verification. They are not passing security guarantees. Manual enrollment and a subsequent real approval succeeded in ChatGPT's in-app browser, with one receipt and user-reported 1Password use. MCP integration remains unverified.

## Native Touch ID experiment

The [native probe catalogue](touch-id/README.md#checks-and-limits) distinguishes automated signature-binding/expiry checks from manual Secure Enclave enforcement, successive prompts and cancellation checks. The two software-key tests passed locally. The first real run rejected both noninteractive signing attempts and verified both interactive signatures; the user confirmed two separate successful Touch ID approvals. A third automated case checks that error logs omit authentication metadata. There is no command-execution path or persistent key.

## Native process identity experiment

The [XPC peer catalogue](xpc-peer/README.md) checks two ordinary-user processes:
three positive controls, rejected substituted clients/services, and an unsafe
direct-call characterization. All six expected outcomes were observed locally.
The unsafe case creates a transport receipt before the client rejects the reply;
a read-only handshake prevents the tested client from sending that operation to
the substituted service. These are transport receipts, not human approvals.
Writable fixture pins and absent protected enrollment remain explicit limits.

Record the tested source version, image ID, runtime limits, result, and evidence for every run. `PASS` means the expected rejection/control occurred, `VULNERABLE` means unauthorized capability was demonstrated, `ERROR` means the harness could not establish a result, and `NOT RUN` means no claim is made. Never relabel an expected limitation as a security pass.

## Regression checks after the baseline review

- `production_requires_distinct_unprivileged_identities`: production accepts distinct non-root UIDs, rejects equal or root UIDs; development still permits equal UIDs.
- `preview.test.ts`: start the preview with an invalid signing-key path (it must not load a key), fetch its public token, and submit a decision with matching HTTP headers. Expect HTTP 403 without contacting the broker or signing.
- Manual release check: from an agent account, attempt to read the production key and invoke every exposed signer operation. No operation may sign without independent human authorization. Not run: no production signer is shipped.

The older attack harness below targets the pre-fix signing host and same-UID configuration. Its exploit-success expectations are historical, not regression acceptance criteria; it has not been rerun for these fixes.

## Disposable fixture tests

Run `fixture/test_smoke.py` as UID 10001 using the [fixture guide](fixture/README.md). Requests go to the real production-mode broker over its Unix socket.

| Test | Attempt | Required result |
|---|---|---|
| `test_unapproved_command_stays_pending` | Request a unique marker file with no approval. | Accepted request remains pending, no outcome, no marker. |
| `test_agent_cannot_read_protected_files` | Open the approver key, fake secret, config, ledger and trust key as the agent. | Every open raises `PermissionError`; contents are never read or printed. |
| `test_agent_cannot_open_protected_files_for_writing` | Open the same files in append mode without writing bytes. | Every open raises `PermissionError`. |
| `test_agent_cannot_self_approve_even_with_matching_number` | Submit the correct request ID, key ID and number with a dummy signature as the agent. | Peer identity rejected; request still pending; no marker. This checks the identity gate, not signature verification. |
| `test_cancellation_keeps_command_unexecuted` | Cancel a pending marker request. | Cancelled status, no outcome, no marker. This does not test a later valid signed approval. |

Command-bearing tests cancel pending requests on cleanup. These checks are narrow observations, not a claim that all secret access or unauthorized execution paths are prevented.

## Approved-command replay tests

Run `fixture/test_replay.py` as the container's fixture controller, which drops to the actual agent and approver identities for requests and signing. The first two tests begin with a successful signed execution, a single appended line, and exactly one launch in the protected audit ledger.

| Test | Attempt | Required result |
|---|---|---|
| `test_replay_and_identical_new_request_cannot_reuse_approval` | Replay the exact consumed approval three times as the approver. Then request the identical command again and reuse the old signature with the new request ID and correct new number. | Exact replays fail as not pending; transplant fails signature verification. Original marker and audit launch count remain one; fresh request stays pending with zero launches. |
| `test_approval_cannot_run_a_different_command` | Create a request for a different script and transplant the old signature, using the new request ID and correct number. | Invalid signature; new request pending, zero launches, no different-command marker. Original execution remains one. |

The third case, `test_same_request_cannot_substitute_command`, starts with a valid approval for `/usr/bin/printf approved`. Injecting a replacement `spec` into that approval fails schema validation. Signing a payload with only the executable changed to `/usr/bin/whoami`, or only the argument changed to `tampered`, fails signature verification against the stored request. ID, nonce, number, timestamps, environment, reason and limits stay unchanged. Each rejection leaves the original pending with zero audit launches; submitting the untouched approval then prints exactly `approved` with one launch. Equal-length, unique byte replacements preserve CBOR text lengths without adding a serializer to the fixture.

The first two cases test consumption and binding to a fresh request, including a different command. They do not independently isolate each signed field: the transplanted request also has a different ID and nonce. Concurrent replays and crash recovery are outside these two cases. Only throwaway fixture keys are used; production human-attestation remains untested.

## Output sharing cases

The Docker output cases run alongside the replay cases in `fixture/test_replay.py`. Only the approver UID signs the explicit choice; the agent reads results through the broker.

| Case | Attempt | Required result |
|---|---|---|
| `test_output_is_shared_only_when_approved_even_if_agent_needs_it` | Emit the root-only fake secret to both streams and exit 7, with sharing on/off crossed with `output_needed` on/off. | Exit status preserved. Secret present only when sharing is approved; streams empty otherwise. Repeated reads and a later opt-in never disclose earlier withheld output. No output in the ledger. |
| `test_output_choice_is_required_boolean_and_bound_to_signature` | Flip a signed choice in either direction; omit it; send a string, integer or null. | Rejected before consumption. Original valid choice still works. |
| `test_agent_cannot_set_sharing_in_execution_request` | Put `share_output:true` in the requested spec. | Schema rejection, no execution. |
| Rust `signed_output_choice_cannot_be_changed_or_omitted` | Flip the signed sharing choice or the request's output-needed hint; omit consent. | Rejection; original approval remains usable. |
| Rust `broker_enforces_output_choice_even_when_agent_needs_it` | Worker returns secret strings even with sharing off; then restart. | Broker strips streams/raw diagnostics for off, preserves exit status; only approved sharing returns content. Choice survives restart, output does not. No secret output in ledger. |
| Rust `capture_disabled_discards_both_streams_but_keeps_exit_status` | Emit both streams with capture disabled. | No retained stream content, exit code intact. |
| Rust `old_ledger_gets_withholding_default` | Open a ledger without the new sharing column. | Migration succeeds with sharing false. |
| UI/SDK | Default, saved off/on, agent-needed hint, denial, Enter submission, malformed input, changed sharing signature. | Host preference controls checkbox; no agent field forces it on; checkbox remains editable when needed; the explicit boolean is signed. Denial never signs. |
| Preview parent host | Check, reload, uncheck, reload; send wrong-source or non-boolean preference messages; deny local storage. | Valid human-source choices persist; invalid messages do not change preference; blocked storage defaults off on a fresh host. No signing capability. |
| Real MCP integration | Sign an output-needed request with sharing off, then read its completed status through MCP. | No stdout/stderr or private markers in the MCP response; exit code 7 preserved. |

Run commands: [fixture guide](fixture/README.md), [contributor checks](../CONTRIBUTING.md). Not covered: memory scraping, macOS privileged integration, a production trusted human UI, or exfiltration through files/network by approved root code.

## Automated attack cases

The implementation is `lab.py`. Each output record uses the ID below. The attacker has ordinary shell execution as the agent UID unless another role is explicitly named.

| ID | Attempt and expected behavior | Evidence to retain |
|---|---|---|
| LAB-01 | Inspect sandbox before attacks. No host directories/Docker socket/external route may be present. | Runtime flags, image ID, route/mount checks. |
| KEY-01 | Agent reads the approver's private key, root trust store, ledger, config, and root-only fake password. Every read must be denied. | Per-file denial results; never secret contents. |
| AUTH-01 | Submit a valid execution request without approving it. It must remain pending with zero launches. | Request state and audit launch count. |
| AUTH-02 | Send a genuine captured signature directly from the agent UID. Separate-UID broker must reject the peer role. | `peer cannot approve`, zero execution. |
| AUTH-03 | Send an all-zero signature through the approver transport. Verification must reject it. | Invalid signature error. |
| AUTH-04 | Use `../host` as the key ID. Broker must reject traversal. | Invalid key ID error. |
| AUTH-05 | Add an `uid` field to spoof peer identity. Schema/kernel identity must reject it. | Schema rejection; no launch. |
| AUTH-06 | Try every two-digit code without signer authority. No code may grant execution. | 90 attempts, zero launches. |
| WIRE-01 | Feed malformed JSON, duplicate fields, invalid UTF-8, and 128 seeded random byte messages. All must fail closed; broker must remain alive. | Seed, count, errors, liveness. |
| WIRE-02 | Send a request exceeding 64 KiB. It must be rejected before dispatch. | Size rejection/reset and broker liveness. |
| WIRE-03 | Open a partial request and stop sending. The total deadline must close it. | Elapsed time below bounded threshold. |
| PATH-01 | Point an agent-writable symlink at a trusted executable. Original writable path must still be rejected. | Protected-path rejection. |
| ENV-01 | Request `LD_PRELOAD` injection. Unknown loader environment must be rejected. | Environment rejection. |
| AUTH-07 | Submit an approval after cancellation. It must never launch. | Not-pending error. |
| AUTH-08 | Send 16 copies of one valid, explicitly authorized fixture approval concurrently. Exactly one may consume and launch. | Accepted count and one audit launch. |
| AUTH-09 | Resubmit an identical command, replay the old signature, then transplant it to the new request ID. New work must remain unapproved. | Replay/transplant rejection, zero fresh launches. |
| AUTH-10 | Restart the broker with a pending signed request, then submit its old approval. Restart must cancel pending work. | Cancellation/not-pending, zero launches. |
| KEY-02 | Configure production with agent UID equal to approver UID. Agent reads the user-owned signing key and signs directly. Production should reject the configuration or independently require trusted user presence. | Accepted insecure config, key access, command UID 0 without human action. |
| HTTP-01 | Submit from a foreign browser origin without valid CSRF headers. Reference host must reject it. | HTTP 403. |
| HTTP-02 | Agent shell fetches public `/host.js`, reads its CSRF token, spoofs HTTP Origin, and calls `/approve` with the known request number. Different-UID signer must not act without a human. | Attacker UID, signer UID, no human action, root command UID, fake-password canary digest match. |
| KEY-03 | Inspect password handling. Broker/signer must not accept, derive keys from, or store the OS login password. | Source inspection and fixture inventory; no claim of real password cracking. |

## Existing automated regression cases

Run the Rust and TypeScript suites separately as described in CONTRIBUTING.md. They cover signed command/reason/timeout/machine changes, invalid keys, expiry boundaries and configuration limits, cancellation/approval races, durable consumption/restart recovery, state ownership, script snapshots, output/timeout bounds, audit capacity, display quoting, stale UI responses, and keyboard form submission. These are distinct from external attack coverage; unit tests are not evidence of OS isolation by themselves.

## Manual or additional lab cases

| ID | Prerequisite and procedure | Expected result / current status |
|---|---|---|
| MAC-ACL-01 | Disposable macOS VM only. Give the agent an allow ACL on a root-owned mode-0700 broker directory or mode-0600 key; compare `stat`, `ls -le`, and attempted writes/reads as the agent. Then try production startup/key access. | ACL access must be rejected or removed by deployment. **NOT RUN**; owner/mode checks alone do not inspect macOS ACL entries. |
| MAC-PEER-01 | Disposable macOS VM. Run broker and signer under separate accounts; repeat AUTH-02/KEY-01/HTTP-02 against launchd packaging. | Same UID/key/API boundaries must hold. **NOT RUN** in this Linux lab. |
| HOST-UI-01 | A real integrating chat host, with fake keys. Try invoking signing from model tools, injected messages, another origin, or browser automation. | Only trusted user interaction may sign. **NOT RUN**; the reference harness is not a certified host integration. |
| CRASH-01 | Disposable VM/container with deterministic fault injection. Crash immediately before and after consumption commit, before spawn, and after spawn but before completion. | Never relaunch consumed work; report uncertain outcomes. **Unit-state coverage exists; exact process-crash timing NOT RUN** here. |
| CLOCK-01 | Disposable VM only. Move wall clock backward/forward while pending. | Document clock dependence; expired requests must not gain unintended lifetime. **NOT RUN**; no host time changes. |
| DISK-01 | Small disposable disk/tmpfs. Exhaust space during journal/consumption commit and completion recording; repeat after restart. | Fail closed before launch; never retry uncertain executions. **NOT RUN** beyond fixed audit-capacity unit test. |
| SECRET-01 | With only fake canaries, inspect application logs, process arguments/environment, outputs, and core-dump policy before and after approval. | No private-key/login-password disclosure. **Filesystem and HTTP paths automated; full memory/core-dump analysis NOT RUN**. |
| DEPS-01 | Resolve the exact Cargo/npm lockfiles against current authoritative advisories; review reachable findings. | Triage findings separately from application exploits. **Separate dependency review required; not established by passing tests.** |
| KERNEL-01 | Dedicated disposable VM with no host integration, outside this harness. | Container/kernel escape testing is **OUT OF SCOPE** for this run. |

## Remediation acceptance cases

After fixes, rerun HTTP-02 expecting rejection without creating a signature or root command, KEY-02 expecting startup rejection in production, and MAC-ACL-01 expecting the deployment check to catch effective access. Keep the prior reproductions as regression tests. Re-run positive controls so denying all work cannot masquerade as a security fix.

## Sponsor enrollment and live sudo policy (planned; not implemented)

Run these cases only in disposable machines with fake accounts and credentials. Existing passing tests do not cover them.

- Enroll through the supported sudo installer as account A. Verify the recorded sponsor is A; no MCP field, CLI sponsor selector or unprivileged file edit can select B. Reject direct-root or ambiguous enrollment provenance rather than guessing.
- Enroll A and B on the same machine. Give each separate agent/approver identities, sockets, keys, state and enrollment identity. Verify A cannot submit, inspect, cancel, approve or replay B's requests, and vice versa. Shared agent UIDs are not isolation.
- Remove A's permission before requesting a command: reject the request. Confirm B's permitted enrollment still works.
- Create a pending request for A, remove permission, then submit an otherwise valid approval: no command side effect. Repeat after consumption but before launch using a deterministic test barrier.
- Allow A one specific executable/argument combination and deny another. Check the exact command, target root identity and relevant policy constraints rather than group membership or the existence of any sudo grant.
- Delete or replace A, change its UID, or reuse its old UID. Fail closed on identity mismatch; require fresh authenticated enrollment. Verify renaming/account recovery semantics explicitly on each supported OS.
- Make policy evaluation unavailable, time out, or return malformed results. No launch; preserve an auditable failure and never retry consumed approvals automatically.
- Attempt to switch sponsor in protected metadata. Unprivileged modification must fail; mismatch with existing state/approval identity must fail closed. Root compromise remains outside the boundary.
- For launch through native sudo: revoke permission at the launch barrier and verify sudo denies execution. Verify authentication occurs only through the trusted human host and secrets never enter MCP messages, output capture, logs or the agent's process environment.
- If a check-then-launch implementation is selected instead: demonstrate and document its residual race; never describe it as atomic revocation enforcement.
- Measure request and launch policy-check latency with allowed and denied commands, without caching authorization across requests. Record OS, sudo version, policy backend and percentile timings.

### Native sudo prototype result

An isolated Linux experiment now covers signed one-use PAM authentication, two sponsor identities and native sudo attribution, revocation between signing and launch, exact command-policy denial, absent/invalid/expired/mismatched approvals, cross-process replay, consumed nonce reuse, lack of reusable authentication, and signer-key/grant access denial. All nine cases passed. Source and exact exclusions: [prototype test record](https://github.com/brandonscript/sudo-relay/tree/4b86659/security-lab/sudo-prototype). This is separate from the production broker; the planned enrollment/integration cases above are still pending.

## Pre-trial review follow-up

The [pre-trial review](../docs/pre-trial-review.md) records blockers and concrete acceptance cases for installer provenance, per-sudoer enrollment, group/account revocation, native authentication shortcuts, real host signing, installation rollback, macOS ACLs, script policy, OS output logging, crash recovery, timeout resources and audit correlation.

Two additional native-sudo characterization tests are implemented at [prototype commit a134db5](https://github.com/brandonscript/sudo-relay/tree/a134db5/security-lab/sudo-prototype). They demonstrate that NOPASSWD can skip PAM and that omitting cache isolation with nonzero timestamps can allow subsequent unsigned execution. These tests deliberately assert the observed unsupported behavior. All eleven prototype tests passed; the corresponding combined broker defenses remain unimplemented.

### Independent gate acceptance (prototype only)

At [prototype commit 751e259](https://github.com/brandonscript/sudo-relay/tree/751e259/security-lab/sudo-prototype), four additional tests cover the root-only pre-launch gate: NOPASSWD with invalid/absent grants plus a valid positive control; durable single consumption and lost-child nonce reuse; sponsor invocation and missing cache-isolation flag; and lack of cache warming under nonzero global timestamp defaults. Fifteen local tests passed and the native-sudo CI job passed. Two characterization cases deliberately bypass the gate to document PAM-only weaknesses. The published broker's integration and authenticated enrollment remain pending.

## Enrollment filesystem checks (implemented; no execution service)

`fixture/test_enrollment.py` runs five controller-managed cases in a disposable
Linux container. Both agent and approver UIDs are denied production pairing and
revocation; administrator pairing is non-overwriting and revocation removes its
key; group/world-writable configuration or parent paths and agent-owned trust
directories are rejected; a pre-existing key symlink cannot overwrite its target.
Positive controls check exact public-key contents and root-only permissions.
Only a public test vector is used. No request, signer, listener or command runner
starts. Five local cases passed November 10, 2026. This does not establish sponsor
provenance, ACL safety, races, live revocation or protected native enrollment.

## Cross-host authorization isolation (implemented; no execution)

`four_hosts_isolate_colliding_requests_and_key_revocation` in `tests/security.rs`
opens four independent development-mode brokers and trust stores, all using the
same disposable test key. The test controller inserts deliberately colliding
pending envelopes: identical request ID, nonce, number, timestamps and command;
only the machine UUID differs. Each of the twelve cross-host deliveries must
fail signature verification, leaving its target pending. Revoking the first
host's key blocks its own valid approval while the other three still accept
their own approvals once and reject replay.

The test inspects returned authorization jobs and never invokes execution or a
socket listener. It passed locally on November 10, 2026. This isolates signed
machine identity and independent key/consumption state; it does not establish
MCP multi-target routing, authenticated display labels, sponsor isolation,
network transport, machine replacement or safe enrollment recovery. Collisions
are controller-created fixtures, not an exposed request-editing endpoint.

## Native model and durable receipt verification (implemented; no execution)

Run `sh security-lab/native-protocol/check.sh` on macOS as an ordinary user.
The fixture creates temporary state, a software CryptoKit key, and a separate
Rust verifier with no executor call. See the [runbook](native-protocol/README.md).

- NP1: Validate broker JSON with the Rust bridge; compare the complete model and
  both sharing decisions with public vectors. Wrong machine, invalid fields,
  mismatched payload/digest, expiry and insufficient buffer reject.
- NP2: Render argv and script models in the existing native form without showing
  a window. Preserve script body/interpreter, environment and request details;
  expiry disables approval/sharing and changes Deny to Close.
- NP3: Submit a native-model P-256 proof to the separate broker verifier. Flipping
  output sharing rejects; the unchanged proof consumes once; immediate replay
  rejects. A canary command's target file must not exist.
- NP4: Terminate and restart the verifier using the same SQLite state. Status is
  `uncertain`; the old approval still rejects. The same proof cannot authorize a
  fresh request, even when its request ID and confirmation number are replaced.

NP1–NP4 passed locally November 10, 2026. The subprocess is a test-controlled pipe,
not authenticated production IPC. No hardware authentication, protected enrollment,
lost-reply recovery, ledger rollback or real execution was tested here.

NP5: `python3 security-lab/xpc-peer/check.py` now includes `durable-review`.
After authenticating the XPC service, it retrieves the production broker model,
signs its exact decision with a software key, and reaches the durable Rust
verifier through the service. One approval consumes; altered sharing and replay
reject; status is `consumed`; canary remains absent. Ten XPC cases pass locally.
This is not runtime child identity protection, administrator enrollment or a
hardware-signing test. See the [XPC limits](xpc-peer/README.md#durable-broker-path-through-xpc).

NP6: The XPC suite pins the bundled verifier child separately. A changed child
with its new pin accepts one test receipt; the same child with the old pin and
a missing-pin case both fail before ledger creation. Valid child processes also
pass identity checks before each request. Thirteen cases pass locally. Dynamic
replacement, launch races, injection and protected path ownership remain open.

NP7 (hardware check pending): prepare a fresh app with `--prepare-native-durable`,
then coordinate with the participant before opening it. Verify the displayed
request, choose output sharing, approve with Touch ID, and inspect the matching
consumed ledger entry and absent canary. Repeat denial, fingerprint cancellation
and expiry in separate fresh fixtures. No extra success/cancellation dialog should
appear. The app's selected protocol is sealed in its bundle; failures must not
switch to the old JSON verifier. Build and software acknowledgement checks pass,
including wrong-request and malformed acknowledgement rejection; this does not
count as a hardware pass.

## Clock boundaries (implemented; no execution)

- `approval_before_creation_rejects_without_consuming_the_request`: present an
  otherwise valid signature one second before its signed creation time. It must
  reject and leave the request pending. At creation time, that proof consumes
  once; a subsequent replay rejects. This test failed before the broker guard.
- `observed_expiry_stays_terminal_after_clock_rollback_and_restart`: observe the
  expiry boundary, then supply an earlier time, restart the broker and try again.
  The state stays expired and the proof never produces an execution job.
- The adapter test moves its mocked clock before creation or beyond expiry while
  signing is pending. Neither returned signature is submitted to the broker.

These pass locally. Rust tests supply time to `Broker::handle`; TypeScript tests
temporarily mock `Date.now`. No system clock changes or command execution occur.
They do not establish monotonic lifetime enforcement while a rollback remains
inside the valid interval, nor suspend/resume, snapshot or ledger-restore safety.

## Protected policy-file prerequisites

- `protected_reads_reject_user_owned_policy`: a policy created by the ordinary
  user must fail the protected reader. Passes locally; no service or command runs.
- `protected_reads_reject_unsafe_or_unbounded_files`: on disposable root CI only,
  read an exact-limit valid file; reject an oversized file, invalid limits, a
  directory, FIFO, writable file/ancestor and non-root owner. No broker is started.
- `root_owned_paths_reject_acl_writable_ancestors`: on disposable macOS CI only,
  verify both path checking and bounded reading reject an ACL on the file or its
  parent, then accept again after that fixture ACL is removed.

Root-only cases are not personal-machine verification. Root-concurrent file
replacement and native enrollment policy integration remain separate work.

### Native peer-policy loading

- A bundle explicitly marked `SudoRelayReceiptFixture` loads the disposable policy.
- An unmarked bundle with no protected path rejects that same file.
- A protected path that is missing, wrong-typed or points to the user-owned fixture
  rejects, even if the fixture marker and valid fixture policy are also present.
- The C bridge leaves output unchanged for invalid paths and insufficient capacity;
  a valid protected read returns only the file bytes and leaves the buffer tail
  unchanged. Positive protected reads run only in disposable root CI.

Swift negative/fixture controls, Rust invalid-path tests and all thirteen XPC cases
pass locally. The earlier protected-reader root cases passed Linux/macOS CI run
42938600587; the newly added C ABI positive controls await their own CI run.
No protected native enrollment or hardware approval is established by these tests.

### Peer-policy revocation on an existing connection

After the identity handshake, obtain a request and create its valid disposable
software signature. Before submission, independently replace each peer requirement
(client, service, verifier), remove policy, or replace it with invalid JSON. Each
submission must reject. Restore the original file and retry: still reject; neither
a new review nor a direct test receipt may be issued by that service instance.

For the durable path, create a broker request and valid CBOR proof, remove policy,
and submit through the existing XPC channel. Restore and resubmit. Both return no
receipt; a read-only SQLite check finds one pending request and zero consumption
audit entries, and the canary remains absent. This also exercises stopping the
verifier child on observed invalidation.

All six new cases and the thirteen existing cases pass locally. The policy files
are deliberately user-owned fixtures; protected-file enforcement is tested
separately. Between-check changes, revocation/consumption races, service restart
and policy rollback are not covered by these results.

### Protected P-256 enrollment and key re-pairing characterization

`protected_p256_enrollment_and_revocation_without_execution` runs only in
disposable root CI. Initialize a protected store, reject pairing/revocation as
either client UID, reject an invalid P-256 point, pair explicitly as administrator,
verify owner/mode/algorithm, and reject replacement. Freeze a request and sign it
with a disposable software key; removing the key must reject that proof without
consumption. No broker service or executor is started.

The original unsafe re-pairing control accepted an old pending proof in disposable
Linux/macOS CI run 42939967725. It is now a rejection regression: revocation must
leave that request cancelled; re-pairing still rejects it; a newly created and
signed request consumes once. Returned jobs are dropped, never executed. The revised
root case awaits its own CI run; local compilation/lint pass.

Local receipt-only regressions also pass:

- `enrollment_revocation_repair_requires_fresh_request`: old approval rejects after
  revocation and after re-pairing; a fresh request provides the positive control.
- `enrollment_interrupted_file_cleanup_cannot_restore_revoked_key`: recreate the
  leftover key file after a durable denial marker. Approval rejects before/after
  broker restart; retrying revocation removes the file. This simulates a crash
  state, not an actual power failure.
- `enrollment_revocation_and_approval_have_one_commit_order`: race both operations
  eight times. A successful consumption must precede revocation in the audit;
  otherwise the request is cancelled without consumption. No executor is called.

These results do not establish sponsor provenance, hardware authentication,
rollback resistance, or recall of jobs consumed before revocation.

`approval_rechecks_time_after_lock_and_before_consumption` supplies a deterministic
clock that crosses expiry while acquiring the transaction, crosses expiry after
verification, or moves before creation before consumption. Each produces no job;
a valid-time positive control still consumes once. Both live transports use the
current-clock entry point. This checks decision-time validation, not system clock
rollback prevention, storage stalls after validation, or physical power loss.

### Killed pairing and revocation processes

`killed_enrollment_processes_stay_blocked_until_explicit_recovery` runs as an
ordinary user with disposable keys and four child processes. Each child stops at
a test-only checkpoint, then the parent sends SIGKILL and verifies termination:

1. Pairing has committed its denial marker but has not created the key file.
2. Pairing has synced the new key file but has not enabled it in the ledger.
3. Pairing has cleared denial inside an uncommitted transaction.
4. Revocation has committed denial but has not removed the key file.

The original broker stays alive while the child dies, so startup cancellation
cannot hide an enrollment failure. In each case the old request is cancelled and
a fresh proof is rejected. Repeat after broker restart, then explicitly revoke
and pair: only a new request may consume once. Every returned job is dropped.

All four cases pass locally. The pause controls compile only under `cfg(test)`;
normal broker and receipt-verifier artifacts were checked for their absence.
These are real process deaths and SQLite recovery checks, not power cuts, storage
faults, snapshot rollback or protected native-key enrollment tests.

### Protected receipt socket and separate client identities

With `native-receipt-lab` enabled, the protected P-256 root test also starts a
receipt-only socket worker on the disposable CI machine. It uses the normal
framing, peer-UID checks, protected root store and ledger. The receipt dispatch
path drops every approved job; it never calls the executor. No new production CLI
mode or service installation is added.

The agent UID submits a canary request but cannot approve or read the approving
UID's private fixture file. The approving UID receives only a request ID, retrieves
the frozen envelope directly from the root socket, checks its machine UUID and
signs with the paired P-256 fixture key. One consumption succeeds; replay fails;
status remains consumed with no execution outcome and the canary absent. Foreign
UID and root-as-client requests reject. Test keys are deliberately known software
fixtures, not evidence of hardware protection or cryptographic secrecy.

`call_protected` checks root-controlled parents, a root-owned socket and the peer's
root UID before sending request bytes. Its local negative test rejects a user-owned
socket before connecting. Compilation and lint pass with and without the lab
feature; the new protected roundtrip awaits disposable Linux/macOS CI. Actual
Swift/native UI integration with this root socket remains open.

### Native protected fetch bridge

The protected socket test now retrieves the pending envelope through
`sudo_relay_fetch_review`, the same C ABI used by the native review model. Wrong
machine pins and unknown IDs must fail; insufficient output capacity must return
its distinct failure code; all failures leave sentinel-filled output unchanged.
The valid positive control returns the exact root-broker request used for signing.
These additions await disposable root CI. The preceding socket roundtrip passed
full CI run 42942110672.

Local Rust tests reject null/malformed/relative/unknown-field reference input with
no output; the Swift model rejects an unprotected endpoint without fallback. The
operation fetches only; no approval submission is available through this API.
Trusted enrollment of the socket/machine pin and native hardware use remain open.

### Root-owned receipt enrollment record

The root socket fixture now creates a bounded versioned record with its socket,
machine UUID, approver UID and fixture display labels. Agent UID must fail native
fetch with that record and leave output untouched. Approver UID must reject a
wrong-account record, wrong-machine record, writable record, unknown request and
small output buffer, then accept the protected positive control. Sign the exact
withheld-output bytes returned by the bridge; root consumption and replay checks
remain in the same fixture. These new cases await disposable CI.

Local schema tests reject invalid versions, non-receipt mode, root/wrong approver,
relative sockets, invalid UUIDs, misleading/oversized labels and unknown fields.
Server responses without a literal boolean receipt-only marker also reject, with
a valid positive control. These tests do not establish real sponsor identity or
protection against account-UID reuse. The prior fetch API passed full CI run
42942654110 before the enrollment-record change.

### Headless Swift reviewer under the protected approving account

Enrollment-record cases passed full CI run 42943601838. The next macOS root
fixture invokes the actual Swift `BrokerReview` initializer as the separate
approving UID, with only a protected enrollment path and request ID. Compare its
rendered command, labels, number and both decision payloads against the broker's
frozen request. Submit its CryptoKit P-256 signature and require one consumption,
replay rejection and no canary file. The agent UID must fail with empty stdout.

This helper uses a deliberately known software fixture key, no AppKit and no
authenticator. Local compilation, lint and missing-opt-in/missing-enrollment
negative controls pass. The positive cross-account Swift path passed the macOS
root job in CI run 42944467261; the Linux root job also passed. Other jobs were
still running at this checkpoint. It does
not establish native window integrity, Touch ID protection or installed identity.

### Enrolled signer identity before signature generation

Native receipt enrollment now requires a valid P-256 public key. Local tests reject
a missing key, malformed encoding, an off-curve point and the other supported
algorithm. Swift rejects key verification when using the older unprotected
fixture constructor. The disposable macOS root test supplies a valid but different
enrolled public key and requires the headless signer to fail with empty stdout;
then the correct pin must retain the positive consumption/replay control. These
new root cases await CI. Local Rust tests, Swift checks/build and strict lint pass.

This pins which public key the protected native flow expects. It does not store
or protect a private key, prove hardware authentication, or atomically synchronize
a changed enrollment with a pending native review. The broker still checks its
current trust store and revocation state before consuming a signature.
