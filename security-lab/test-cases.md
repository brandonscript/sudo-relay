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
