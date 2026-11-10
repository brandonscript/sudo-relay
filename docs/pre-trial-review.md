# Review before a real-machine trial

November 9, 2026. Bounded Ponytail review of the main broker, execution/transport path, approval SDK/card, service packaging, and native-sudo prototype. Expected use: one pending operation per broker, potentially several sudoers on one machine. This is a first-party code review, not an independent audit.

**Verdict: continue in disposable Linux machines; do not install the prototype PAM stack on a personal or production machine.** The published broker and sudo authentication experiment are separate implementations. Passing tests on both does not establish that a combined system is safe.

## Must fix before live use

### 1. Sponsor revocation and installer binding are not in the shipped broker

The production configuration has agent/approver UIDs but no enrolled sponsor. `broker init` accepts those client IDs as arguments; `execution::run` launches the executable directly as the root broker. Removing the installing account's sudo permission therefore does not block subsequent signed broker commands. The native-sudo tests use simulated sponsor identities and do not exercise this installation or execution path.

Locations: [Config](../src/broker.rs), [initialization](../src/bin/broker.rs), [execution](../src/execution.rs).

Required change: integrate authenticated per-sudoer enrollment, distinct per-enrollment keys/state/socket access, early policy checks and launch through sudo as that enrolled identity. A sponsor name supplied by an MCP request or an unverified environment variable is not installation provenance. Root remains trusted; this cannot defend against an administrator replacing the broker itself.

Acceptance: real installer invocation by A binds A without an account selector; forged enrollment metadata and cross-enrollment approvals fail; removing A's grant or changing its command restriction after approval prevents launch while B still works. Include group-based revocation with old processes retaining group lists, account deletion/recreation, UID reuse and policy-backend failure. These integrated tests are still pending.

### 2. PAM can be skipped, and its success can create reusable authentication

New tests reproduced both cases inside the disposable container. NOPASSWD permitted an unsigned marker command despite `-k`. With five-minute global timestamps and `-k` omitted, a correctly approved command populated credentials used by a later unsigned command. Restoring `-k` made the latter request fail. The signature verifier did not accept a forgery: sudo skipped authentication.

Evidence: [eleven-case fixture and source](https://github.com/brandonscript/sudo-relay/tree/a134db5/security-lab/sudo-prototype). Both new tests explicitly characterize unsupported behavior; their passing status does not mean the gaps are fixed.

Required change: preserve independent signed approval/consumption in the trusted broker before every launch, including NOPASSWD paths. Keep the relay launcher from accepting or creating general reusable sudo authentication. Replacing the broker's approval gate with PAM authentication alone would break the one-approval-per-command requirement. Existing elevation permissions outside the broker are still outside its scope.

Acceptance: combined broker tests with NOPASSWD, pre-existing timestamps, nonzero timestamp defaults, omitted/altered launcher options and concurrent invocations. Every broker execution still needs a unique signed approval. An approved relay execution must not enable a subsequent unauthenticated ordinary sudo invocation.

### 3. There is still no protected human-signing integration to try

The reference HTTP host deliberately returns 403 for approval and holds no signing key. The card accepts its signing-host initialization only from a same-origin parent. That supports the local preview structure, not a demonstrated production chat host or remote/mobile signer. Giving the preview a key or loosening its origin check would not establish human presence.

Locations: [reference host approval handler](../ui/src/demo.ts), [card host channel](../ui/src/card.ts), [trusted-host interface](../ui/src/adapter.ts).

Required change: implement and review the real host's authentication and signing boundary. Authenticate the user and protect the request display, output choice and signature from the agent's tools and browser automation.

Acceptance: a real target host can display and approve the identical signed request; model tools, forged postMessage events, stale requests, another browser origin, reconnects and agent automation cannot sign. Test desktop/mobile accessibility and denial as well as success. This remains unimplemented.

## Additional tests to add

| Priority / case | Concrete setup | Required observation |
|---|---|---|
| Before native installation: rollback | Interrupt each installation step; break or remove the module; uninstall with requests pending. | Ordinary OS administration remains recoverable; relay fails closed; old approvals cannot resume. The container's global PAM defaults are not a production installation design. |
| Before macOS trial: ACLs and OpenPAM | On a disposable Mac, add an ACL granting the agent access to an otherwise root-owned/private key or state path; exercise native auth. | Reject effective unsafe access. Current mode/ownership checks do not inspect ACLs; Linux `/proc` binding is unavailable on macOS. |
| Before integrating scripts: policy/command correspondence | Review a script, replace its snapshot/interpreter/arguments, or permit only a narrower sudo command. | Displayed content and executed snapshot match; an interpreter/wrapper does not enlarge the sponsor's command permission. |
| Before relying on output privacy: native logs | Enable sudo I/O logging, share output off, emit fake canaries. | Broker sends no streams to agent; document any independently configured OS logging. Do not claim the checkbox suppresses all system logs. |
| Crash and disk failure | Terminate before/after approval commit, before/after PAM receipt commit, and during execution; fill the state filesystem. | No automatic retry, no double launch, explicit uncertain outcomes; no lost receipt silently authorizes replay. |
| Timeout resource cleanup | Approved harmless helper creates a short-lived separate-session descendant holding stdout; repeat a bounded number of times. | Record cleanup failure; establish bounds on remaining reader threads/FDs and safe shutdown. `execution.rs` currently drops unfinished reader JoinHandles, so a descendant retaining a pipe can keep that reader alive after a response. Not reproduced in this pass; process-group cleanup was already documented as best effort. |
| Audit completeness | Reject a signature, deny a peer, consume approval, fail spawn, and successfully launch. | Correlate broker request, sponsor/enrollment, approving key, sudo execution and outcome. The current `running` event precedes spawn, so it is not by itself proof of an OS command launch; rejected authorization paths are not all durable audit events. |
| Boundary timing | Hold the execution worker until after signed expiry or key revocation. | Define and test whether approval consumption or actual launch is the validity boundary. Current broker checks key and expiry at consumption; no promise of post-consumption revocation should be implied. |

## What was checked

Read the connected Rust authorization, state, execution and socket paths; TypeScript approval/display/host code; service definitions; prototype PAM module and harness; and existing test catalogue. Added and ran the two native-sudo characterization cases above plus all nine previous cases: eleven passed in 2.148 seconds on Linux arm64 with sudo 1.9.16p2. The container and throwaway credentials were removed. Production execution/authentication code was not changed by this review.

Not checked: independent review, real trusted host signing, production installation/rollback, macOS PAM/ACL behavior, current dependency advisories, sustained fuzzing, memory/core dumps, or every crash/race interleaving. Findings about unimplemented integration are design blockers, not newly discovered exploits in the signed-envelope verifier.

## November 10: contained prototype hardening

The [independent launch gate](https://github.com/brandonscript/sudo-relay/tree/751e259/security-lab/sudo-prototype) now verifies and durably consumes a signed grant before the fixture controller releases its waiting sponsor process. It checks the controller's separately retained command/identity/process record, enforces the fixed sudo invocation including `-k`, and rejects unprivileged gate calls. PAM redemption is a separate stage, so NOPASSWD cannot remove the controller's approval requirement. Lost children and denied launches do not refund consumed grants.

Fifteen local tests passed, including four new gate tests covering passwordless-rule bypass, missing/forged/expired/altered grants, consumption before release, lost-child reuse, unsafe launcher flags and nonzero timestamp caching. The new native-sudo Docker job also passed on the [GitHub Linux runner](https://github.com/brandonscript/sudo-relay/actions/runs/42773128688). The original two characterization tests intentionally bypass the controller gate to preserve the failing design's behavior. This is a prototype correction, not a production broker integration.

For the next design session: authenticated installer provenance and per-sudoer enrollment; integration of this gate with the real broker's CBOR approvals, scripts, audit and output sharing; and the protected chat signing host. Those three items remain open. No host authentication configuration was changed.

The [November 10 chat approval research and design](chat-approval-design.md) proposes an unprivileged passkey experiment first, documents the potential separate-page requirement, and lists unrun host acceptance tests. It does not resolve these blockers.
