# Native sudo authentication prototype

A disposable Linux experiment: can a signed, one-use approval satisfy sudo authentication while sudo still applies the sponsoring user's command policy and records that user in its log?

**Yes, for the tested Linux setup. This is not a production authentication module or a complete sudo-relay integration. Never install it on a real host.** The main broker remains unchanged and still has the documented sponsor-revocation gap.

## Run

From the repository root, with Docker running:

```sh
docker compose -p sudo-relay-pam-prototype -f security-lab/sudo-prototype/compose.yaml build
docker compose -p sudo-relay-pam-prototype -f security-lab/sudo-prototype/compose.yaml run --rm --no-deps prototype
docker compose -p sudo-relay-pam-prototype -f security-lab/sudo-prototype/compose.yaml down --volumes --remove-orphans
```

The container has no networking, ports, host mounts, Docker socket or persistent volumes. Runtime files and throwaway keys live on tmpfs and disappear when the container is removed. Unlike the broker fixture, it intentionally permits setuid elevation inside the container: testing native sudo requires it. The existing broker fixture retains its `no-new-privileges` setting.

## What it does

A root test controller simulates a future broker. It creates separate locked-password sponsor accounts and an approving identity. It launches a waiting unprivileged child as the sponsor, constructs the exact intended sudo invocation, and asks the separate approving identity to sign an Ed25519 grant. No password is generated, stored, supplied to sudo, or sent to an agent.

The grant binds a fixture machine identity, sponsor name and UID, process ID and Linux process start time, full invocation argv, expiry and nonce. The controller places the signed ticket in a root-only directory and releases the waiting child. The child executes sudo. A Rust PAM module verifies the signature, compares the grant to sudo's PAM user/remote-user and actual process argv, and commits a one-use receipt before reporting authentication success. Failed or uncertain launches do not recover that nonce. Sudo evaluates command authorization and writes its normal log. Authentication timestamps are disabled in this fixture.

Only the controller can place tickets. It is a simulated trusted component, not an MCP tool. The approving identity owns the private key; neither sponsor can read it. The prototype uses a separate signed JSON protocol rather than the production CBOR envelope and does not display a real human approval card.

## Verification

On November 9, 2026, all nine tests passed in 1.775 seconds on Linux arm64, Debian trixie, sudo 1.9.16p2. Rust formatting and Clippy with warnings denied also passed. The container was removed after the run.

| Case | Observed result |
|---|---|
| Valid grant for each of two sponsors | Root UID output; sudo log identifies the actual sponsor and command |
| Denied or unapproved request (no ticket) | No command side effect |
| Invalid signature, expired grant, wrong sponsor, machine, process start or argv | No command side effect |
| Exact approval copied to another process or sponsor | Rejected |
| Freshly signed grant reusing a consumed nonce | Rejected |
| Sponsor's sudo permission removed after signing, before releasing child | Request policy check and native launch deny; other sponsor still works |
| Command outside sponsor's allowed command rule, despite valid signed grant | Denied by sudo |
| Plain sudo invocation after an approved execution | Denied; no reusable authentication observed |
| Sponsor opens signer key/grant directory or tries writing a ticket | Permission denied |

Observed request policy checks were 3.5–6.5 ms. Sudo authentication, command launch and exit were 5.7–16.3 ms across these cases. These are a few local samples, not percentiles, a signature-verification microbenchmark, or a promise for LDAP/network policy backends. Human signing and ticket preparation are outside those launch measurements.

## What this does not establish

- No real chat host, MCP/broker integration, authenticated installer enrollment, persistent per-sudoer identity or account-replacement detection is implemented here.
- `/proc` process binding is Linux-specific. macOS/OpenPAM compatibility is untested.
- Existing `NOPASSWD` rules can skip PAM authentication, and real hosts may have cached authentication or other PAM stacks. A production broker must enforce signed approval independently on every broker launch; PAM alone is not that gate. This experiment does not change existing elevation routes.
- The fixture deliberately selects its PAM service globally inside the container. It does not validate coexistence with a real host's ordinary sudo authentication, MFA, remote policy, account-lock/expiry policy or installation rollback.
- Grants bind argv, not every file, environment dependency, interpreter action or executable's bytes. No scripts or production output-sharing flow are integrated.
- Tests cover revocation before sudo runs, not every revocation interleaving within sudo's own policy-to-launch interval. There is no claim of stronger atomicity than sudo provides.
- Crash/power-loss durability, PID reuse under hostile load, memory extraction, hostile kernel behavior, dependency auditing and independent review remain untested. No container-escape testing was performed.

The result supports further integration work. It does not remove any security limitation from the published alpha.

## Follow-up review: authentication shortcuts

Two additional characterization tests bring this fixture to eleven tests, all passing in 2.148 seconds. These two tests deliberately assert observed bypass behavior in unsupported configurations; they are not proof of protection:

- `test_known_limit_nopasswd_skips_pam_without_a_ticket`: a NOPASSWD rule allowed a marker command without any ticket, even through the usual `-k` launcher.
- `test_known_limit_cached_authentication_skips_pam_without_a_ticket`: with global five-minute timestamps and `-k` omitted, an approved launch populated credentials that allowed a subsequent unsigned marker command. The positive rejection control using `-k` ignored that cache and blocked the unsigned launch.

The original no-reusable-authentication result depends on the fixture settings and launcher flags. A production integration must enforce signed approval before every broker launch regardless of whether PAM runs, prevent relay authentication from warming general sudo credentials, and test both existing timestamps and NOPASSWD policies. These cases do not show a forged signature accepted by the module; they show the module being skipped. Ordinary pre-existing sudo permissions remain outside sudo-relay's interception scope.

## Independent launch gate

The default fixture path now calls a separate Rust `approval-gate` before releasing its waiting sponsor process. This root-only helper verifies the signed grant against a launch record retained separately by the controller, checks the waiting process's UID/start time, enforces the fixed sudo invocation including `-k`, and durably consumes a canonical nonce as `released`. PAM separately redeems the same grant as `consumed` if sudo requests authentication. No gate failure releases the process, and a consumed launch grant is never refunded after a lost child or denied sudo launch.

The gate and PAM share signature/expiry/envelope verification. Ticket data cannot choose the controller's expected sponsor or command. The two original shortcut tests deliberately bypass the gate in the test harness to preserve evidence of why it is needed; the gate binary has no bypass option and refuses unprivileged callers. The fixture's root controller remains trusted and is not a production MCP or enrollment interface.

On November 10, 2026, fifteen cases passed locally in 2.747 seconds. Four new tests establish:

- With NOPASSWD active, missing, forged, expired, wrong-command and wrong-sponsor grants fail at the gate; a fresh valid grant executes and creates a release receipt even though PAM is skipped.
- The gate accepts a grant once before process release. A second acceptance fails; losing the child after consumption does not permit a new process to reuse the nonce, even with a new signature.
- A sponsor cannot invoke the root gate successfully. A signed invocation omitting the required `-k` flag is rejected.
- With nonzero global timestamp caching configured, an approved gated launch does not warm the cache for a subsequent unsigned ordinary sudo command.

The fixture now runs in the prototype branch's Linux CI. No production broker, installer, PAM host configuration or chat signer is changed by this work. Earlier sections describe the original feasibility runs; the independent-gate tests address those specific shortcut cases only. The command timing printed by the fixture excludes the new gate subprocess, so it is not a measurement of total gated-launch overhead.
