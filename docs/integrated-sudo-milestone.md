# Disposable Linux sudo integration

November 11, 2026. Scope: connect real broker approval/consumption to native sudo
inside a disposable container, document the evidence, then stop for review.
No host sudo, PAM, signing-key or service configuration is changed.

## Acceptance and evidence

The new adapter calls the current `Broker::handle_current` and uses only its
returned execution job. The normal broker executable is not switched to this
path. Human approval is simulated with a disposable software key under a separate
approver UID; this run does not test Touch ID or a real MCP/chat connection.

| Case | Required and observed result |
|---|---|
| Enrollment and valid command, two sponsors | Real sudo installer invocation binds its caller despite forged incoming sudo environment values. Each signed request produces UID 0 output; native sudo logs the correct sponsor. |
| Agent access and installer impersonation | Agent cannot invoke the root controller/gate/installer or read human/internal keys. Direct root invocation with fabricated sudo environment but no sudo parent is rejected. Extra sponsor-selector argument is rejected. |
| Signature, command and enrollment binding | Forged signature, valid signature over altered command bytes, receipt-only proof, copied approval onto a new command, and copied approval onto another enrollment all fail. |
| Replay | Reusing a consumed approval fails. No fresh execution job is produced. |
| Denial and expiry | Cancelled and expired requests cannot launch. Expiry after consumption but before process release also prevents launch. |
| Competing controller | A second broker process cannot take the same state directory while the first holds its lock. |
| Sponsor revocation | Remove the grant after broker consumption and again after the early policy check, before releasing native sudo: neither launches the marker. Another sponsor still works. |
| Command policy narrowed | Narrow the grant after request creation: approval cannot launch the now-disallowed command. A new request is also denied early. |
| NOPASSWD | Forged broker approval still fails; valid approval works. Ordinary pre-existing NOPASSWD sudo remains available outside the broker, as intended. |
| Existing cached authentication | A separate positive control deliberately omits `-k` and uses an internal fixture ticket to create a real sudo timestamp; plain `sudo -n` confirms it works. That cache still cannot replace a broker signature. |
| No new reusable authentication | Clear existing timestamps, approve through the supported `-k` path with five-minute global caching configured, then try ordinary unsigned sudo: it fails and creates no marker. |
| Crash before launch | Kill controller/adapter after durable broker consumption: no marker. Restart classifies the request uncertain and rejects replay. |
| Crash after execution / response loss | Kill after marker creation but before reporting completion: marker exists, restart reports uncertain, replay fails, and sudo's launch count does not increase. |

Run commands and containment details are in the [fixture README](../security-lab/integrated-sudo/README.md).

## What this does not establish

- This root-only adapter is not a production agent-facing transport. It simulates
  peer roles at the broker library boundary. Wiring the protected native reviewer
  and actual MCP/socket transport into this path remains a separate milestone.
- Installer provenance is demonstrated for this monitored sudo invocation. The
  first run rejected enrollment without a readable sudo parent; the fixture now
  explicitly retains that parent and grants container-only inspection capability.
  Other sudo process modes, authentication stacks and installer recovery are not
  validated. NOPASSWD authorizes the fixture installer; no password-entry UX is tested.
- The fixture globally selects its experimental PAM service. Coexistence with a
  real host's PAM/MFA/account policy and macOS/OpenPAM is not tested.
- Account deletion/recreation, indistinguishable UID reuse, group-revocation races,
  external identity/policy providers and failures in those providers remain open.
  Current identity/groups are checked, but this does not provide stronger atomic
  revocation than the underlying OS/sudo policy evaluation. Policy can change
  after its last check; already-running approved code cannot be revoked here.
- Tests kill processes at deterministic points. Disk-full, power-loss, ledger/VM
  snapshot rollback, clock rollback, install interruption and durable recovery
  under those conditions are not covered.
- Only fixed harmless argv commands are allowed. Scripts, arbitrary environment,
  long-running commands, detached descendants, output-sharing integration and
  native-log privacy are excluded. The fixture enables sudo I/O logging; a sharing
  checkbox cannot suppress independently configured OS logs.
- No independent audit, container escape test or claim of production readiness.
  The signed reviewer's earlier hardware evidence remains separate from this
  software-signed Linux run.

## Result

The final local run passed **9 test methods (with the subcases above) in
10.765 seconds**, on Linux arm64, Debian trixie, sudo 1.9.16p2. The container
image ID was `sha256:cf84359507f874a0cfaff9bf018c6bc047f4f90587fea4fa2718c8a2168a4b4c`.

Rust formatting and Clippy with warnings denied passed for the new adapter.
The existing library suite passed 14 tests; one subprocess worker was intentionally
ignored as a standalone test. `git diff --check` passed. The restored PAM/gate
sources match commit `751e259` byte-for-byte. A dedicated CI job is added but has
not run on a hosted runner yet.

Earlier runs exposed fixture setup/verification issues: unavailable sudo-parent
inspection, a wrapped log line that the first attribution assertion did not
handle, and a cache test that initially lacked proof of a real usable timestamp.
The final run includes explicit parent inspection, wrapped-log parsing and a
positive cached-authentication control. No rejected authorization was changed
into success to make a test pass.

The runtime container was removed, followed by Compose teardown. A label-filtered
container inventory returned no remaining resources for this project. The image
and build cache remain; they contain code, not the runtime signing keys or ledgers.
No host sudo/PAM configuration was changed.

**Bounded milestone complete; stop for review.** This is evidence for the test
adapter, not permission to install the PAM prototype on Astra or another personal
machine.
