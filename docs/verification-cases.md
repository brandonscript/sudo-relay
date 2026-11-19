# Verification case registry

Use these IDs in test results, regression reports, and private vulnerability reports. They identify reproducible checks behind the README's verification claims. The linked evidence records historical outcomes; assigning an ID does not constitute a new run.

## Naming and scope

Client cases use `<client>-<client-major>-<workstation-os>-<target-os>-<feature>-<number>`. For example, `codex-26-macos-ubuntu-touchid-001` identifies a Touch ID case for Codex major version 26, approving on macOS and executing on Ubuntu. The version belongs to the AI client. Record the exact sudo-relay version and source revision with each run.

The historical Codex reports do not record its version. Their IDs use `codex-unknown` until supporting evidence establishes the major version. The `codex-26` example illustrates the convention and does not assign a version to those historical runs. If the version is recovered, retain the old ID as an alias when assigning the versioned ID.

Automated checks without an AI client use a layer prefix, such as `mcp-linux-software-001` or `vm-ubuntu-lifecycle-001`. They carry no AI client version.

Numbers are three digits, allocated within each prefix, and never reused. Keep an ID for reruns of the same assertion and scope. A different client major version, OS family, or security assertion gets a new ID linked to its predecessor. Record exact OS releases, architectures, and full client versions with each run. OS patch updates remain runs of the same case. The ID describes scope, not compatibility with every release of an OS.

## Reproducing the cases

For Mac acceptance, follow the [Touch ID setup guide](../preview/README.md), then the linked case procedure. The [quiet-close guide](native-quiet-close.md#astra-acceptance-after-signing) describes the cancellation and dismissal checks. These require the user to operate the signed native app.

For automated MCP cases, run the commands in [Reproduce](mcp-sudo-milestone.md#reproduce). That suite exercises the cases below together in disposable Linux. Its software signer does not establish that a human or a commercial chat client's inline card approved a request.

For VM lifecycle cases, follow the [setup and removal guide](../preview/README.md) and compare the checkpoints in the [developer preview results](developer-preview-milestone.md). Preserve the baseline file hashes before installation.

## Registered cases

The linked reports contain passing evidence for these assertions. Consult each report for its build, environment, historical failures, and coverage limits. Where an old report omits an exact OS/client version or artifact hash, that metadata remains unrecorded; fill it in on the next run rather than inferring it from today's package version.

### Codex

| Case ID | Check and procedure | Required result | Runbook & results |
|---|---|---|---|
| `codex-unknown-macos-ubuntu-touchid-001` | **Approve once.** Request `/usr/bin/id -u` through Codex, enable output sharing, and approve in the protected reviewer with Touch ID. | Status is complete, exit code is 0, stdout is `0\n`, and the audit records exactly one consumption and launch. | [Runbook](test-cases/codex-unknown-macos-ubuntu-touchid-001.md) · [Results](developer-preview-milestone.md#human-approved-actual-mcp-execution--november-13) |
| `codex-unknown-macos-ubuntu-close-001` | **Close after remote cancellation.** Open a review, cancel through MCP, then click the red title-bar close button. | Window closes quietly, request stays cancelled, and execution outcome is null. | [Runbook](test-cases/codex-unknown-macos-ubuntu-close-001.md) · [Results](native-quiet-close.md#november-18-live-result) |
| `codex-unknown-macos-ubuntu-close-002` | **Deny after remote cancellation.** Open a review, cancel through MCP, then click Deny. | Window closes quietly, request stays cancelled, and execution outcome is null. | [Runbook](test-cases/codex-unknown-macos-ubuntu-close-002.md) · [Results](native-quiet-close.md#november-18-live-result) |
| `codex-unknown-macos-ubuntu-close-003` | **Close while pending.** Open a pending review and click the red title-bar close button before expiry. | Window closes quietly, request becomes cancelled, and execution outcome is null. | [Runbook](test-cases/codex-unknown-macos-ubuntu-close-003.md) · [Results](native-quiet-close.md#november-18-live-result) |
| `codex-unknown-macos-ubuntu-close-004` | **Close after idle expiry.** Leave a review untouched until expiry, then click Close. | Window closes quietly, request remains expired, and execution outcome is null. | [Runbook](test-cases/codex-unknown-macos-ubuntu-close-004.md) · [Results](native-quiet-close.md#november-18-live-result) |

### Automated MCP integration

| Case ID | Check and procedure | Required result | Runbook & results |
|---|---|---|---|
| `mcp-linux-software-001` | **Approval and peer identity.** Run the MCP integration suite, including agent/unrelated-UID approval attempts and a separately signed approver submission. | Unprivileged submissions fail. The approver succeeds and MCP receives UID 0 output when sharing is enabled. | [Runbook](test-cases/mcp-linux-software-001.md) · [Results](mcp-sudo-milestone.md#acceptance-tests) |
| `mcp-linux-software-002` | **Signed output choice.** Run the suite with sharing off/on, altered signed sharing bits, and bounded output probes. | Changed decisions fail. Unshared streams are empty. Shared output obeys the cap and reports truncation. | [Runbook](test-cases/mcp-linux-software-002.md) · [Results](mcp-sudo-milestone.md#acceptance-tests) |
| `mcp-linux-software-003` | **Proof substitution.** Run altered-command, receipt-proof, and cross-enrollment proof cases. | Substituted proofs create no execution marker. | [Runbook](test-cases/mcp-linux-software-003.md) · [Results](mcp-sudo-milestone.md#acceptance-tests) |
| `mcp-linux-software-004` | **Concurrent approval.** Submit the same signed approval concurrently from two approver processes. | Exactly one succeeds and the launch count increases by one. | [Runbook](test-cases/mcp-linux-software-004.md) · [Results](mcp-sudo-milestone.md#acceptance-tests) |
| `mcp-linux-software-005` | **Cancellation and expiry.** Cancel through MCP before approval, then separately attempt an expired approval. | Neither request launches or produces an execution outcome. | [Runbook](test-cases/mcp-linux-software-005.md) · [Results](mcp-sudo-milestone.md#acceptance-tests) |
| `mcp-linux-software-006` | **Revocation and NOPASSWD.** Run revocation-after-request and NOPASSWD cases. | Revoked authority prevents launch. NOPASSWD still requires an independent signed approval. | [Runbook](test-cases/mcp-linux-software-006.md) · [Results](mcp-sudo-milestone.md#acceptance-tests) |
| `mcp-linux-software-007` | **Disconnect and reconnect.** Submit one complete approval, disconnect before reading its reply, then reconnect MCP and replay. | Execution completes once and replay causes no additional launch. | [Runbook](test-cases/mcp-linux-software-007.md) · [Results](mcp-sudo-milestone.md#acceptance-tests) |
| `mcp-linux-software-008` | **Loss after consumption.** Pause after durable consumption, kill the broker/adapter before launch, and restart. | State is uncertain, the marker is absent, and the approval cannot be reused. | [Runbook](test-cases/mcp-linux-software-008.md) · [Results](mcp-sudo-milestone.md#acceptance-tests) |

### Ubuntu VM lifecycle

| Case ID | Check and procedure | Required result | Runbook & results |
|---|---|---|---|
| `vm-ubuntu-lifecycle-001` | **Install and identify sponsor.** Follow the clean-VM installation procedure as the existing sudo-enabled account. | Installer binds the invoking sponsor, creates separate role accounts, and starts the protected loopback channel. | [Runbook](test-cases/vm-ubuntu-lifecycle-001.md) · [Results](developer-preview-milestone.md#clean-installation-and-signed-reviewer-checkpoint--november-13) |
| `vm-ubuntu-lifecycle-002` | **Restart and replay.** Complete a request, restart the service, retrieve status, and attempt to reuse its approval. | Completed/consumed state survives, replay fails, and transient output is unavailable. | [Runbook](test-cases/vm-ubuntu-lifecycle-002.md) · [Results](developer-preview-milestone.md) |
| `vm-ubuntu-lifecycle-003` | **Revoke and remove.** Exercise key/sponsor revocation and the documented uninstall, comparing original sudo/PAM files afterward. | Revocation prevents execution. Removal cleans relay state/services/accounts/policy, original files match, and ordinary sudo works. | [Runbook](test-cases/vm-ubuntu-lifecycle-003.md) · [Results](developer-preview-milestone.md) |

## Recording a run or vulnerability

For each run, record the case ID, date, result (`pass`, `fail`, `inconclusive`, or `not run`), exact software version and source revision, relevant binary hashes, OS releases and architectures, client version, approval method, and procedure used. Attach sanitized logs or report paths, observed status, audit counts, and any request IDs needed to correlate the evidence. Record omissions explicitly. Keep historical failures alongside subsequent passing runs.

For a vulnerability, cite the affected case IDs, affected builds and environments, reproduction steps, expected result, and observed behavior. A new finding outside these cases should receive a new case ID when its regression check is defined. Follow [SECURITY.md](../SECURITY.md) for private reporting and keep passwords, private keys, tokens, and sensitive command output out of evidence.
