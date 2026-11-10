# sudo-relay

Human approval for privileged agent commands.

sudo-relay adds a signed approval step when an agent needs privileged access. You review the command, enter its two-digit number, and approve it once. Your existing chat permissions stay in place. The broker does not use a sudo password. Despite the name, it executes commands through its own broker and is not affiliated with the sudo project.

**Alpha software. Not independently audited. Use a disposable machine and throwaway credentials.** Read the [security status and open questions](#security-status) before installing a privileged service.

Before a real-machine trial, read the [pre-trial review and outstanding blockers](docs/pre-trial-review.md). The native-sudo prototype is separate from the shipped broker.

The [chat approval design](docs/chat-approval-design.md) covers optional passkeys and the weaker guarantees of approval through a logged-in session. Try both in the [unprivileged approval experiment](security-lab/approval-host/README.md): it creates receipts only and cannot execute commands. Production host integration remains unfinished.

## Supported clients

The included reference host demonstrates an approval card inside a small chat-style page. Other clients need the trusted host adapter; ordinary MCP support or MCP Apps rendering alone cannot authorize execution. No existing commercial chat client is claimed to be supported.

The card adapts to phone-sized screens. The reference host listens on desktop loopback only; it is not a remotely accessible phone service. Mobile use requires an integrating chat host that securely connects its trusted signing adapter to the broker.

## Security status

This project has automated checks and a local code review. It has not had an independent security audit or a complete penetration test. Passing tests show that specific cases behaved as expected in the tested environment. They do not establish that the system cannot be exploited.

### What we have checked

- A production-mode Linux broker inside Docker, with separate agent and approver user IDs and throwaway keys. Tested agent operations could not read or open protected fixture files for writing, or approve their own requests.
- Successful signed execution, rejection of replayed approvals, and rejection of attempts to substitute a command, argument, request ID or output-sharing choice. Positive controls confirm that valid approvals still work.
- Output sharing on and off, including requests where the agent says it needs output. With sharing off, the tested stdout/stderr and raw diagnostics were withheld. Later opt-in did not disclose earlier withheld output.
- Unit and integration checks for invalid signatures, expiry, cancellation, concurrent consumption, restart state transitions, input/output limits, and Rust/TypeScript agreement on signed bytes. UI checks cover the code field and remembered sharing choice. These are specific checks, not coverage of every race or failure mode.

The [test catalogue](security-lab/test-cases.md) describes the cases, expected results and exclusions. The [verification record](docs/verification.md#sudo-relay-source-alpha) records local and hosted runs. Root-broker tests passed in the disposable Linux fixture and on GitHub-hosted Linux/macOS runners. The full MCP integration runs without root; hosted root tests do not validate service installation or a production signing host.

### What we have not established

The following are possible compromise paths or missing evaluations. They are not a list of confirmed exploits, and they are not an exhaustive list of what could go wrong.

| Area | What remains unknown |
|---|---|
| Sponsor revocation | The broker currently has no sponsoring-sudoer enrollment or live sudo-policy check. Removing an installing user’s sudo rights does not revoke broker access. Per-sudoer binding and revocation enforcement are pending; do not use the alpha where this is an authorization requirement. |
| Trusted display and human approval | No production chat-host/signing integration has been verified. An agent-controlled or compromised approval view could show something different from what the signer authorizes. A signature alone does not prove what appeared on screen or that a person approved it. The reference host is preview-only and cannot sign. |
| Key and process isolation | File-open tests do not cover key extraction from process memory, debugging interfaces, swap, core dumps, backups or logs. Separate user IDs are necessary for this design but are not a complete evaluation of effective access. |
| Real Linux/macOS installations | systemd/launchd service lifecycle, administrator setup and macOS root deployment have not been validated on disposable machines. Owner/mode checks do not inspect macOS ACL entries; additional access granted by ACLs needs evaluation. |
| Files changing during approval or execution | Tests do not establish resistance to every path-replacement race. Executable contents, interpreters, libraries, configuration files, plugins and network content are not all frozen by approval. A reviewed command can act on different content later. |
| Crashes, storage failures and rollback | State-transition tests do not replace crashing real processes at each commit/spawn boundary or testing power loss, full disks and corruption. Restoring an old ledger or VM snapshot could restore an approval that was already used. Resistance to rollback has not been established. |
| Clock changes | Expiry depends on the host wall clock. Clock rollback, suspend/resume and VM clock behavior have not been tested for unintended extensions of the approval window. |
| Misleading content and input | Quoting and validation checks do not prove that a person will interpret every command correctly. Real-browser/mobile accessibility, misleading Unicode, wrapping, injected agent explanations and malicious command output need further review. The number is an attention check, not identity verification. |
| Availability and cleanup | Full hostile-load and resource-exhaustion testing has not been done. Timeout cleanup is best effort; descendant processes may escape their original process group. Limits do not guarantee availability against an authorized hostile account. |
| Dependencies, builds and releases | Passing application tests does not audit cryptographic libraries, parsers or build dependencies. Current dependency advisories, sustained fuzzing, CI credentials, build provenance and release-signing procedures need separate review. Release automation has not been validated end to end. |
| Remote and mobile use | There is no verified production remote/mobile adapter. Any future connection needs its own evaluation of pairing, machine identity, user authentication and transport security. MCP Apps rendering alone does not supply those guarantees. |

### Boundaries to keep in mind

An approved command runs as real root. It can install persistent access, change this broker, or disclose data through files or networking. Disabling output sharing controls only the broker's response channel; it does not contain approved code. The goal is at-most-once launch from a consumed approval, not exactly-once effects or recovery from a compromised OS, administrator or signing host.

Existing sudo, Docker, SSH and other elevation routes are not blocked. A compromised agent that already has another route to root can use it without this broker. The Docker fixture tests application behavior; it does not evaluate kernel or container-runtime escapes.

Use the alpha for evaluation, not as the only protection for production access or sensitive data. Reviewers are welcome to challenge these assumptions and add reproducible cases using fake credentials. Report suspected vulnerabilities privately using the instructions in [SECURITY.md](SECURITY.md).

## Build

Install a stable Rust toolchain and Node.js 24, then run:

```sh
git clone https://github.com/brandonscript/sudo-relay.git
cd sudo-relay
cargo build --locked
cd ui
npm ci
npm run build
cd ..
```

Building does not install a service, change sudo settings, or execute privileged commands.

## Try it without root

Create a private test directory, then initialize a broker that runs as your current user:

```sh
DEMO_DIR=$(mktemp -d)
chmod 700 "$DEMO_DIR"
target/debug/broker --development init "$DEMO_DIR/config.json" "$DEMO_DIR/state" "$DEMO_DIR/run/broker.sock" "$(id -u)" "$(id -u)" "$(id -g)"
target/debug/broker --development serve "$DEMO_DIR/config.json"
```

Leave that terminal open. In another terminal, use the same `DEMO_DIR` value and create an approval key:

```sh
cd ui
npm run keygen -- "$DEMO_DIR/approver.pem"
```

From the repository root, pair the printed **public key**, never the private PEM contents:

```sh
target/debug/broker --development pair "$DEMO_DIR/config.json" demo PUBLIC_KEY_HEX
```

Add this local MCP server to your chat client, replacing both paths with absolute paths:

```json
{
  "mcpServers": {
    "sudo-relay": {
      "command": "/absolute/path/target/debug/mcp-server",
      "args": ["/absolute/path/to/run/broker.sock", "/absolute/path/ui/dist/card.html"]
    }
  }
}
```

Ask it to request `/usr/bin/printf` with `hello` as a separate argument. This creates a pending request; it does not run it. The tool result contains the request ID and complete approval envelope.

Start the reference host from `ui`:

```sh
BROKER_SOCKET="$DEMO_DIR/run/broker.sock" npm run demo
```

Open the printed loopback URL and load the request ID to preview the card. The reference host cannot sign or approve requests; submissions return an error. Live approval requires a protected signer integration.

Development mode never elevates. Production rejects matching agent and approver user IDs. Separate accounts alone do not prove human approval.

## Install on a host

See [installation and removal](docs/install.md) for administrator setup, key pairing, systemd and launchd configuration, revocation, and removal. Use a disposable machine first. Production mode requires root-owned configuration, binaries, and protected paths; keep the trusted signing host outside the agent's control.

The approval window defaults to five minutes. Administrators can change `approval_ttl_secs` in the broker configuration; see [installation settings](docs/install.md#choose-the-approval-window).

## Limits to understand

- Approval applies to one exact request. It does not grant a shell session or permission for later commands.
- An approved root command can install persistent access. This project is not a sandbox.
- Scripts are frozen; files, dependencies, and network responses they read are not.
- Existing sudo, Docker, SSH, and other admin routes remain your responsibility.
- Commands and scripts are stored in the private request ledger. Do not put secrets in command arguments or explanations.
- Output is shared only when you enable **Share command output with the agent** for that approval. The checkbox remembers your previous choice and defaults off. An agent saying it needs output cannot force sharing. Shared output stays in memory, up to 1 MiB per stream and the most recent 32 completions. Restarting loses output. The ledger stops accepting new requests at 10,000 records; an administrator must archive and rotate it.

See the [security model](docs/security.md), [protocol](docs/protocol.md), and [contributor guide](CONTRIBUTING.md).

## Disposable test environment

Use the [Docker fixture](security-lab/fixture/README.md) to start a production-mode Linux broker with throwaway keys and separate test identities. It runs no test cases automatically and removes its runtime data on teardown.

## License

[MIT](LICENSE).
