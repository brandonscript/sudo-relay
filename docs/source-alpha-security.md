# Source alpha security notes

## Security status

Automated checks and local code review have been completed. The project still needs an independent security audit and a full penetration test.

### Verified conditions

- A production-mode Linux broker inside Docker, with separate agent and approver user IDs and throwaway keys. Tested agent operations could not read or open protected fixture files for writing, or approve their own requests.
- Successful signed execution, rejection of replayed approvals, and rejection of attempts to substitute a command, argument, request ID or output-sharing choice. Positive controls confirm that valid approvals still work.
- Output sharing on and off, including requests where the agent says it needs output. With sharing off, the tested stdout/stderr and raw diagnostics were withheld. Later opt-in did not disclose earlier withheld output.
- Unit and integration checks for invalid signatures, expiry, cancellation, concurrent consumption, restart state transitions, input/output limits, and Rust/TypeScript agreement on signed bytes. UI checks cover the code field and remembered sharing choice. These are specific checks, not coverage of every race or failure mode.

The [test catalogue](../security-lab/test-cases.md) describes the cases, expected results and exclusions. The [verification record](verification.md#sudo-relay-source-alpha) records local and hosted runs. Root-broker tests passed in the disposable Linux fixture and on GitHub-hosted Linux/macOS runners. The full MCP integration runs without root; hosted root tests do not validate service installation or a production signing host.

In a [live Codex test](mcp-host-boundary-results.md), the agent read private card data and approved a request through the expanded MCP Apps card without the person approving it. Approval also succeeded after the operator reported switching “Any App” off; the MCP Apps browser route remained available in that session. Nothing executed. Hiding data from model-facing tool results and requiring a number plus a button did not protect this card from agent computer use. Production signing integration remains unfinished; this finding does not demonstrate a bypass of native permission prompts, passkeys or Touch ID.

A later [inline-only probe](mcp-host-boundary-results.md#inline-only-experiment--demonstrated-route-unavailable) removed expansion and was absent from that browser interface, while human approval still worked. That is evidence against the specific route tested, not a general human-only approval guarantee. Production behavior is unchanged.

### Open questions

This table lists open questions. Some have partial test coverage.

| Area | What remains unknown |
|---|---|
| Sponsor revocation | The legacy direct-root broker has no sponsoring-sudoer enforcement. The separate fixed-command preview binds the installer’s actual sudo identity, checks policy at request time and executes through native sudo; VM tests cover sponsor/key revocation. Account replacement, external policy providers and revocation races remain unevaluated for general use. |
| Trusted display and human approval | A protected Mac reviewer completed a bounded native-to-MCP-to-full-VM approval test. The preview’s automatic MCP-to-reviewer path passed in Codex with the lab signing setup. Signing with a new team and bundle ID is untested. Agent-controlled chat approval alone is unsafe; the reference browser host cannot sign. A signature alone does not prove a person saw the intended display. |
| Key and process isolation | File-open tests do not cover key extraction from process memory, debugging interfaces, swap, core dumps, backups or logs. Separate user IDs are necessary for this design but are not a complete evaluation of effective access. |
| Real Linux/macOS installations | The per-sponsor Ubuntu preview has fresh-VM install, password-required sudo, MCP and role-separated SSH checks. Permanent Mac reviewer setup, launchd deployment, broader distributions and interrupted upgrades remain unverified. macOS checks now reject extended ACL entries on protected paths and private files; the local temporary-file check and disposable macOS CI checks of root-owned files/ancestors pass. Effective ACL interpretation and replacement races remain unevaluated. |
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

Use the alpha to evaluate the design on disposable systems. Reviewers are welcome to challenge these assumptions and add reproducible cases using fake credentials. Report suspected vulnerabilities privately using the instructions in [SECURITY.md](../SECURITY.md).
