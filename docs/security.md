# Security model

The broker accepts one signed approval for one stored request. Its safety depends on the approving host and broker remaining trustworthy. This is an experimental implementation, not independently audited software. The README lists [tested behavior and open compromise paths](../README.md#security-status); that list is not exhaustive.

## Intended protections

Under the trusted-component and permission assumptions below, the design is intended to reject forged approvals, changes to signed requests, reuse of consumed requests, and unauthorized changes to broker policy. Local tests cover specific attempts; they do not establish that every bypass is prevented. Only the configured approver UID can submit signatures. Requests are bounded, expire after the configured approval window (five minutes by default), and are serialized with durable state transitions.

Approval messages contain signatures, not private signing keys. Keeping keys out of agent access depends on the trusted host and operating system. The number is visible and guessable by design; it is only an attention check. Cryptography, peer identity checks, and protected storage enforce authorization.

## Trusted components

Trust the OS/kernel, cryptographic libraries, administrator, service binary, root-owned state, approving chat host, signing key storage, and the UI that presents the request. The approving UI must be outside agent browser/computer automation. An agent that can control the approval browser can enter the number and click the button. An agent that can inspect or modify the signing host process can impersonate approval.

The reference Node host is preview-only: it loads no signing key and rejects approvals. Loopback HTTP origin and CSRF checks do not isolate a signer from local agents, even under separate user IDs. Production rejects matching agent and approver UIDs and requires an integrating host's protected signing mechanism to authenticate each human approval. Do not place production signing keys in agent-accessible storage.

A generic MCP client claiming UI support is not evidence of human presence. Unsupported clients can create pending requests and inspect status, but cannot execute them without the trusted host's signature.

## Execution boundary

Production validates both original executable path ancestors and canonical target ancestors as root-owned and not group/world writable. The canonical argv executable is frozen into the signed request. Script interpreter paths must be trusted too; script bodies are copied from the stored envelope to a private, exclusively created snapshot before launch. Ordinary arguments can still refer to mutable files. Commands can load plugins, read files, or fetch network content that was not frozen.

Approved code runs as real root. It can escape its process group, install persistence, modify this broker, or disable future checks. Process-group termination is best effort, not containment. Existing sudo, privileged containers, SSH credentials, and other escalation routes are not intercepted or removed.

## Persistence and resource limits

SQLite uses full synchronization and transactional consumption before launch. A filesystem lock prevents a second broker opening the same state and applying restart recovery while the first is live. Restart cancels pending requests and marks consumed/running requests uncertain; it never relaunches them. This is at-most-once launch, not exactly-once effects. Cancellation applies only while pending.

The ledger includes command/script text and reasons; treat it as sensitive. With explicit signed sharing consent, stdout/stderr remain in memory, limited to 1 MiB each and 32 completions. Without consent, the executor drains and discards both streams, and the broker withholds raw diagnostics. Output is never written to the ledger. The sharing choice is persisted atomically with approval consumption; requesters cannot set it. Agent claims that output is needed do not override this decision. The database refuses new requests after 10,000 records. A local authorized peer can still deny availability by occupying the serial socket or exhausting execution slots. Input has size and wall-clock limits; availability against an authorized hostile account is not guaranteed.

Revoked keys cannot authorize pending work but cannot retract already consumed approval. Request IDs, nonces, machine identity, expiry, and exact signed bytes are checked to reject cross-request and cross-machine replay. This depends on trustworthy state and time; restoring old ledger/VM state or rolling back the clock has not been evaluated. Rotating state requires a new machine identity.

## Output sharing

The checkbox controls the broker's output channel, not the behavior of arbitrary approved root code. Such code can disclose secrets through files or networking, and exit codes/timing can also convey information. Output shared with an agent may contain secrets or instructions; treat it as untrusted command data, not as further authorization. No automatic secret redaction is promised.

The remembered browser preference is a convenience, not approval. It belongs to the trusted host; an MCP result cannot change it. A production host must protect the preference and the displayed decision from the agent. The reference browser host demonstrates persistence but remains preview-only, with no signing key or approval endpoint that can authorize work.

## Reporting

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/brandonscript/sudo-relay/security/advisories/new). Do not post passwords, private keys, or exploitable findings publicly. See [SECURITY.md](../SECURITY.md) for what to include.
