# Approval adapter

Review one privileged command inside a chat, then approve it once.

This directory contains a strict TypeScript adapter SDK, an MCP Apps card, and a small reference chat host. It does not add approval support to existing chat clients automatically. A trusted host integration must keep signing keys and approval handling outside the agent's control.

## Build and test

Use Node.js 24 or later:

```sh
npm ci
npm run check
npm test
npm run build
```

The build emits `dist/card.html`, a self-contained MCP Apps resource. Serve it as `ui://sudo-relay/approval.html` and return the pending request as the tool result’s `structuredContent`.

## Try the reference host

The reference host is preview-only. It loads no signing key and rejects every approval submission, including requests with valid HTTP headers and confirmation numbers.

```sh
BROKER_SOCKET=/path/to/broker.sock npm run demo
```

Open `http://127.0.0.1:7351` and load a pending request ID. You can review the card, but approving it returns an error and cannot execute the command. Do not expose this local preview server through a tunnel.

## Integrate a chat host

`approveOnce` in `src/adapter.ts` accepts a pending broker request, number, explicit sharing boolean, and a `TrustedHost` implementation: `approveOnce(pending, number, shareOutput, host)`. The SDK reconstructs the signed CBOR envelope, verifies its SHA-256 digest, checks expiry and the paired machine, and asks the host to sign the verified request and sharing decision together.

The host is responsible for authenticating a genuine human interaction. A method callable by the model, a number repeated by the agent, or an MCP tool hidden from the model is not proof of approval. Do not expose the signing callback as an MCP tool.

The host must supply `signatureAlgorithm: 'ed25519' | 'p256-sha256'` from its
enrollment, alongside `keyId` and `machineId`. Ed25519 returns 64 raw signature
bytes; P-256 signs the same CBOR decision with SHA-256 and returns DER bytes.
There is no algorithm selector in the approval message: the broker selects it
from the administrator-paired key. The SDK bounds signature size; cryptographic
verification remains the broker's responsibility. Unknown host algorithms fail
before signing, with no fallback. Expiry is checked again after signing returns.
This SDK support does not connect the native Touch ID lab or establish a
protected host; those integration and enrollment steps remain unfinished.

The MCP Apps card uses standard tool-result delivery for display. The reference host adds a separate same-origin `approval-host-init` / `approval-human-decision` / `approval-human-cancel` / `approval-host-result` channel. Ordinary MCP Apps hosts without this trusted integration can display the request, but cannot approve it. Custom host integrations must supply an equally protected channel; do not loosen origin checks to make unsupported clients work.

## Output sharing

**Share command output with the agent** starts unchecked. The preview parent remembers checkbox changes in browser local storage and restores the last choice on the next request or reload. If storage is unavailable, a fresh host defaults off. No preference grants execution approval.

The parent provides `share_output_preference` with initialization, receives checkbox changes via `approval-output-preference`, and obtains the per-request boolean in `approval-human-decision`. Integrating hosts must implement their own protected preference storage and sign this exact decision through the SDK. Never infer consent from an MCP field or from `output_needed`.

An agent can set `output_needed:true`; the card labels that claim, but keeps the checkbox editable and permits approval without sharing. The agent may then be unable to continue the task. Denying is always available while pending. The preview host remains unable to sign or execute, regardless of the checkbox.

## What the card shows

The card shows a readable, POSIX-quoted command by default, with wrapping command text and execution details available to expand. Display quoting preserves spaces, empty arguments, quotes, and literal shell operators; execution still uses structured argv. Script requests display the complete script body. The agent's explanation appears below the title and machine identity, above the command. Executable paths are currently required to be absolute, so the fixed working directory `/` stays in the collapsed execution details. Approval requires a matching two-digit number and submitting with **Approve once** or **Enter** while the code field is focused. Expired requests disable approval. Remaining time comes from the signed expiry, including custom broker approval windows. The two visual digit slots use one accessible numeric input, so typing, pasting, backspace, and keyboard navigation do not jump between fields.

The number is an attention check. The signature is the authorization. Broker expiry, replay protection, failed-attempt limits, and atomic consumption remain mandatory even when using this SDK.

## Limits

The reference host checks HTTP headers to reduce browser-origin attacks. These checks do not authenticate local processes. Signing is disabled rather than relying on them for human authorization. Keep any future approving host and browser outside agent process and computer-control access.

No existing chat client is certified as supported. No real credentials or privileged commands are needed for the unit tests. The package is not published to npm; release review is still required.

After a successful host response, the selected action stays visible as a disabled **Approved** or **Denied** button. The other action is hidden. Errors leave the pending actions available; responses carry the request ID so an old response cannot close a newer card.

Production requires distinct agent and approver accounts and a signer that independently authenticates each human approval. HTTP origin and CSRF checks do not authenticate a local process. The included preview host supplies no production signer.
