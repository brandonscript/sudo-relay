# Protocol

## Local transport

One JSON object and newline per Unix-socket connection. Requests are limited to 64 KiB and a two-second total read deadline; specs are limited to 16 KiB. Replies are `{ "ok": true, "value": ... }` or `{ "ok": false, "error": "..." }`. The broker verifies peer UIDs using Linux `SO_PEERCRED` or macOS `getpeereid`. Socket access also requires its configured group.

Methods:

- `request_execution`: `spec` with `command`, `env`, `reason`, `timeout_secs`, and optional `output_needed`. Returns `{envelope, signing_payload, digest}`.
- `execution_status`: `id`. Returns `{id,state,pending,output_shared,outcome}`; pending/outcome may be null.
- `cancel_execution`: `id`. Cancels pending requests only.
- `approve`: `id`, `key_id`, `number`, boolean `share_output`, and hex `signature`. Available only on the local protocol to the configured approving UID, never as an MCP tool.

A command is `{kind:"argv",argv:["/absolute/executable","argument"]}` or `{kind:"script",interpreter:"/bin/sh",script:"..."}`. `/bin/bash` is also supported. The protocol accepts `timeout_secs` from 1–86,400 seconds, default 300. The broker additionally enforces root-configured `max_execution_secs` (default 300) both when recording a request and before consuming approval. Older adapters retain the 300-second limit; update broker and adapter together for longer requests. `env` defaults empty; allowed names are LANG, TZ, TERM, DEBIAN_FRONTEND, and uppercase LC_ names. Reason defaults empty. `output_needed` defaults false and is an agent-supplied advisory, never authorization to receive output. A request cannot set `share_output`. Unknown fields are rejected.

The broker uses cwd `/`, stdin closed, PATH `/usr/bin:/bin:/usr/sbin:/sbin`, HOME `/var/empty`, and no inherited environment. Argv permits 1–256 entries. Control/bidi characters are rejected; scripts allow line breaks and tabs. The card renders a wrapped, quoted command as text, never command-derived HTML.

The root-owned configuration sets `approval_ttl_secs` (default 300, range 1–86400). This is not a request field. The resulting `expires_at` remains part of the signed payload; configuration changes do not extend an existing request.

## Signed bytes

Envelope fields: `version:2`, `machine_id`, `id`, `nonce`, `created_at`, `expires_at`, `number`, `spec`. Times are integer Unix seconds. IDs are UUIDs; nonce is 32 random bytes encoded as hex; number is a random decimal string from 10 through 99.

The frozen request is encoded as this deterministic CBOR array:

```text
["sudo-relay/request/v2", machine_id, id, nonce,
 created_at, expires_at, number, command, environment, reason,
 timeout_secs, output_needed]
```

Command is `["argv",argv]` or `["script",interpreter,script]`. Environment is an array of `[name,value]` pairs sorted by name. `signing_payload` is lowercase hex of these request bytes; `digest` is their SHA-256 hex. The UI reconstructs both before display. This field is the frozen request, not the complete human decision.

The approving host signs the following deterministic CBOR array directly:

```text
["sudo-relay/decision/v2", request_bytes, share_output]
```

`request_bytes` is a CBOR byte string containing the exact frozen request above. `share_output` is a mandatory boolean chosen by the person. Arrays, text and byte strings have definite lengths; integers use their shortest encoding. Rust and TypeScript share vectors for the request and both decisions. Changing the sharing choice invalidates the signature. Version 1 signatures are not accepted; update clients and broker together. Existing pending requests are cancelled on broker restart. Older ledgers receive a sharing column defaulting to false.

With sharing off, both streams are drained without retaining content. The broker also clears stream content and substitutes fixed diagnostic messages before caching results. `execution_status` still returns state, exit code, timeout and cleanup indicators, and `output_shared:false`; stdout/stderr are empty. With sharing on, output is bounded and memory-only. Changing a later UI preference cannot disclose a previous request's withheld output.

The trusted parent host supplies `share_output_preference` in `approval-host-init`. The card sends human checkbox changes as `approval-output-preference` and includes `share_output` in `approval-human-decision`. The parent remembers the preference, but must obtain fresh approval and sign the explicit choice for each request. The preview host stores the preference in its browser origin's local storage, defaulting off when unavailable; it still cannot sign.

Ed25519 verification uses strict verification. The broker compares the supplied number after authenticating the signature; three authenticated wrong attempts cancel the request. UI mismatches do not send a signature and therefore do not count as broker attempts.

## State and MCP

States: pending → consumed → running → complete; pending can instead become cancelled or expired. Restart turns pending into cancelled and consumed/running into uncertain. Only consumed requests produce execution jobs. Invalid signatures never consume a request.

The stdio MCP server exposes exactly three tools: request_execution, execution_status, cancel_execution. Its approval resource is `ui://sudo-relay/approval.html`, MIME `text/html;profile=mcp-app`; request_execution references it through `_meta.ui.resourceUri`. Tool results contain the pending envelope in `structuredContent`.

The UI uses the official MCP Apps SDK to receive tool results. Signing is a separate host integration. The reference card accepts initialization only from its same-origin parent and sends the decision to that parent; other hosts must securely adapt this channel rather than exposing signing as an MCP tool. No private key or generic signing endpoint is supplied to model code.
