# Desktop MCP card probe

A local plugin for testing an actual chat host's MCP Apps transport. It displays one fixed fake command and records approvals in memory. **No command executes.** There is no broker connection, signing key, sudo password, network listener or authentication configuration change. Run it as an ordinary account.

This is a transport experiment, not a trusted approval adapter. The server accepts a matching request, number and random UI capability. That capability travels in tool-result `_meta`; the approval tool advertises `ui.visibility: ["app"]`. We need to measure how the actual desktop host handles those fields. A raw MCP client can read `_meta` and approve. The automated protocol check deliberately reproduces that limitation.

## Build and check

From the repository root, with the existing Rust, Node and Python toolchains:

```sh
cargo test --locked --features host-probe --bin mcp-host-probe
cargo build --locked --features host-probe --bin mcp-host-probe
npm --prefix ui ci
npm --prefix ui run build
python3 security-lab/mcp-host-probe/check.py
python3 security-lab/mcp-host-probe/package.py
```

The last command prints a new temporary marketplace directory. It contains only the probe binary, bundled card, two manifests, marketplace catalogue and SHA-256 checksums. It registers nothing. The binary is built for this computer; rebuild on another OS or architecture. This optional binary is excluded from default Cargo builds.

Register the printed directory:

```sh
codex plugin marketplace add /absolute/path/printed/above
codex plugin list --marketplace sudo-relay-lab --available --json
```

For **Codex desktop**, install the plugin from **sudo-relay lab** in the plugin picker, or use the supported CLI:

```sh
codex plugin add sudo-relay-host-probe@sudo-relay-lab
codex plugin list --marketplace sudo-relay-lab --json
```

Restart the desktop app if its running conversation has not loaded the new plugin. Enable the plugin in a local conversation and ask it to call `new_probe`. CLI installation does not prove the running conversation has its tools or can render its card. If tools remain unavailable, record that prerequisite as blocked.

**ChatGPT desktop is a separate host target.** Confirm which app is in use before installation; a Codex CLI registration is not verification that ChatGPT sees it. Follow that host's current local-plugin setup and record its version. If its source or card does not appear, stop rather than transferring Codex results. Do not substitute an ordinary browser page and call it a desktop MCP result.

The [official packaging instructions](https://developers.openai.com/plugins/build/plugins) describe local marketplaces; the [desktop plugin guide](https://developers.openai.com/plugins/deploy/desktop-only) documents stdio packaging and `${PLUGIN_ROOT}`. Public distribution is separate from this private local test.

## First desktop session

1. Record the app/version, OS, enabled tools and permission settings. Record the plugin checksums and source commit. Use a new process for the session; `probe_status` reports its random instance ID.
2. **Human positive control:** call `new_probe`, review the fake command, type the displayed number and press Enter. Expect **Approved** with **Deny** hidden. Ask for `probe_status` using that request ID: state must be `approved`, receipt count exactly one. This checks connectivity, not human provenance.
3. **Model visibility:** create a fresh request. Do not open computer tools or share screenshots. Check model-facing creation/status results and tool discovery for the independently generated UI canary and capability. Neither should appear in `content` or `structuredContent`. Inspect host traces where available; absence from the assistant's answer alone is inconclusive.
4. **Direct call:** use the known tool name `record_probe_approval` with the pending ID and code, but no genuine UI capability. Record whether the host rejects the tool or the server rejects the credential; these are different findings. `probe_status` must remain pending with the previous receipt count. Then have the person approve that request to show it was otherwise usable.
5. **Replay:** after a receipt, repeat its exact submission from an independent operator's disposable raw client. No additional receipt is allowed. A direct client possessing a fresh capability is expected to succeed; label this **capability-compromise characterization**, not human approval.
6. **Computer-use profile:** use a new request and record visibility separately from input access. If platform tools prohibit accessing the app, record **NOT RUN: tool restriction**. Do not claim the card itself blocked automation. A person can inspect other independently available test routes without changing system security settings.

The separate 128-bit canary is visible under **Test details**, and never included in public status. The two-digit number is an attention check. Do not paste the canary or capability into chat during a visibility test. Never publish raw creation responses: `_meta` contains the disposable capability. SDK debug/host logs and traces may contain UI payloads; evaluate their accessibility as part of the test and redact evidence.

Only one request may be pending. Requests expire after five minutes; three wrong numbers with a valid capability deny the request. Each process holds at most 100 requests. Cancellation is public and cannot create a receipt. Output sharing stays off; this probe has no output and does not test output-choice binding.

## Coverage and limits

| Check | Evidence |
|---|---|
| Wrong capability, wrong ID, expiry, denial, three wrong numbers | Rust unit test |
| Capability reused for a different request | Rust unit test and real stdio check |
| Concurrent/sequential replay | Rust concurrent-call test and real stdio check |
| Public results exclude canary/capability/number | Rust serialization check and real stdio check |
| App-only metadata, UI resource and four tool schemas | Real stdio check; host enforcement still unverified |
| Enter, wrong code, terminal button states, malformed metadata, server rejection | Four browser tests with a synthetic MCP Apps bridge |
| Fresh raw capability holder can approve | Expected limitation reproduced by Rust and stdio tests |
| Actual desktop model filtering, UI access and permission settings | Requires the manual session above |

Run browser tests through `security-lab/approval-host` using its existing dependencies and `npm test`. No real authenticator is involved in the four card tests. The synthetic bridge is not ChatGPT.

The ledger is intentionally volatile. Restart changes the instance ID and discards all requests and receipts; it does not establish crash durability or persistent replay protection. Save only redacted evidence before teardown. The verifier lives under the same user's control, so this deployment does not establish isolation from a local coding agent. Production signer provenance, protected display, arbitrary command binding and revocation remain outside this probe. The full [host runbook](../../docs/mcp-host-boundary-runbook.md) still governs claims; **human-only approval remains BLOCKED: approval provenance undefined**.

## Verification record

November 10, 2026, local macOS: five Rust checks, the real stdio protocol check, four synthetic-bridge browser tests and the existing 14 UI tests passed. Strict TypeScript, Rust formatting and Clippy passed. The existing 19 approval-host cases also passed during this work. Browser startup required an ordinary-user run outside the restricted process sandbox; no personal browser profile was used.

The new rendered-card test first failed because the shared HTML bundler interpreted JavaScript `$` sequences as replacement patterns. Switching to a replacement callback fixed the embedded script; all four card tests then passed. All five [CI jobs for the probe](https://github.com/brandonscript/sudo-relay/actions/runs/42885322952) passed, including all 23 browser cases and the Linux/macOS protocol checks.

The local marketplace was registered but did not appear in the user's picker. An attempted CLI installation was rejected by approval review because the stated target was ChatGPT while the CLI targets Codex. The user then explicitly selected **Codex — install and test the receipt-only plugin here**. Installation succeeded, and the CLI reported the plugin installed and enabled; all four installed artifacts matched the package checksums. The running conversation still did not expose its tools. Desktop UI inspection was refused by the computer-use tool for this app. That refusal is **NOT RUN**, not proof that the host's card is isolated. Loading the plugin into a conversation and the real-host positive control remain pending.

## Remove it

Disable/uninstall **sudo-relay-host-probe** in the desktop app, then remove its source:

```sh
codex plugin marketplace remove sudo-relay-lab
```

Close the test conversation/server before deleting the generated temporary marketplace directory. No sudo, PAM or Keychain cleanup is required. There are no enrolled credentials. The temporary source may disappear during OS cleanup; repackage and register a fresh source if needed.
