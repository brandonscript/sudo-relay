# Multiple targets

Use one named MCP connection per target and approving account. This keeps the
existing single-socket server simple: requests cannot select another destination
through a tool argument. A shared connector with a target switch is not planned
for the first implementation.

The current server supports separate local instances. Four real MCP processes
have been tested together against inert local socket backends. This is routing
evidence, not a working four-machine privileged setup. Remote transport, native
signer handoff and production enrollment remain unfinished.

## Configure local instances

After creating separate disposable broker fixtures, give each MCP entry a clear
name and its own socket. The following illustrates four already-existing local
fixtures; substitute their actual absolute paths. It does not install brokers or
pair approving keys.

```json
{
  "mcpServers": {
    "sudo-relay-home-brandon": {
      "command": "/absolute/path/target/debug/mcp-server",
      "args": ["/absolute/path/home/run/broker.sock", "/absolute/path/ui/dist/card.html"]
    },
    "sudo-relay-build-brandon": {
      "command": "/absolute/path/target/debug/mcp-server",
      "args": ["/absolute/path/build/run/broker.sock", "/absolute/path/ui/dist/card.html"]
    },
    "sudo-relay-backup-brandon": {
      "command": "/absolute/path/target/debug/mcp-server",
      "args": ["/absolute/path/backup/run/broker.sock", "/absolute/path/ui/dist/card.html"]
    },
    "sudo-relay-test-brandon": {
      "command": "/absolute/path/target/debug/mcp-server",
      "args": ["/absolute/path/test/run/broker.sock", "/absolute/path/ui/dist/card.html"]
    }
  }
}
```

Each process has its own fixed socket and resource context. Clients differ in how
they display or prefix connection names; the actual host's tool picker and card
routing still need testing. Select the intended connection, and keep its name
with the returned request ID when checking status or cancelling.

A connection name is a convenience, not verified machine identity. Duplicate
hostnames should have distinct aliases, such as `home-vancouver-brandon` and
`home-remote-brandon`. The protected reviewer must show the enrolled machine name,
specific OS version and bare account name, and verify the machine identity in the
signed request. Agent-supplied aliases must never replace that check.

## Changes and failures

- **Rename:** change the client-side alias only. This does not re-pair a key,
  change the machine identity, or move a pending request.
- **Offline:** report that target unavailable. Do not redirect its request or
  status lookup to a different server. Reconnect to the original target and check
  the original request; an uncertain result is not permission to repeat work.
- **Remove:** disabling the MCP entry stops that client connection. It does not
  revoke a broker key, cancel every pending request, or uninstall the broker.
  Authenticated revocation and removal are separate administrator operations.
- **Replace a machine or account:** require fresh authenticated enrollment. Do
  not copy a receipt database or adopt a replacement because its hostname matches.
- **Pair another target:** create a separate machine/account enrollment. Keep
  pending requests, receipts and revocation isolated. Whether production uses
  separate signing keys per target is still an explicit design decision.

The broker tests reject cross-machine signatures even with deliberately colliding
IDs/nonces and the same test key. Those tests do not establish account replacement,
remote transport security, or safe backup restoration.

## Reproduce the routing check

```sh
cargo build --locked --bin mcp-server
python3 security-lab/multi-target/check.py
```

Run as an ordinary user. The fixture starts four MCP servers and four inert Unix
backends, checks each resource and tool destination, uses the same request ID on
all four, cancels one, then disconnects one backend. The other three must remain
pending and reachable; an offline lookup must not contact them. Temporary files
and processes are removed afterward. There is no signer, executor or sudo path.
