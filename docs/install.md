# Installation and removal

Production requires different agent and approver user IDs. The included HTTP host is preview-only and cannot approve requests. A separately reviewed signer that authenticates each human approval is required before live use.

Use a disposable Linux or macOS machine first. These are administrator instructions, not an automatic installer.

## Prepare the machine

Build with `cargo build --release --locked` and build the UI as described in the README. Install the broker as a root-owned executable, outside any agent-writable directory:

```sh
sudo install -d -m 755 /usr/local/libexec/sudo-relay
sudo install -m 755 target/release/broker /usr/local/libexec/sudo-relay/broker
sudo install -d -m 700 /etc/sudo-relay
```

Choose numeric IDs for the requesting agent, trusted approving host, and a shared socket-access group. Create the accounts/group with your OS account tools and add both clients to that group. The broker also verifies peer UIDs; group membership alone cannot approve. Keep the approving host separate from the agent account for a meaningful local boundary.

Initialize with those three numbers, replacing `AGENT_UID`, `APPROVER_UID`, and `SOCKET_GID`:

```sh
sudo /usr/local/libexec/sudo-relay/broker init /etc/sudo-relay/config.json /var/lib/sudo-relay /var/run/sudo-relay/broker.sock AGENT_UID APPROVER_UID SOCKET_GID
```

This creates a private state directory, a public socket directory, and a machine UUID. Parent directories must be root-owned and not group/world writable. On macOS, create `/var/lib` as a root-owned directory if absent, or supply `/Library/Application Support/sudo-relay` as the quoted state path instead. Do not loosen permissions to make validation pass.

## Choose the approval window

The root-owned JSON configuration supports `"approval_ttl_secs": 300`. Omitted values default to five minutes for existing configurations. Set it to a whole number from 1 to 86,400 seconds (one day), then restart the broker. Expiry cannot be disabled or changed by an MCP request. Restart cancels pending requests; the new window applies to newly created requests. The execution timeout is separate and remains capped at 300 seconds.

The card displays the remaining time from the signed expiry, not a fixed five-minute label.

## Pair an approving host

On the trusted host, run `npm run keygen -- /private/path/approver.pem` from `ui`. Keep the private file in storage the agent cannot read or replace. Copy only the printed public hex key to the administrator:

```sh
sudo /usr/local/libexec/sudo-relay/broker pair /etc/sudo-relay/config.json desktop PUBLIC_KEY_HEX
```

Pin the machine UUID in the host adapter. Pairing a host is an administrative trust decision. Public keys are re-read on every approval so revocation takes effect without restarting:

```sh
sudo /usr/local/libexec/sudo-relay/broker revoke /etc/sudo-relay/config.json desktop
```

Revocation cannot undo a command already consumed or launched. Generate a new host key and pair a new key ID to rotate keys.

## Start the service

On Linux:

```sh
sudo install -m 644 packaging/broker.service /etc/systemd/system/sudo-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now sudo-relay.service
```

On macOS:

```sh
sudo install -m 644 packaging/broker.plist /Library/LaunchDaemons/local.sudo-relay.broker.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/local.sudo-relay.broker.plist
```

Configure the MCP server as the unprivileged agent account, with the socket path and built approval HTML resource as arguments. Never run the MCP server as root. The signing host is a separate integration, not a model-callable tool. See [the adapter guide](../ui/README.md).

## Inspect and archive

Service stderr reports operational failures; request metadata and decisions live in `state.sqlite3` in the private state directory. Output is never written there. With the broker stopped, an administrator can inspect it with SQLite:

```sql
SELECT time,id,event,key_id FROM audit ORDER BY seq;
```

At the 10,000-request limit, stop the service, archive the entire private state directory, initialize a new state directory and machine UUID, re-pair approved public keys, and update the host's machine pin. Keep old ledgers private. Do not delete individual rows to bypass consumption history. Old signed approvals cannot authorize new UUIDs or the new machine identity.

## Remove

Stop and disable the Linux service with `sudo systemctl disable --now sudo-relay.service`, or unload macOS with `sudo launchctl bootout system /Library/LaunchDaemons/local.sudo-relay.broker.plist`. Remove the corresponding service file and installed broker directory, then remove the MCP entry and revoke/delete the host signing key.

Archive or delete `/etc/sudo-relay`, the chosen state directory, and `/var/run/sudo-relay` after stopping the service. These contain the configuration, public keys, request ledger, and socket. Removal does not undo changes made by previously approved root commands.
