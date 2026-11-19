# Native approval for the disposable Linux trial

This is a separate execution reviewer, not an upgrade to the receipt-only app.
It accepts only `/usr/bin/id -u`, an empty environment and a timeout no greater
than 30 seconds. All execution stays inside the disposable Linux fixture.

The ordinary native receipt entry point, receipt domain and receipt enrollment
remain unchanged. Shared UI components keep receipt wording by default. This
reviewer explicitly says the command will run in disposable Linux and uses the
separate `sudo-relay.disposable-linux-signer.v1` Keychain service. Setup creates a
new device-local biometric key; it never loads an existing receipt key.

## Approval path

The signed native app reads administrator-owned enrollment via the Rust bridge.
That record fixes the local approving UID, machine UUID, readable machine/OS/user
labels, P-256 approval key, SSH port, protected known-hosts file and transport
identity. The SSH destination is hard-coded to loopback, user `approver`, and the
forced review channel. User SSH configuration, agent identities, forwarding and
connection sharing are disabled. The SSH operation has a ten-second deadline
and a 128 KiB response cap. No automatic retry occurs.

The bridge validates the broker's pending envelope and fixed trial command before
showing it. The app freezes the reviewed decision bytes, compares the loaded key
with the enrolled public key, obtains fresh Touch ID, rechecks expiry and verifies
the signature before submitting once. The bridge re-fetches the current request
and verifies the exact execution signature before sending it to the broker. The
broker remains responsible for expiry, durable consumption and one-use launch.
A consumption acknowledgement is not command completion; check MCP status.

The SSH identity is a transport credential, not the human approval key. Possession
of it does not sign approvals. Someone controlling Docker can replace the Linux
fixture; this test cannot establish security against that administrator.

## Checks completed on Stardust

- Native execution app compiled with Swift 6 and warnings as errors; not launched.
- Four Rust tests cover enrollment purpose/account, pending/expiry/target/command,
  execution versus receipt and output-sharing signatures, and no retry after an
  absent or mismatched acknowledgement.
- Six container SSH tests passed in 6.160 seconds. The added test uses the exact
  native FFI bridge with a disposable P-256 key: fetch matches MCP, receipt proof
  rejected, execution proof accepted, MCP reports UID 0, replay rejected.
- Existing native protocol/receipt persistence and key-store checks passed.
  Fifteen Swift tests passed; receipt UI defaults and expiry behavior remain.
- No Secure Enclave operation, new Keychain item, host sudo/PAM modification or
  Astra execution has occurred in these checks.

## Signing handoff

`package-signing-kit.py TEMPLATE_ZIP OUTPUT_ZIP` builds the native app and includes
its source, checksums, current icon and public provisioning material from the
previous verified Astra app. It requires the isolated Astra team and rejects
unexpected access groups or a debugging entitlement. It accesses no signing key.

On the isolated Astra signing account, `sign-on-astra.command` checks the supplied
files, signs with the existing certificate and writes a ready ZIP. It does not
launch the app, enroll a key or change host settings. Return that ZIP for exact
artifact verification and log out before enrolling in the ordinary account.
Checksums detect changed files; they do not independently authenticate this kit.

The existing bundle identifier is retained because that is what Astra's isolated
profile provisions. The displayed name and icon are sudo-relay. The separate
Keychain service and fresh key keep the trial distinct from receipt enrollment.

## Remaining gates

The signed app must be verified, a fresh public-key candidate created on Astra,
and a narrowly scoped administrator pairing/install kit reviewed. Then test the
host-to-container loopback connection and real Touch ID approval through MCP.
The current fixture uses software keys; that is not hardware-authentication proof.
Human approval of a command and its output-sharing choice remain unverified for
this new entry point. Stop for review after the requested end-to-end milestone.

## Human-session preparation

`human_session.py` is the container-side trial driver. Its startup receives only
the approving public key and generates the unrelated internal PAM key and SSH
transport keys. No human signing private key is generated or imported. It starts
the actual MCP server under the agent UID and permits one `/usr/bin/id -u`
request, with a five-minute approval window, per container. Status reports the
MCP outcome and independently counts native sudo log entries. An alarm ends an
abandoned session after 15 minutes.

The host uses `loopback.py` as a byte carrier from one local TCP listener to an
unprivileged `docker exec` stdio process. That process connects only to the
container's loopback SSH daemon. The container retains `network_mode: none`,
with no published ports or host mounts. Native SSH still authenticates the
pinned host key over the carrier; the carrier cannot manufacture a valid SSH
server or human approval signature. Only one carrier subprocess runs at a time.

Two additional checks passed on Stardust:

```sh
python3 security-lab/native-execution/test_human_session.py
python3 security-lab/native-execution/check-loopback.py
```

The session check confirmed public-key-only setup, exact fixed request and
five-minute window, cancellation with zero sudo launches, and container removal.
The loopback check traversed the real Mac-to-Docker-VM-to-container connection:
server pin and pending request matched, a missing pin failed, and no command ran.
It inspected the running container to verify network mode, absent port bindings
and absence of host mounts. Temporary transport files and the container were
removed. This is not yet an Astra or biometric result.

The initial internal-bridge/port-publication attempt returned no published
binding on this Docker engine. That path was removed rather than enabling
external container networking. Final test image:
`sha256:60b4fbb630bf7a6324e45bfd64070544b477da096157e792916ab5a8f2ca6a92`.

The isolated signing step is still pending. Root-owned enrollment and app
installation cannot be finalized until the returned signed archive and fresh
public-key candidate have been checked. No installation has occurred here.

After the shared fixture initialization changed, the nine native-sudo regression
methods passed again in 12.116 seconds. The six SSH/native-bridge checks also
passed again; no temporary integration containers remained.

## Returned Astra signing artifact

The archive supplied at `/Volumes/TEST_SHARE/sudo-relay-execution-ready.zip` was verified
without launching it. Archive SHA-256:
`4da8f9ce970de1d502c441bf1637e639132082f8677bac9acb480136fbd0a8a5`.
The signed executable SHA-256 is
`6f29e21981d61d9e6e509b6144dd59bd4b9e18f9c4494dc91a54ddc79145b1b1`,
and its CDHash is `cfb11a323448287e7ff0c4fbfdce827eb762bcec`.

Strict code-signature verification with Apple anchor, isolated team and bundle
identifier passed. Certificate, entitlements, provisioning profile, Info.plist
and icon matched the signing kit; no debugging entitlement was present. Removing
signatures from temporary binary copies left one differing byte in the
`__LINKEDIT` virtual size. Normalizing only that segment's virtual-size field
made the remaining binaries byte-identical. Originals were not modified.

A separate enrollment ZIP now contains that exact signed app and a launcher
pinned to its executable hash and code requirement. It only invokes `--enroll`;
there is no Docker, sudo, pairing or execution operation. The ordinary Astra
account must create the fresh key and return its public candidate before the
administrator pairing kit can be finalized. That hardware step is pending.

## Fresh key and administrator-trial handoff

Astra returned execution-purpose public candidate fingerprint
(fingerprint omitted from this source snapshot),
for ordinary account UID 501 and the isolated access group. Purpose, version,
account, group, fingerprint and public EC point validation passed. This candidate
alone is not proof of private-key possession; the end-to-end approval verifies it.

`run_trial.py` runs Docker and the native reviewer as the ordinary user. A small
administrator helper installs only the exact signed app, enrollment and SSH pins
under an unpredictable root-owned `/private/var/db/sr-linux-trial-*` directory.
It cannot launch commands. It removes its directory on normal completion, EOF,
handled termination or its 15-minute deadline. A force-kill/power loss may require
manual cleanup. No host sudoers, PAM, SSH daemon or launchd configuration changes.
The transport identity is root-owned and readable by the approving account's
primary group; it is not the biometric approval key. The parent controls Docker,
which remains a trusted test-broker assumption.

The trial requires one verified native acknowledgement, completed MCP status,
exactly one sudo log entry identifying sponsor_a and USER=root, successful command
completion, the signed output-sharing behavior and verified cleanup before
marking its report completed. With sharing off, the root-target log is checked
but stdout is withheld. No approval is retried. The fresh Keychain key remains
until the user explicitly removes it.

Eight nonprivileged handoff tests pass: build failure before any installer or container launch, Docker availability, isolated configuration
cleanup/server identity, rejection of remote Docker endpoints, pinned archive/path validation, key/account
policy validation, rejection of relaxed runtime containment, and strict result
acceptance. The exact packaged Docker source built successfully; host loopback
and public-key-only session checks also passed. The administrator installer and
real Touch ID execution trial on Astra remain pending.

### Docker runtime recovery (2026-11-12)

Astra's first attempt stopped before administrator installation: the selected
OrbStack socket no longer existed, and the classic builder also invoked an
unrelated Google registry credential helper. The user subsequently supplied
`docker info` showing a working Colima server. That confirms daemon availability,
not completion of the approval trial.

The runner now checks the daemon before building, then uses a temporary Docker
configuration containing no copied registry credentials or credential-helper
settings. It retains discovered Compose/Buildx plugins, pins the local Unix
socket, and verifies the same server ID before building. Environment overrides
are restored and the temporary directory is removed even when the build fails.
No global Docker context or configuration is changed.

Seven handoff tests passed with macOS system Python. A local cached Compose build
also passed under the temporary configuration. Astra's fresh Colima build and
human Touch ID execution remain unverified; the local build used Buildx, whereas
Astra currently reports only Compose. No Google sign-in is required by this kit.

### Anonymous registry access correction (2026-11-12)

The first isolated configuration used an empty `auths` map. Docker automatically
selects a platform credential store when `ContainsAuth()` is false, so this did
not guarantee anonymous access. Astra subsequently reported a Docker Hub PAT
error before any container or administrator setup. We have not inspected its
saved credentials; the exact credential involved is unknown.

The temporary config now includes an explicit empty Docker Hub auth entry. This
suppresses default-store detection without inserting any username, password or
token. See Docker CLI `cli/config/config.go` (`LoadDefaultConfigFile`) and
`cli/config/configfile/file.go` (`ContainsAuth`).

Run `python3 -B security-lab/native-execution/check-docker-anonymous.py` on macOS
with Docker available. It shadows platform credential helpers with harmless
scripts and probes the pinned public Rust manifest. On Stardust, the empty-config
control invoked the fake helper; the corrected config fetched the manifest and
invoked no helper. Real saved credentials were not read by this probe. Eight
handoff unit tests also passed. Build failure now reports that administrator
setup never started. Astra's fresh build and approval remain pending.

### Administrator prompt timeout (2026-11-12)

Astra report `68f031c4507b4abb923837ea4dddefed` confirms the image built,
software approval key was absent, and the container was removed. The report has
no request ID or reviewer result. The screenshot shows the 120-second installer
response timer expiring while sudo was waiting for authentication, followed by
sudo reporting no password. `temporary_install_removed: false` means cleanup
was not acknowledged; it does not establish that installation occurred. A manual
check for remaining trial directories/processes was requested before retrying.

The runner now performs normal terminal `sudo -v` after the build, before creating
the container. Password input stays with sudo and is not piped or captured by
Python. The subsequent temporary installer uses `sudo -n`, so missing/expired
credentials fail immediately instead of blocking its protocol on a password
prompt. This uses normal sudo timestamp behavior without changing sudo policy;
configurations that do not retain authentication may reject the installer.
Nine handoff unit tests pass, including failed authentication causing no process
launch and inheriting the terminal streams. The revised authentication path has
not yet been verified on Astra. No administrator command was run by the agent.

### First completed command on Astra (2026-11-12)

User reported successful interaction and supplied report
`61ff0eced0cc4ddf8a54d27d257cbc08`. The report confirms MCP request
`c8d2fcb0-5350-42d4-98e5-b30ba12c9db8` reached `complete`, exit code 0,
without timeout, truncation or execution/cleanup error. Output sharing was off
and both output streams were empty. Sponsor attribution was present. Reviewer
exit code was 0. Temporary Mac installation and container removal both passed.

Overall acceptance remains **failed/inconclusive**: `completed` is false,
`sudo_launches` is 2, and `verified_app_ack` is false. The runner counts command
text in sudo's log, whose fixture enables `log_exit_status`; two matching entries
are not yet proof of two launches. Raw log entries and reviewer stdout were not
preserved in this report, so neither discrepancy can be resolved from it. Do not
relax acceptance or claim at-most-once launch based on this run. Next work is to
reproduce both discrepancies in the disposable fixture, preserve bounded
nonsecret diagnostics, and distinguish launch events from completion records.
No further human retry requested until that investigation is ready.

### Discrepancy investigation (2026-11-12)

Disposable Linux reproduced two `/usr/bin/id -u` log records for one accepted
P-256 approval: a launch record and `EXIT=0` record shared TSID 000003. Replay of
the proof was rejected. The old substring counter incorrectly counted both.
`command_log` now separately counts launch and successful completion records,
checks their session IDs and sponsor/root attribution, and preserves up to 16
matching records. Acceptance requires exactly one launch and completion with a
valid record pairing. Unknown records, missing completions, duplicate launch
records and a genuine second session cannot pass acceptance.

Six real SSH/container tests passed (5.520s), including the exact native FFI
approval/acknowledgement path, replay rejection and log-count regressions. Nine
host handoff unit tests passed, including rejection of empty, duplicate, noisy or
incomplete app acknowledgement text. The test containers were removed; no host
sudo settings were touched. An initial diagnostic invocation omitted fixture
initialization and failed before any test launch; the corrected invocation and
full suite passed.

The macOS app acknowledgement discrepancy is **not resolved**. The signed binary
contains the expected acknowledgement string, and source emits it only after the
protected bridge succeeds. Linux verified that bridge's response, not AppKit's
stdout behavior. The previous Astra report did not retain stdout, so there is no
evidence to justify relaxing exact matching. The revised runner records the first
2048 characters of reviewer stdout and its full character count alongside exit
code and existing stderr diagnostics. This is native-reviewer diagnostic output,
not the command output withheld by the broker. One new human Astra trial is
needed with the unchanged signed app and key. Overall milestone stays open.

### Milestone accepted after report-parser correction (2026-11-12)

Astra report `5837a4e8b3e549b6b6008b14a1257ab3` preserved the missing evidence.
SHA-256: `712d2ecc0e576c412518e61d8c856d1bee280d73ee2512e32350f283a75e96cd`.
Request `ca75319d-fd27-4b63-adf7-a45f4bc0c2b3` completed once through native sudo as sponsor_a,
USER=root: one launch and one EXIT=0 record share TSID 000003. Output sharing was
off and stdout/stderr stayed empty. Both temporary installation and container
removal passed; software approval private key was absent from Linux.

The reviewer exited 0 and emitted the exact successful acknowledgement, surrounded
by two known diagnostic messages from `BiometricSigning.signWithBiometrics`.
Its noninteractive signing attempt produced no signature; interactive signing
returned, and the app then reported acceptance after bridge verification. Mixed
buffered print/direct writes explain why the noninteractive diagnostic appears
last. The whole-output equality check incorrectly treated this as missing ack.

The parser now accepts only the original exact acknowledgement or the exact
observed three-line transcript from the pinned app; it does not search for a
substring or ignore arbitrary lines. Ten handoff tests pass, including rejection
of extra/duplicate output, changed diagnostic/error code, missing ack, nonzero
exit and two launches. Re-evaluating the original report with corrected acceptance
passes all execution and cleanup checks. The original `completed:false` report
is preserved unchanged; this is a corrected assessment, not a new hardware run.

This completes the bounded human Touch ID → protected reviewer → actual MCP →
disposable Linux sudo milestone with output sharing off. No further Astra run is
needed to resolve these two reporting discrepancies. Stop for review here.
This is not production security certification: software-only tests cover other
paths, but this hardware run did not test output sharing on, arbitrary commands,
production installation, other hosts, or malicious Docker administrators.
