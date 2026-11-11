# Dependency review

November 10, 2026. This is a dated advisory check, not an independent audit.
Queries sent public package names and locked versions to the
[OSV batch API](https://google.github.io/osv.dev/api/); no keys or local data were sent.

## SQLite update

The first scan of 164 registry packages identified
[RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html)
in bundled `libsqlite3-sys` 0.36.0. Opening an attacker-written database and
mismatched WAL can disclose process memory. Protected broker paths reduce that
exposure; they are not a substitute for the upstream fix.

Updated `rusqlite` to 0.41.1 and bundled `libsqlite3-sys` to 0.39.1. The subsequent
scan of 165 registry packages no longer reports the SQLite advisory. Existing
receipt-only tests passed for P-256 proofs, restart consumption, old-ledger
migration and four-host isolation; all-target Clippy passed. No executor was
called by these targeted tests. Cross-platform CI is separate evidence.

## MCP update

The earlier scan reported these records for `rmcp` 0.15.0:

- GHSA-33f5-2c5q-wgwj: OAuth resource metadata validation.
- GHSA-89vp-x53w-74fx / RUSTSEC-2026-0189: HTTP DNS rebinding.
- GHSA-9g45-5xwm-f3wc: HTTP redirect header disclosure.
- GHSA-9pj6-vhgr-3mwh: HTTP session-table leak.
- GHSA-c9xm-49cp-xcr9: OAuth discovery SSRF.
- RUSTSEC-2026-0462: HTTP client response buffering.

Records can be retrieved at `https://api.osv.dev/v1/vulns/ID`.
`cargo tree -e features -i rmcp` shows server, macros, base64, transport-async-rw
and transport-io, without HTTP transport or OAuth features. Both MCP binaries
use stdio. These specific vulnerable HTTP/OAuth paths were not enabled in that
build; this was not a claim that the old SDK had no other vulnerabilities.
Reevaluate before adding transports.

Updated both stdio servers to `rmcp` 3.9.0 and its current resource/content APIs.
A fresh OSV batch scan of all 168 locked registry packages returned no advisory
matches on November 10, 2026. The feature tree still has no HTTP, OAuth or MCP
client transport enabled.

Local receipt-only checks pass with protocol versions 2025-06-18 and 2025-11-25:
exact tool inventories, app-only approval metadata, inline resource metadata,
replay/cross-request rejection, and four separate target connections with colliding
request IDs, cancellation isolation and no offline fallback. All-target Clippy
with the host-probe/native-receipt-lab features passes. The raw transport holder
can still approve the capability-based probe; upgrading does not fix that known
host-boundary limitation.

These checks use the legacy initialize handshake. The SDK also supports newer
discovery-based negotiation; that route and live desktop-client compatibility
remain unverified. No installed plugin was refreshed by this dependency change.

Full cross-platform CI run 42949014786 passed for commit `74f2b16`, including
Linux/macOS checks, disposable root fixtures and the approval-host job. This
does not replace the outstanding live desktop compatibility check.

## npm advisory check

`npm audit --json` returned zero vulnerabilities for both lockfiles on
November 10, 2026: `ui` (75 total dependencies reported) and
`security-lab/approval-host` (64). This checks published npm advisories, not
source correctness or package provenance.

## Still unverified

This pass covers Cargo and npm package/version advisories. It does not
audit source correctness, provenance, native system frameworks,
CI action supply chains, unpublished flaws or future advisory changes. Repeat
before release and after dependency changes; do not interpret zero matches as
proof of safety.
