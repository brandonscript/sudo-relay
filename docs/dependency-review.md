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

## Remaining MCP advisories

The scan still reports these records for `rmcp` 0.15.0:

- GHSA-33f5-2c5q-wgwj: OAuth resource metadata validation.
- GHSA-89vp-x53w-74fx / RUSTSEC-2026-0189: HTTP DNS rebinding.
- GHSA-9g45-5xwm-f3wc: HTTP redirect header disclosure.
- GHSA-9pj6-vhgr-3mwh: HTTP session-table leak.
- GHSA-c9xm-49cp-xcr9: OAuth discovery SSRF.
- RUSTSEC-2026-0462: HTTP client response buffering.

Records can be retrieved at `https://api.osv.dev/v1/vulns/ID`.
`cargo tree -e features -i rmcp` shows server, macros, base64, transport-async-rw
and transport-io, without HTTP transport or OAuth features. Both MCP binaries
use stdio. These specific vulnerable HTTP/OAuth paths are not enabled in the
current build; this is not a claim that the old SDK has no other vulnerabilities.
Upgrade and compatibility testing remain open. Reevaluate before adding transports.

## Still unverified

This pass covers Cargo registry package/version advisories only. It does not
audit source correctness, provenance, native system frameworks, npm dependencies,
CI action supply chains, unpublished flaws or future advisory changes. Repeat
before release and after dependency changes; do not interpret zero matches as
proof of safety.
