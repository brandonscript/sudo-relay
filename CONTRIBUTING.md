# Contributing

Use the smallest change that solves the whole problem. Keep security checks, error handling, accessibility, and platform behavior explicit. New abstractions need a current caller, not a possible future use.

## Conventions

Rust uses rustfmt, Clippy, typed protocol enums/structs, and errors returned to callers. TypeScript uses strict checking, `unknown` at boundaries, explicit runtime validation, camelCase functions, and no unchecked `any`. Use snake_case for Rust and wire names. Keep public types and protocol changes consistent across both languages and their shared fixture.

README structure follows the practical shape of the owner's Shrinx and fixm4b projects: one-sentence purpose, installation, a first useful action, everyday configuration, limits, and links for deeper details. Use short, human-oriented prose and sentence-case headings. Do not treat every existing repository sentence as owner-authored.

## Check a change

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cd ui
npm ci
npm run check
npm test
npm run build
cd ..
node --import ./ui/node_modules/tsx/dist/loader.mjs scripts/integration.mts
```

Privileged tests are ignored by default. Run them only in a disposable Linux/macOS VM or container as root, using `cargo test --test privileged -- --ignored --test-threads=1`. Other tests require a non-root user. Never run test root commands on a personal or production host.

For every security change, test the failing case, its allowed counterpart, and relevant restart/concurrency behavior. Treat UI visibility as presentation, not authorization. Keep signing keys outside the MCP account.

## Review and release

Run a Ponytail review of the complete flow and a separate documentation pass. Compare naming and README structure to the owner's reference repositories; verify commands rather than merely proofreading them. Record results and untested environments in docs/verification.md.

For a source release, verify the exact commit with CI, review the archive for credentials and local artifacts, and retain the README disclaimer, coverage limits, and private security reporting link. Keep the release marked as a prerelease while setup and security gaps remain open. Test the published download command after the assets are available.

Signed binary distribution needs a separate release review, including signing provenance, name and trademark checks, platform coverage, and independent security review. The source candidate does not include an automated signed-binary release workflow.
