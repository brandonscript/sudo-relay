# Local signing setup

`ReceiptLab.xcodeproj` wraps the existing protected receipt reviewer. It does not
install the verifier. Its Keychain entitlement is limited to the isolated Astra
receipt-lab app group; select only the isolated signing team. Explicit biometric
key setup/removal is now available through the reviewer; see
[the Astra setup runbook](../../docs/protected-review-test-summary.md).

Build the Rust bridge first from the repository root:

```sh
cargo build --locked --lib
```

Then open `ReceiptLab.xcodeproj` in Xcode. The project builds only for the current
Mac's architecture, matching that local Rust library. Hardened runtime is enabled,
base debugger entitlements are not injected, and no runtime exceptions are enabled.
Use Build, not Run, during signing setup. Normal approval needs a protected
enrollment and request-ID argument; `--enroll` creates only an unpaired test key
after explicit biometric confirmation. Neither mode creates broker trust.

A signed Release build and the dummy-marker Keychain experiment ran on November
11. Ordinary unrelated code was denied, but a substitute signed using the locally
available development identity could read the marker. **Do not enroll an approval
key with this signing arrangement.** See
[results and reproduction](../../docs/protected-review-test-summary.md) and
[the installation proposal](../../docs/native-install-review.md).
