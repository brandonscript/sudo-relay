# Protected review test summary

The isolated macOS receipt lab verified administrator-authenticated pairing and
one Touch ID signed receipt per request. Denial, cancellation during Touch ID,
idle expiry, expiry during Touch ID, and disconnect before submission recorded
zero receipts. When confirmation was lost after commit, one receipt was recorded
and the reviewer did not resubmit. The lab did not execute commands.

The Keychain marker checks established a narrower result. An unrelated app was
denied, but a substitute authorized by the same locally available signing
authority could read the marker. Keep the signing authority isolated from the
agent. The modified-app test was inconclusive for variants that never returned
a Keychain result. Neither experiment establishes production code identity or
Keychain isolation.

For the separate fixed-command execution evidence, see the
[developer preview milestone](developer-preview-milestone.md) and
[quiet-close checks](native-quiet-close.md).
