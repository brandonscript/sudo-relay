# Icon source review

Reviewed November 10, 2026. The accepted appearance is a white outlined shield
on a dark rounded tile. The current temporary macOS packager obtains its shield
from `NSImage(systemSymbolName: "shield", ...)` in
`security-lab/touch-id/package-lab.swift`.

Apple's current [Xcode and Apple SDKs Agreement, section 2.10](https://images.apple.com/legal/sla/docs/xcode.pdf)
limits system-provided images to the relevant Apple platforms and excludes their
use in app icons, logos and trademarks, including substantially or confusingly
similar images. The existing system-symbol export must not become the project's
distributed icon. Its presence in a working temporary bundle was not evidence of
redistribution permission.

An original candidate is in `assets/icon-candidate/sudo-relay.svg`, with a rendered
PNG preview beside it. Its geometry was written directly for this project; no
Apple symbol was exported, traced or embedded. The angular shield and linked
points retain the broad white-on-dark concept while changing the mark itself.
These source files are covered by this repository's MIT license. This provenance
note is not trademark clearance or a legal opinion about similarity.

The candidate has been rendered and visually inspected, but has not been chosen
by the project owner or installed in the macOS packager. Do not treat it as the
final project mark. After selection, use one original vector source for macOS
icon sets and Linux scalable/raster assets, remove the SF Symbol export from the
packager, and check the actual Dock and Linux desktop presentation. The existing
native-window system shield is a separate in-app UI use, not the exported app icon.

Linux `.desktop` integration still needs a real reviewer executable and tested
application identity; an icon asset alone does not finish that work.
