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

An original candidate is in `assets/icon/sudo-relay.svg`, with a rendered
PNG preview beside it. Its geometry was written directly for this project; no
Apple symbol was exported, traced or embedded. The angular shield and linked
points retain the broad white-on-dark concept while changing the mark itself.
These source files are covered by this repository's MIT license. This provenance
note is not trademark clearance or a legal opinion about similarity.

The project owner selected this candidate on November 10, 2026. The retained
packager now uses that original SVG and the display name `sudo-relay`. The Xcode
reviewer uses the generated ICNS. Existing frozen, signed experiment bundles are
not edited: their name/icon change requires a fresh signature and new artifact
pins. Confirm the new Dock and authentication-prompt appearance on Astra after
re-signing. In-app system symbols remain distinct from exported app artwork.

Linux `.desktop` integration still needs a real reviewer executable and tested
application identity; an icon asset alone does not finish that work.

November 11 preference update: the user prefers the empty shield. The retained
custom SVG now omits its two dots and connecting line; the outline is still our
custom geometry, not the earlier system-symbol export. PNG and ICNS are rebuilt
from it. Previously signed bundles remain unchanged; the new icon is for the next
signed build.

## November 20 — relay-arrow identity

The owner selected concept 22 from the second pencil-sketch sheet and requested cleanup and app-icon exports. The new identity uses two offset forward arrows, with a short bent tail on the smaller arrow. A generated cleanup reference is retained alongside an editable vector redraw. The mark and dark tile are project artwork, with no Apple system-symbol export.

The vector master, macOS ICNS, Linux hicolor SVG/PNG sizes, and review previews are under `assets/icon/`. The existing packagers continue reading the same master and ICNS paths. Source assets have been updated locally for review. Installed and previously signed apps have not been replaced or repinned. Linux desktop integration, live Dock rendering, and legal clearance remain unverified.
