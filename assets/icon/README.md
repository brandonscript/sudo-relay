# sudo-relay icon

The icon uses two forward arrows with equal diagonal spacing. The SVG files are the editable masters.

| File | Use |
|---|---|
| `sudo-relay.svg` | White mark on a dark rounded tile |
| `sudo-relay-mark.svg` | Dark mark on a transparent background |
| `sudo-relay.icns` | macOS app icon, 16px through 1024px |
| `linux/hicolor/` | Linux icon sizes and scalable SVG |
| `preview.webp` | README preview |

Regenerate the platform assets on macOS from the repository root:

```sh
swift assets/icon/generate-icons.swift
```

The generator uses AppKit and `iconutil`. Rebuild, sign, and repin existing app bundles to include an updated icon. Linux desktop integration requires a reviewer executable and desktop entry; the icon files alone do not provide either.

Artwork is covered by the repository MIT license. See [artwork licensing](../../docs/icon-source-review.md).
