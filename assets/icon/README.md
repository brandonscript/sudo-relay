# sudo-relay icon

Concept 22, selected by the owner on November 20, 2026. Two offset forward arrows represent a handoff. The small arrow retains its bent tail, and the larger arrow completes the direction of travel.

The selected pencil sketch was cleaned with image generation, then redrawn as two editable vector paths. `concept-22-cleanup.png` retains the generated cleanup reference. The vector master defines the final geometry. Both arrow tips share a horizontal centerline, and the upper and lower diagonal gaps are equal.

| File | Use |
|---|---|
| `sudo-relay.svg` | App-icon master, white mark on a dark rounded tile |
| `sudo-relay-mark.svg` | Standalone dark mark with a transparent background |
| `sudo-relay.png` | 1024px transparent-corner app icon |
| `sudo-relay.icns` | macOS app bundle icon, 16px through 1024px representations |
| `linux/hicolor/` | Linux app-icon PNGs at 16, 24, 32, 48, 64, 128, 256, 512, and 1024px, plus scalable SVG |
| `preview.webp` | Compressed 512px review preview |
| `review.png` | Large preview and actual-size 16, 32, 64, and 128px exports |

Regenerate the platform exports on macOS from the repository root.

```sh
swift assets/icon/generate-icons.swift
```

This uses AppKit and iconutil without installing or launching an application. The existing bundle packagers read the SVG or ICNS at the same paths. Generated icon assets do not install a Linux reviewer or desktop entry. The review previews are auxiliary exports.

Artwork is covered by the repository MIT license. Originality/trademark clearance has not been performed. Existing signed app bundles must be rebuilt, signed, and repinned to pick up the new resource. See the [source review](../../docs/icon-source-review.md).
