#!/usr/bin/env swift
import AppKit
import Foundation

let files = FileManager.default
let directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let source = directory.appendingPathComponent("sudo-relay.svg")
guard let artwork = NSImage(contentsOf: source) else {
    fatalError("Cannot load SVG artwork")
}
let temporary = files.temporaryDirectory.appendingPathComponent("sudo-relay-icons-\(UUID().uuidString)")
let iconset = temporary.appendingPathComponent("sudo-relay.iconset")
try files.createDirectory(at: iconset, withIntermediateDirectories: true)
defer { try? files.removeItem(at: temporary) }

func render(_ size: Int, to destination: URL) throws {
    guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
        let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
        fatalError("Cannot allocate icon bitmap")
    }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    artwork.draw(in: NSRect(x: 0, y: 0, width: size, height: size))
    NSGraphicsContext.restoreGraphicsState()
    guard let png = bitmap.representation(using: .png, properties: [:]) else {
        fatalError("Cannot encode PNG")
    }
    try files.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
    try png.write(to: destination)
}

for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let suffix = scale == 2 ? "@2x" : ""
        try render(size * scale, to: iconset.appendingPathComponent("icon_\(size)x\(size)\(suffix).png"))
    }
}
for size in [16, 24, 32, 48, 64, 128, 256, 512, 1024] {
    try render(size, to: directory.appendingPathComponent("linux/hicolor/\(size)x\(size)/apps/sudo-relay.png"))
}
let scalable = directory.appendingPathComponent("linux/hicolor/scalable/apps/sudo-relay.svg")
try files.createDirectory(at: scalable.deletingLastPathComponent(), withIntermediateDirectories: true)
try Data(contentsOf: source).write(to: scalable)
try render(1024, to: directory.appendingPathComponent("sudo-relay.png"))
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
process.arguments = ["-c", "icns", "-o", directory.appendingPathComponent("sudo-relay.icns").path, iconset.path]
try process.run()
process.waitUntilExit()
guard process.terminationStatus == 0 else {
    FileHandle.standardError.write(Data("ICNS export failed; iconutil returned \(process.terminationStatus)\n".utf8))
    exit(1)
}
print("Generated macOS ICNS and Linux SVG/PNG icons from the vector master.")
