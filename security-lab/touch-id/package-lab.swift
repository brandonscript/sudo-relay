// Packages an already-built receipt lab in a temporary directory; never installs or launches it.
// Bundle artwork comes from the owner-approved original SVG, not a system symbol.
import AppKit
import Foundation

guard CommandLine.arguments.count == 2 else {
    fatalError("Usage: swift package-lab.swift /absolute/path/to/touch-id-probe")
}
let binary = URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL
let files = FileManager.default
precondition(files.isExecutableFile(atPath: binary.path), "Build the receipt lab first")
let root = files.temporaryDirectory.appendingPathComponent("sudo-relay-native-lab-\(UUID().uuidString)")
let app = root.appendingPathComponent("sudo-relay.app")
let contents = app.appendingPathComponent("Contents")
let resources = contents.appendingPathComponent("Resources")
let executables = contents.appendingPathComponent("MacOS")
let iconset = root.appendingPathComponent("sudo-relay.iconset")
for directory in [resources, executables, iconset] {
    try files.createDirectory(at: directory, withIntermediateDirectories: true)
}
let destination = executables.appendingPathComponent("touch-id-probe")
try files.copyItem(at: binary, to: destination)

let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("assets/icon/sudo-relay.svg")
guard let artwork = NSImage(contentsOf: source) else { fatalError("Original icon unavailable") }
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = size * scale
        guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
            let context = NSGraphicsContext(bitmapImageRep: bitmap) else { fatalError("Cannot render icon") }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        let side = CGFloat(pixels)
        artwork.draw(in: NSRect(x: 0, y: 0, width: side, height: side))
        NSGraphicsContext.restoreGraphicsState()
        guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("Cannot encode icon") }
        let suffix = scale == 2 ? "@2x" : ""
        try png.write(to: iconset.appendingPathComponent("icon_\(size)x\(size)\(suffix).png"))
    }
}
let icon = resources.appendingPathComponent("sudo-relay.icns")
let convert = Process()
convert.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
convert.arguments = ["-c", "icns", "-o", icon.path, iconset.path]
try convert.run(); convert.waitUntilExit()
precondition(convert.terminationStatus == 0 && files.fileExists(atPath: icon.path), "Icon conversion failed")
let info: [String: String] = [
    "CFBundleExecutable": "touch-id-probe", "CFBundleIdentifier": "local.sudo-relay.receipt-lab",
    "CFBundleName": "sudo-relay", "CFBundleDisplayName": "sudo-relay",
    "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "CFBundleShortVersionString": "0.1.0",
    "CFBundleIconFile": "sudo-relay.icns", "NSPrincipalClass": "NSApplication", "LSMinimumSystemVersion": "13.0",
]
let plist = contents.appendingPathComponent("Info.plist")
try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: plist)
let sameBinary = try Data(contentsOf: binary) == Data(contentsOf: destination)
precondition(sameBinary, "Copied binary differs")
precondition(Bundle(url: app)?.executableURL?.resolvingSymlinksInPath().path == destination.resolvingSymlinksInPath().path,
             "Bundle executable lookup failed")
print(app.path)
