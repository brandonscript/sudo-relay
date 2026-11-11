// Packages an already-built receipt lab in a temporary directory; never installs or launches it.
// Icon source is under review: do not distribute this SF Symbol export (docs/icon-source-review.md).
import AppKit
import Foundation

guard CommandLine.arguments.count == 2 else {
    fatalError("Usage: swift package-lab.swift /absolute/path/to/touch-id-probe")
}
let binary = URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL
let files = FileManager.default
precondition(files.isExecutableFile(atPath: binary.path), "Build the receipt lab first")
let root = files.temporaryDirectory.appendingPathComponent("sudo-relay-native-lab-\(UUID().uuidString)")
let app = root.appendingPathComponent("sudo-relay lab.app")
let contents = app.appendingPathComponent("Contents")
let resources = contents.appendingPathComponent("Resources")
let executables = contents.appendingPathComponent("MacOS")
let iconset = root.appendingPathComponent("LabIcon.iconset")
for directory in [resources, executables, iconset] {
    try files.createDirectory(at: directory, withIntermediateDirectories: true)
}
let destination = executables.appendingPathComponent("touch-id-probe")
try files.copyItem(at: binary, to: destination)

guard let shield = NSImage(systemSymbolName: "shield", accessibilityDescription: nil)?
    .withSymbolConfiguration(NSImage.SymbolConfiguration(paletteColors: [.white])) else {
    fatalError("Shield symbol unavailable")
}
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
        NSColor(calibratedWhite: 0.16, alpha: 1).setFill()
        NSBezierPath(roundedRect: NSRect(x: side * 0.08, y: side * 0.08, width: side * 0.84, height: side * 0.84),
                     xRadius: side * 0.18, yRadius: side * 0.18).fill()
        let height = side * 0.58
        let width = height * shield.size.width / shield.size.height
        shield.draw(in: NSRect(x: (side - width) / 2, y: (side - height) / 2, width: width, height: height))
        NSGraphicsContext.restoreGraphicsState()
        guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("Cannot encode icon") }
        let suffix = scale == 2 ? "@2x" : ""
        try png.write(to: iconset.appendingPathComponent("icon_\(size)x\(size)\(suffix).png"))
    }
}
let icon = resources.appendingPathComponent("LabIcon.icns")
let convert = Process()
convert.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
convert.arguments = ["-c", "icns", "-o", icon.path, iconset.path]
try convert.run(); convert.waitUntilExit()
precondition(convert.terminationStatus == 0 && files.fileExists(atPath: icon.path), "Icon conversion failed")
let info: [String: String] = [
    "CFBundleExecutable": "touch-id-probe", "CFBundleIdentifier": "local.sudo-relay.receipt-lab",
    "CFBundleName": "sudo-relay lab", "CFBundleDisplayName": "sudo-relay lab",
    "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "CFBundleShortVersionString": "0.1.0",
    "CFBundleIconFile": "LabIcon.icns", "NSPrincipalClass": "NSApplication", "LSMinimumSystemVersion": "13.0",
]
let plist = contents.appendingPathComponent("Info.plist")
try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: plist)
let sameBinary = try Data(contentsOf: binary) == Data(contentsOf: destination)
precondition(sameBinary, "Copied binary differs")
precondition(Bundle(url: app)?.executableURL?.resolvingSymlinksInPath().path == destination.resolvingSymlinksInPath().path,
             "Bundle executable lookup failed")
print(app.path)
