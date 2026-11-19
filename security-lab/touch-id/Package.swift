// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TouchIDExperiment",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "touch-id-probe", targets: ["TouchIDProbe"])],
    targets: [
        .target(name: "ApprovalProbe"),
        .executableTarget(name: "TouchIDProbe", dependencies: ["ApprovalProbe"]),
        .testTarget(name: "ApprovalProbeTests", dependencies: ["ApprovalProbe"]),
    ]
)
