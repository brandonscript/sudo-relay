import Foundation

final class ReceiptService: NSObject, NSXPCListenerDelegate, PeerReceiptProtocol, @unchecked Sendable {
    private let policy: PeerPolicy
    private let root: URL
    // XPC may deliver different clients concurrently; serialize the test receipt file.
    private let lock = NSLock()

    init(policy: PeerPolicy, root: URL) { self.policy = policy; self.root = root }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.setCodeSigningRequirement(policy.client)
        connection.exportedInterface = NSXPCInterface(with: PeerReceiptProtocol.self)
        connection.exportedObject = self
        connection.invalidationHandler = { exit(0) }
        connection.resume()
        return true
    }

    func hello(reply: @escaping @Sendable (String) -> Void) {
        reply("peer-check-hello")
    }

    func receipt(reply: @escaping @Sendable (String) -> Void) {
        lock.lock(); defer { lock.unlock() }
        do {
            let destination = root.appendingPathComponent("receipt.txt")
            // The harness gives each connection attempt a fresh directory.
            try Data("peer-check-receipt-only\n".utf8).write(to: destination, options: .withoutOverwriting)
            reply("peer-check-receipt-only")
        } catch { reply("receipt-failed") }
    }
}

@main
struct Service {
    static func main() throws {
        guard getuid() != 0 else { exit(2) }
        var root = Bundle.main.bundleURL
        for _ in 0..<4 { root.deleteLastPathComponent() }
        let delegate = try ReceiptService(policy: PeerPolicy.load(from: root), root: root)
        let listener = NSXPCListener.service()
        listener.delegate = delegate
        DispatchQueue.global().asyncAfter(deadline: .now() + 15) { exit(2) }
        withExtendedLifetime(delegate) { listener.resume() }
    }
}
