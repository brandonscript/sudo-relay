import Foundation
import CryptoKit

final class ReceiptService: NSObject, NSXPCListenerDelegate, PeerReceiptProtocol, @unchecked Sendable {
    private let policy: PeerPolicy
    private let root: URL
    private let verifier: ReviewReceiptVerifier?
    // XPC may deliver different clients concurrently; serialize the test receipt file.
    private let lock = NSLock()

    init(policy: PeerPolicy, root: URL) throws {
        self.policy = policy; self.root = root
        let keyFile = root.appendingPathComponent("fixture-public.key")
        if FileManager.default.fileExists(atPath: keyFile.path) {
            let key = try P256.Signing.PublicKey(rawRepresentation: Data(contentsOf: keyFile))
            verifier = ReviewReceiptVerifier(signer: key, now: Int64(Date().timeIntervalSince1970))
        } else { verifier = nil }
    }

    func review(reply: @escaping @Sendable (Data?, Data?, Data?) -> Void) {
        guard let packet = try? verifier?.issue() else { reply(nil, nil, nil); return }
        reply(packet.bytes, packet.signature, packet.authority.rawRepresentation)
    }

    func submit(_ decision: Data, signature: Data, reply: @escaping @Sendable (Bool) -> Void) {
        guard decision.count <= 16384, signature.count <= 80, let verifier else { reply(false); return }
        do {
            _ = try verifier.consume(decision: decision, signature: signature, now: Int64(Date().timeIntervalSince1970))
            reply(true)
        } catch { reply(false) }
    }

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
