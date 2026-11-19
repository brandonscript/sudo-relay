import Foundation
import CryptoKit

final class ReceiptService: NSObject, NSXPCListenerDelegate, PeerReceiptProtocol, @unchecked Sendable {
    private let policy: PeerPolicy
    private let root: URL
    private let verifier: ReviewReceiptVerifier?
    private var durable: ReceiptProcess?
    private var policyInvalidated = false
    // XPC may deliver different clients concurrently; serialize the test receipt file.
    private let lock = NSLock()

    init(policy: PeerPolicy, root: URL) throws {
        self.policy = policy; self.root = root
        let config = root.appendingPathComponent("broker-config.json")
        if FileManager.default.fileExists(atPath: config.path) {
            guard let verifierPin = policy.verifier else { throw ReviewError.invalidAuthority }
            durable = try ReceiptProcess(executable: Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/receipt-verifier"), config: config, expectedCode: verifierPin)
        }
        let keyFile = root.appendingPathComponent("fixture-public.key")
        if FileManager.default.fileExists(atPath: keyFile.path) {
            let key = try P256.Signing.PublicKey(rawRepresentation: Data(contentsOf: keyFile))
            verifier = ReviewReceiptVerifier(signer: key, now: Int64(Date().timeIntervalSince1970))
        } else { verifier = nil }
    }

    // Called under lock. A changed policy requires a fresh service, never automatic recovery.
    private func policyIsCurrent() -> Bool {
        guard !policyInvalidated else { return false }
        guard let current = try? PeerPolicy.load(from: root), current == policy else {
            policyInvalidated = true
            verifier?.deny()
            durable?.stop(); durable = nil
            return false
        }
        return true
    }

    func broker(_ request: Data, reply: @escaping @Sendable (Data?) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard policyIsCurrent(), request.count < 65536, let durable else { reply(nil); return }
        do { reply(try durable.exchange(request)) }
        catch {
            // Unknown outcome stays unknown. No automatic child restart or approval resubmission.
            durable.stop(); self.durable = nil; reply(nil)
        }
    }

    func status(_ id: String, reply: @escaping @Sendable (String) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard policyIsCurrent(), id.utf8.count <= 36, let id = UUID(uuidString: id), let verifier else { reply("unknown"); return }
        reply(verifier.status(id: id, now: Int64(Date().timeIntervalSince1970)).rawValue)
    }

    func cancel(reply: @escaping @Sendable () -> Void) {
        lock.lock(); defer { lock.unlock() }
        verifier?.deny()
        reply()
    }

    func review(reply: @escaping @Sendable (Data?, Data?, Data?) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard policyIsCurrent(), let packet = try? verifier?.issue() else { reply(nil, nil, nil); return }
        reply(packet.bytes, packet.signature, packet.authority.rawRepresentation)
    }

    func submit(_ decision: Data, signature: Data, reply: @escaping @Sendable (Bool) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard policyIsCurrent(), decision.count <= 16384, signature.count <= 80, let verifier else { reply(false); return }
        do {
            _ = try verifier.consume(decision: decision, signature: signature, now: Int64(Date().timeIntervalSince1970))
            reply(true)
        } catch { reply(false) }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard policyIsCurrent() else { return false }
        connection.setCodeSigningRequirement(policy.client)
        connection.exportedInterface = NSXPCInterface(with: PeerReceiptProtocol.self)
        connection.exportedObject = self
        // Keep bounded verifier state when one client disconnects; a second connection may query it.
        connection.resume()
        return true
    }

    func hello(reply: @escaping @Sendable (String) -> Void) {
        lock.lock(); defer { lock.unlock() }
        reply(policyIsCurrent() ? "peer-check-hello" : "policy-unavailable")
    }

    func receipt(reply: @escaping @Sendable (String) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard policyIsCurrent() else { reply("receipt-failed"); return }
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
        DispatchQueue.global().asyncAfter(deadline: .now() + 360) { exit(2) }
        withExtendedLifetime(delegate) { listener.resume() }
    }
}
