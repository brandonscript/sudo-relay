import Foundation
import CryptoKit

@main
struct Client {
    @MainActor static var activeConnection: NSXPCConnection?

    @MainActor static func main() throws {
        guard getuid() != 0 else { exit(2) }
        let arguments = Array(CommandLine.arguments.dropFirst())
        let root = Bundle.main.bundleURL.deletingLastPathComponent()
        if arguments == ["--fixture-key"] {
            let key = P256.Signing.PrivateKey()
            try key.rawRepresentation.write(to: root.appendingPathComponent("fixture-private.key"))
            try key.publicKey.rawRepresentation.write(to: root.appendingPathComponent("fixture-public.key"))
            return
        }
        guard arguments.isEmpty || arguments == ["--characterize-without-handshake"] || arguments == ["--signed-review"] || arguments == ["--signed-denied"] || arguments == ["--signed-reconnect"] else { exit(2) }
        let policy = try PeerPolicy.load(from: root)
        let connection = NSXPCConnection(serviceName: "local.sudo-relay.peer-service")
        connection.remoteObjectInterface = NSXPCInterface(with: PeerReceiptProtocol.self)
        connection.setCodeSigningRequirement(policy.service)
        connection.resume()
        activeConnection = connection
        let proxy = connection.remoteObjectProxyWithErrorHandler { @Sendable error in
            report("peer-rejected", error: error)
            exit(1)
        } as! PeerReceiptProtocol
        let sendReceipt: @Sendable () -> Void = {
            proxy.receipt { receipt in
                guard receipt == "peer-check-receipt-only" else { report("invalid-reply"); exit(2) }
                report("receipt-received")
                exit(0)
            }
        }
        if arguments != ["--characterize-without-handshake"] {
            // Peer checks on replies do not prevent an initial call's remote side effects.
            proxy.hello { response in
                guard response == "peer-check-hello" else { report("invalid-hello"); exit(2) }
                report("peer-verified")
                if arguments == ["--signed-reconnect"] {
                    Task { @MainActor in await checkReconnect(proxy, root: root, policy: policy) }
                } else if arguments == ["--signed-review"] || arguments == ["--signed-denied"] {
                    checkSignedReview(proxy, root: root, denied: arguments == ["--signed-denied"])
                }
                else { sendReceipt() }
            }
        } else {
            // Explicit negative control in this disposable lab only; never a production option.
            sendReceipt()
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
            report("timeout-not-a-security-pass"); exit(2)
        }
        withExtendedLifetime(connection) { dispatchMain() }
    }
}

func checkSignedReview(_ proxy: any PeerReceiptProtocol, root: URL, denied: Bool) {
    proxy.review { bytes, signature, authority in
        do {
            guard let bytes, let signature, let authority else { report("missing-review"); exit(2) }
            // Trust derives from the authenticated XPC service, not from a key in an arbitrary packet.
            let review = try AuthenticatedReview(bytes: bytes, signature: signature,
                authority: Curve25519.Signing.PublicKey(rawRepresentation: authority), now: Int64(Date().timeIntervalSince1970))
            // shortcut: software proof exercises transport only; hardware signer integration remains separate.
            let key = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: root.appendingPathComponent("fixture-private.key")))
            let decision = try review.decision(shareOutput: false, now: Int64(Date().timeIntervalSince1970))
            let proof = try key.signature(for: decision).derRepresentation
            if denied {
                proxy.cancel {
                    proxy.submit(decision, signature: proof) { accepted in
                        guard !accepted else { report("denied-decision-accepted"); exit(2) }
                        report("signed-review-denied-zero-receipts"); exit(0)
                    }
                }
                return
            }
            let altered = try review.decision(shareOutput: true, now: Int64(Date().timeIntervalSince1970))
            proxy.submit(altered, signature: proof) { accepted in
                guard !accepted else { report("altered-decision-accepted"); exit(2) }
                proxy.submit(decision, signature: proof) { accepted in
                    guard accepted else { report("valid-decision-rejected"); exit(2) }
                    proxy.submit(decision, signature: proof) { replay in
                        guard !replay else { report("replay-accepted"); exit(2) }
                        report("signed-review-one-receipt-alteration-and-replay-rejected"); exit(0)
                    }
                }
            }
        } catch { report("review-failed", error: error); exit(2) }
    }
}

@MainActor
func checkReconnect(_ proxy: any PeerReceiptProtocol, root: URL, policy: PeerPolicy) async {
    do {
        let packet: (Data?, Data?, Data?) = await withCheckedContinuation { continuation in
            proxy.review { continuation.resume(returning: ($0, $1, $2)) }
        }
        guard let bytes = packet.0, let signature = packet.1, let authority = packet.2 else { report("missing-review"); exit(2) }
        let review = try AuthenticatedReview(bytes: bytes, signature: signature,
            authority: Curve25519.Signing.PublicKey(rawRepresentation: authority), now: Int64(Date().timeIntervalSince1970))
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: root.appendingPathComponent("fixture-private.key")))
        let decision = try review.decision(shareOutput: false, now: Int64(Date().timeIntervalSince1970))
        let proof = try key.signature(for: decision).derRepresentation
        let accepted: Bool = await withCheckedContinuation { continuation in
            proxy.submit(decision, signature: proof) { continuation.resume(returning: $0) }
        }
        guard accepted else { report("valid-decision-rejected"); exit(2) }
        let replacement = NSXPCConnection(serviceName: "local.sudo-relay.peer-service")
        replacement.remoteObjectInterface = NSXPCInterface(with: PeerReceiptProtocol.self)
        replacement.setCodeSigningRequirement(policy.service)
        replacement.resume()
        defer { replacement.invalidate() }
        let next = replacement.remoteObjectProxyWithErrorHandler { @Sendable error in
            report("replacement-peer-failed", error: error); exit(2)
        } as! PeerReceiptProtocol
        let hello: String = await withCheckedContinuation { continuation in
            next.hello { continuation.resume(returning: $0) }
        }
        guard hello == "peer-check-hello" else { report("invalid-hello"); exit(2) }
        Client.activeConnection?.invalidate()
        // A live second channel keeps this test about disconnect, not service restart.
        let status: String = await withCheckedContinuation { continuation in
            next.status(review.request.id.uuidString) { continuation.resume(returning: $0) }
        }
        guard status == "approved" else { report("lost-consumption-state"); exit(2) }
        let replay: Bool = await withCheckedContinuation { continuation in
            next.submit(decision, signature: proof) { continuation.resume(returning: $0) }
        }
        guard !replay else { report("replay-accepted"); exit(2) }
        report("replacement-peer-verified-approved-replay-rejected"); exit(0)
    } catch { report("review-failed", error: error); exit(2) }
}
