import AppKit
import CryptoKit
import LocalAuthentication

@main
@MainActor
struct NativeClient {
    static func main() {
        guard getuid() != 0 else { exit(2) }
        umask(0o077)
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        Task { @MainActor in
            do { try await review() }
            catch {
                report("native-review-stopped", error: error)
                if requiresErrorNotice(error) {
                    let alert = NSAlert()
                    alert.messageText = "Test approval failed"
                    alert.informativeText = "Nothing executes in this lab.\n\(errorSummary(error))"
                    alert.addButton(withTitle: "Close")
                    alert.runModal()
                }
                exit(1)
            }
            exit(0)
        }
        app.run()
    }

    static func review() async throws {
        let root = Bundle.main.bundleURL.deletingLastPathComponent()
        let mode = Bundle.main.object(forInfoDictionaryKey: "SudoRelayLabProtocol") as? String ?? "native-json-v1"
        guard mode == "native-json-v1" || mode == "broker-cbor-v2" else { throw ReviewError.invalidRequest }
        let policy = try PeerPolicy.load(from: root)
        if mode == "broker-cbor-v2", policy.verifier == nil { throw ReviewError.invalidAuthority }
        let capability = BiometricSigning.context()
        var error: NSError?
        let available = capability.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        let touchID = capability.biometryType == .touchID
        capability.invalidate()
        guard available, touchID, SecureEnclave.isAvailable else { throw ReviewError.invalidProof }
        let keyData = try BiometricSigning.makeBiometricKey()
        let lookup = BiometricSigning.context()
        lookup.interactionNotAllowed = true
        defer { lookup.invalidate() }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData, authenticationContext: lookup)
        // Disposable fixture enrollment before service launch; not a protected trust store.
        if mode == "broker-cbor-v2" {
            let hex = key.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined()
            try Data("p256-sha256:\(hex)".utf8).write(to: root.appendingPathComponent("state/keys/native.pub"), options: .withoutOverwriting)
        } else {
            try key.publicKey.rawRepresentation.write(to: root.appendingPathComponent("fixture-public.key"))
        }
        let connection = NSXPCConnection(serviceName: "local.sudo-relay.peer-service")
        connection.remoteObjectInterface = NSXPCInterface(with: PeerReceiptProtocol.self)
        connection.setCodeSigningRequirement(policy.service)
        connection.resume()
        defer { connection.invalidate() }
        let proxy = connection.remoteObjectProxyWithErrorHandler { @Sendable error in
            // An ambiguous disconnect must never trigger a new signing attempt or submission.
            report("peer-disconnected-outcome-unconfirmed", error: error); exit(1)
        } as! PeerReceiptProtocol
        DispatchQueue.global().asyncAfter(deadline: .now() + 360) {
            report("native-review-timeout-outcome-unconfirmed"); exit(2)
        }
        let hello: String = await withCheckedContinuation { continuation in
            proxy.hello { continuation.resume(returning: $0) }
        }
        guard hello == "peer-check-hello" else { throw ReviewError.invalidAuthority }
        report("peer-verified")
        if mode == "broker-cbor-v2" {
            try await reviewDurableNative(proxy, root: root, keyData: keyData)
            return
        }
        let packet: (Data?, Data?, Data?) = await withCheckedContinuation { continuation in
            proxy.review { continuation.resume(returning: ($0, $1, $2)) }
        }
        guard let bytes = packet.0, let signature = packet.1, let authority = packet.2 else {
            throw ReviewError.invalidRequest
        }
        let now = { Int64(Date().timeIntervalSince1970) }
        let review = try AuthenticatedReview(bytes: bytes, signature: signature,
            authority: Curve25519.Signing.PublicKey(rawRepresentation: authority), now: now())
        let panel = try NativeReviewPanel(review: review)
        NSApplication.shared.activate(ignoringOtherApps: true)
        guard panel.runReview() else {
            await withCheckedContinuation { continuation in proxy.cancel { continuation.resume() } }
            report("native-review-closed-zero-receipts")
            return
        }
        do {
            let decision = try review.decision(shareOutput: panel.form.share.state == .on, now: now())
            let proof = try BiometricSigning.signWithBiometrics(decision, keyData: keyData,
                reason: "Approve one test receipt for local-receipt-lab").derRepresentation
            let accepted: Bool = await withCheckedContinuation { continuation in
                proxy.submit(decision, signature: proof) { continuation.resume(returning: $0) }
            }
            guard accepted else {
                if now() >= review.request.expiresAt { throw ReviewError.expired }
                throw ReviewError.invalidProof
            }
            report("native-review-one-receipt-verified")
        } catch {
            await withCheckedContinuation { continuation in proxy.cancel { continuation.resume() } }
            throw error
        }
    }
}
