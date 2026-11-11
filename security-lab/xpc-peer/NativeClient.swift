import AppKit
import CryptoKit
import LocalAuthentication

@main
@MainActor
struct NativeClient {
    static func main() {
        guard getuid() != 0 else { exit(2) }
        umask(0o077)
        if CommandLine.arguments.dropFirst() == ["--enroll-receipt-key"] {
            do { try enrollFixture(); exit(0) }
            catch { report("native-key-enrollment-failed", error: error); exit(1) }
        }
        guard CommandLine.arguments.count == 1 else { exit(2) }
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        Task { @MainActor in
            do { try await review() }
            catch {
                report("native-review-stopped", error: error)
                if requiresErrorNotice(error) {
                    let alert = NSAlert()
                    let notice = reviewFailureNotice(error)
                    alert.messageText = notice.title
                    alert.informativeText = notice.message
                    alert.addButton(withTitle: "Close")
                    alert.runModal()
                }
                exit(1)
            }
            exit(0)
        }
        app.run()
    }

    static func enrollFixture() throws {
        guard Bundle.main.object(forInfoDictionaryKey: "SudoRelayReceiptFixture") as? Bool == true,
              Bundle.main.object(forInfoDictionaryKey: "SudoRelayLabProtocol") as? String == "broker-cbor-v2"
        else { throw ReviewError.invalidAuthority }
        let root = Bundle.main.bundleURL.deletingLastPathComponent()
        let path = root.appendingPathComponent("native-key.json")
        let pin = root.appendingPathComponent("state/keys/native.pub")
        guard !FileManager.default.fileExists(atPath: path.path), !FileManager.default.fileExists(atPath: pin.path)
        else { throw ReviewError.invalidAuthority }
        let data = try BiometricSigning.makeBiometricKey()
        let context = BiometricSigning.context()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: context)
        try FixtureSigningKey(wrappedKey: data, publicKey: key.publicKey.x963Representation).save(to: path)
        let hex = key.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined()
        try Data("p256-sha256:\(hex)".utf8).write(to: pin, options: .withoutOverwriting)
        report("native-key-fixture-enrolled")
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
        let saved = mode == "broker-cbor-v2"
            ? try FixtureSigningKey.load(from: root.appendingPathComponent("native-key.json")) : nil
        let keyData = try saved?.wrappedKey ?? BiometricSigning.makeBiometricKey()
        let lookup = BiometricSigning.context()
        lookup.interactionNotAllowed = true
        defer { lookup.invalidate() }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData, authenticationContext: lookup)
        // Durable fixtures reopen an explicitly enrolled key; missing state never creates a replacement.
        if mode == "broker-cbor-v2" {
            let hex = key.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined()
            guard let saved else { throw ReviewError.invalidAuthority }
            try saved.verify(key.publicKey)
            let pinFile = try FileHandle(forReadingFrom: root.appendingPathComponent("state/keys/native.pub"))
            defer { try? pinFile.close() }
            let pin = try pinFile.read(upToCount: 256) ?? Data()
            guard pin == Data("p256-sha256:\(hex)".utf8) else { throw ReviewError.invalidAuthority }
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
