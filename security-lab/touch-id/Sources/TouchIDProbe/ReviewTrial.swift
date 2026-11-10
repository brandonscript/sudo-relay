import AppKit
import ApprovalProbe
import CryptoKit
import LocalAuthentication
import Security

extension Probe {
    static func makeBiometricKey() throws -> Data {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                         [.privateKeyUsage, .biometryCurrentSet], &error) else {
            if let error { throw error.takeRetainedValue() }
            throw ProbeError.invalidAccessControl
        }
        let creation = context()
        creation.interactionNotAllowed = true
        defer { creation.invalidate() }
        return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: creation).dataRepresentation
    }

    static func signWithBiometrics(_ bytes: Data, keyData: Data, reason: String) throws -> P256.Signing.ECDSASignature {
        let blocked = context()
        blocked.interactionNotAllowed = true
        defer { blocked.invalidate() }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData, authenticationContext: blocked)
            _ = try key.signature(for: bytes)
            throw ProbeError.noninteractiveSigningSucceeded
        } catch ProbeError.noninteractiveSigningSucceeded {
            throw ProbeError.noninteractiveSigningSucceeded
        } catch {
            print("Noninteractive attempt produced no signature (\(errorSummary(error))).")
        }
        let approval = context()
        approval.localizedReason = reason
        defer { approval.invalidate() }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData, authenticationContext: approval)
        let signature = try key.signature(for: bytes)
        FileHandle.standardOutput.write(Data("Interactive signature returned; verifying receipt next.\n".utf8))
        return signature
    }

    static func runReviewTrial() throws {
        let keyData = try makeBiometricKey()
        let lookup = context()
        lookup.interactionNotAllowed = true
        let publicKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData, authenticationContext: lookup).publicKey
        lookup.invalidate()
        let now = { Int64(Date().timeIntervalSince1970) }
        // Fixture bootstrap: production must pin these keys outside the requesting agent's control.
        let verifier = ReviewReceiptVerifier(signer: publicKey, now: now())
        let packet = try verifier.issue()
        let review = try AuthenticatedReview(bytes: packet.bytes, signature: packet.signature, authority: packet.authority, now: now())
        let panel = try NativeReviewPanel(review: review)
        guard panel.runReview() else {
            verifier.deny()
            let outcome = now() >= review.request.expiresAt ? "expired" : "denied"
            FileHandle.standardOutput.write(Data("Review \(outcome): zero receipts; nothing executed.\n".utf8))
            return
        }
        // Freeze the selected decision before requesting OS authentication. No mutable UI data enters signing afterward.
        let decision = try review.decision(shareOutput: panel.form.share.state == .on, now: now())
        do {
            let signature = try signWithBiometrics(decision, keyData: keyData, reason: "Approve one test receipt for local-receipt-lab")
            let receipt = try verifier.consume(decision: decision, signature: signature.derRepresentation, now: now())
            var replayRejected = false
            do { _ = try verifier.consume(decision: decision, signature: signature.derRepresentation, now: now()) }
            catch ReviewError.alreadyDecided { replayRejected = true }
            guard replayRejected else { throw ProbeError.invalidSignature }
            FileHandle.standardOutput.write(Data("Review receipt verified: \(receipt.id); digest \(receipt.decisionDigest); share output \(receipt.shareOutput); replay rejected; nothing executed.\n".utf8))
        } catch {
            verifier.deny()
            if isAuthenticationCancellation(error) {
                FileHandle.standardOutput.write(Data("Authentication cancelled: zero receipts; nothing executed; no fallback.\n".utf8))
            }
            throw error
        }
    }
}
