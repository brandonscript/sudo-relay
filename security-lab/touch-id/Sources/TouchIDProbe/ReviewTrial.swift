import AppKit
import ApprovalProbe
import CryptoKit
import LocalAuthentication
import Security

extension Probe {
    static func runReviewTrial() throws {
        let keyData = try BiometricSigning.makeBiometricKey()
        let lookup = BiometricSigning.context()
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
            let signature = try BiometricSigning.signWithBiometrics(decision, keyData: keyData, reason: "Approve one test receipt for local-receipt-lab")
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
