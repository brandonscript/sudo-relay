import CryptoKit
import Foundation

/// Disposable CI signer: software key only, no UI, biometrics or command execution.
@main
@MainActor
struct ProtectedReviewCheck {
    private struct Result: Encodable {
        let id: String
        let number: String
        let subtitle: String
        let command: String
        let shared: String
        let withheld: String
        let signature: String
        let consumed: Bool
    }

    static func main() {
        do { try check() }
        catch {
            FileHandle.standardError.write(Data("Native receipt check rejected.\n".utf8))
            exit(1)
        }
    }

    private static func check() throws {
        guard getuid() != 0, ProcessInfo.processInfo.environment["PE_NATIVE_RECEIPT_CHECK"] == "1",
              CommandLine.arguments.count == 3 else { throw ReviewError.invalidRequest }
        let enrollment = URL(fileURLWithPath: CommandLine.arguments[1])
        let decision = try ProtectedReceiptDecision(enrollment: enrollment, requestID: CommandLine.arguments[2])
        let review = decision.review
        guard review.subtitle == "protected-receipt-fixture · Disposable OS fixture · test-user",
              review.commandLabel == "Example command · Not executed" else { throw ReviewError.invalidRequest }
        let now = Int64(Date().timeIntervalSince1970)
        let shared = try review.decision(shareOutput: true, now: now)
        let withheld = try review.decision(shareOutput: false, now: now)
        let keyBytes = try Data(contentsOf: enrollment.deletingLastPathComponent().appendingPathComponent("host/host.key"))
        let key = try P256.Signing.PrivateKey(rawRepresentation: keyBytes)
        try review.verifySigningKey(key.publicKey)
        let wrongSigner = try ProtectedReceiptDecision(enrollment: enrollment, requestID: review.requestID)
        do {
            try wrongSigner.approve(publicKey: P256.Signing.PrivateKey().publicKey, shareOutput: false) { _ in
                preconditionFailure("Wrong key reached signing")
            }
            throw ReviewError.invalidRequest
        } catch ReviewError.invalidAuthority { }
        let cancelledSigning = try ProtectedReceiptDecision(enrollment: enrollment, requestID: review.requestID)
        do {
            try cancelledSigning.approve(publicKey: key.publicKey, shareOutput: false) { _ in
                throw CocoaError(.userCancelled)
            }
            throw ReviewError.invalidRequest
        } catch let error as CocoaError where error.code == .userCancelled { }
        do {
            try cancelledSigning.approve(publicKey: key.publicKey, shareOutput: false) { _ in
                preconditionFailure("Cancelled signing retried")
            }
            throw ReviewError.invalidRequest
        } catch ReviewError.alreadyDecided { }
        let expiredDuringSigning = try ProtectedReceiptDecision(enrollment: enrollment, requestID: review.requestID)
        var checks = 0
        var signatures = 0
        do {
            try expiredDuringSigning.approve(publicKey: key.publicKey, shareOutput: false, now: {
                checks += 1
                return checks == 1 ? now : review.expiresAt
            }) { bytes in
                signatures += 1
                return try key.signature(for: bytes).derRepresentation
            }
            throw ReviewError.invalidRequest
        } catch ReviewError.expired { }
        guard checks == 2, signatures == 1 else { throw ReviewError.invalidRequest }
        do {
            try expiredDuringSigning.approve(publicKey: key.publicKey, shareOutput: false) { _ in
                preconditionFailure("Expired attempt retried signing")
            }
            throw ReviewError.invalidRequest
        } catch ReviewError.alreadyDecided { }
        // The pending request must survive the rejected local attempts for this positive control.
        let signature = try key.signature(for: withheld).derRepresentation
        do {
            try review.submitReceipt(signature: signature, shareOutput: true)
            throw ReviewError.invalidRequest
        } catch ReviewError.submissionUnconfirmed { }
        try decision.approve(publicKey: key.publicKey, shareOutput: false) { bytes in
            guard bytes == withheld else { throw ReviewError.invalidRequest }
            return try key.signature(for: bytes).derRepresentation
        }
        do {
            try decision.approve(publicKey: key.publicKey, shareOutput: false) { _ in
                preconditionFailure("Repeated decision reached signer")
            }
            throw ReviewError.invalidRequest
        } catch ReviewError.alreadyDecided { }
        do {
            try review.submitReceipt(signature: signature, shareOutput: false)
            throw ReviewError.invalidRequest
        } catch ReviewError.submissionUnconfirmed { }
        let result = Result(id: review.requestID, number: review.confirmationNumber,
            subtitle: review.subtitle, command: review.commandText(), shared: hex(shared), withheld: hex(withheld), signature: hex(signature), consumed: true)
        FileHandle.standardOutput.write(try JSONEncoder().encode(result))
    }

    private static func hex(_ bytes: Data) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
