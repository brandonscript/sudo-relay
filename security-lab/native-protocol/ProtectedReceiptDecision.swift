import CryptoKit
import Foundation

/// One review attempt. A new object is required after denial, failure or submission.
@MainActor
final class ProtectedReceiptDecision {
    let review: BrokerReview
    private var attempted = false

    init(enrollment: URL, requestID: String) throws {
        review = try BrokerReview(protectedEnrollment: enrollment, requestID: requestID)
    }

    func deny() throws {
        guard !attempted else { throw ReviewError.alreadyDecided }
        attempted = true
        try review.cancelReceipt()
    }

    func approve(publicKey: P256.Signing.PublicKey, shareOutput: Bool,
                 now: () -> Int64 = { Int64(Date().timeIntervalSince1970) },
                 sign: (Data) throws -> Data) throws {
        guard !attempted else { throw ReviewError.alreadyDecided }
        attempted = true
        try review.verifySigningKey(publicKey)
        let bytes = try review.decision(shareOutput: shareOutput, now: now())
        let signature = try sign(bytes)
        // Authentication may outlive the request; never submit a now-expired decision.
        _ = try review.decision(shareOutput: shareOutput, now: now())
        try review.submitReceipt(signature: signature, shareOutput: shareOutput)
    }
}
