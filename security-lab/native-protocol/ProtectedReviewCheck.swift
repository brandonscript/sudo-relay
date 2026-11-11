import CryptoKit
import Foundation

/// Disposable CI signer: software key only, no UI, biometrics or command execution.
@main
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
        let review = try BrokerReview(protectedEnrollment: enrollment, requestID: CommandLine.arguments[2])
        guard review.subtitle == "protected-receipt-fixture · Disposable OS fixture · test-user",
              review.commandLabel == "Example command · Not executed" else { throw ReviewError.invalidRequest }
        let now = Int64(Date().timeIntervalSince1970)
        let shared = try review.decision(shareOutput: true, now: now)
        let withheld = try review.decision(shareOutput: false, now: now)
        let keyBytes = try Data(contentsOf: enrollment.deletingLastPathComponent().appendingPathComponent("host/host.key"))
        let key = try P256.Signing.PrivateKey(rawRepresentation: keyBytes)
        try review.verifySigningKey(key.publicKey)
        let signature = try key.signature(for: withheld).derRepresentation
        do {
            try review.submitReceipt(signature: signature, shareOutput: true)
            throw ReviewError.invalidRequest
        } catch ReviewError.submissionUnconfirmed { }
        try review.submitReceipt(signature: signature, shareOutput: false)
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
