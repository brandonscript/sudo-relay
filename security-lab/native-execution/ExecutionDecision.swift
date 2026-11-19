import CryptoKit
import Foundation
import ReviewCore

struct ExecutionReview: NativeReviewContent {
    let broker: BrokerReview
    var title: String { "Approve Linux command" }
    var purposeText: String { "Run this command once on the Linux host shown above." }
    var outputLabel: String { "Share command output with the agent" }
    var commandLabel: String { "Command · Disposable Linux" }
    var subtitle: String { broker.subtitle }
    var createdAt: Int64 { broker.createdAt }
    var expiresAt: Int64 { broker.expiresAt }
    func commandText() -> String { broker.commandText() }
    func reviewText() throws -> String { try broker.detailsText(purpose: "EXECUTION APPROVAL — DISPOSABLE LINUX") }
}

/// Frozen review, one decision attempt, no retry after a possibly delivered proof.
@MainActor
final class ExecutionDecision {
    private struct Enrollment: Decodable {
        let machine_id: String
        let machine_name: String
        let operating_system: String
        let account: String
        let signing_key: String
    }
    private struct Fetched: Decodable {
        let enrollment: Enrollment
        let pending_json: String
    }
    private struct Reference: Encodable {
        let operation: String
        let enrollment: String
        let id: String
        var signature: String? = nil
        var share_output: Bool? = nil
    }
    private let enrollment: URL
    private let publicKey: P256.Signing.PublicKey
    private var attempted = false
    let review: ExecutionReview
    var signingKeyAccount: String { ReceiptSigningKeyStore.account(for: publicKey) }

    init(enrollment: URL, requestID: String) throws {
        self.enrollment = enrollment
        let bytes = try Self.call(Reference(operation: "fetch", enrollment: enrollment.path, id: requestID))
        let fetched = try JSONDecoder().decode(Fetched.self, from: bytes)
        let key = fetched.enrollment.signing_key
        guard key.hasPrefix("p256-sha256:") else { throw ReviewError.invalidAuthority }
        let hex = String(key.dropFirst("p256-sha256:".count))
        guard hex.utf8.count == 130 else { throw ReviewError.invalidAuthority }
        let chars = Array(hex)
        let raw = try Data(stride(from: 0, to: chars.count, by: 2).map {
            guard let byte = UInt8(String(chars[$0...$0+1]), radix: 16) else { throw ReviewError.invalidAuthority }
            return byte
        })
        publicKey = try P256.Signing.PublicKey(x963Representation: raw)
        review = ExecutionReview(broker: try BrokerReview(authenticatedPending: Data(fetched.pending_json.utf8),
            pairedMachine: fetched.enrollment.machine_id, machineName: fetched.enrollment.machine_name,
            operatingSystem: fetched.enrollment.operating_system, account: fetched.enrollment.account,
            now: Int64(Date().timeIntervalSince1970)))
        guard review.broker.requestID == requestID else { throw ReviewError.invalidRequest }
    }

    func deny() throws {
        guard !attempted else { throw ReviewError.alreadyDecided }
        attempted = true
        _ = try Self.call(Reference(operation: "cancel", enrollment: enrollment.path, id: review.broker.requestID))
    }

    func approve(publicKey loadedKey: P256.Signing.PublicKey, shareOutput: Bool,
                 now: () -> Int64 = { Int64(Date().timeIntervalSince1970) }, sign: (Data) throws -> Data) throws {
        guard !attempted else { throw ReviewError.alreadyDecided }
        attempted = true
        guard loadedKey.x963Representation == publicKey.x963Representation else { throw ReviewError.invalidAuthority }
        let bytes = try review.broker.decision(shareOutput: shareOutput, now: now())
        let signature = try sign(bytes)
        _ = try review.broker.decision(shareOutput: shareOutput, now: now())
        guard try publicKey.isValidSignature(P256.Signing.ECDSASignature(derRepresentation: signature), for: bytes) else {
            throw ReviewError.invalidProof
        }
        _ = try Self.call(Reference(operation: "approve", enrollment: enrollment.path, id: review.broker.requestID,
            signature: signature.map { String(format:"%02x", $0) }.joined(), share_output: shareOutput))
    }

    private static func call(_ reference: Reference) throws -> Data {
        let input = try JSONEncoder().encode(reference)
        var output = [UInt8](repeating: 0, count: 131072)
        let count = input.withUnsafeBytes { bytes in
            output.withUnsafeMutableBufferPointer { destination in
                sudo_relay_execution_review(bytes.bindMemory(to: UInt8.self).baseAddress, input.count,
                    destination.baseAddress, destination.count)
            }
        }
        guard count > 0, count <= output.count else {
            if reference.operation == "approve" { throw ReviewError.submissionUnconfirmed }
            throw ReviewError.invalidAuthority
        }
        return Data(output.prefix(count))
    }
}
