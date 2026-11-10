import CryptoKit
import Foundation

public struct Challenge: Encodable, Sendable {
    public let domain = "sudo-relay-touch-id-experiment-v1"
    public let id: UUID
    public let sequence: Int
    public let expiresAt: Int64
    public let machine = "local-experiment-only"
    public let argv = ["/usr/bin/printf", "Touch ID experiment only"]
    public let shareOutput = false

    public init(sequence: Int, now: Date = Date()) {
        id = UUID()
        self.sequence = sequence
        expiresAt = Int64(now.timeIntervalSince1970) + 300
    }

    // This lab format cannot authorize the broker's CBOR/Ed25519 protocol.
    public func bytes() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    public func verify(
        _ signature: P256.Signing.ECDSASignature,
        key: P256.Signing.PublicKey,
        now: Date = Date()
    ) throws -> Bool {
        guard now.timeIntervalSince1970 < Double(expiresAt) else { return false }
        return try key.isValidSignature(signature, for: bytes())
    }
}
