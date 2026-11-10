import CryptoKit
import Foundation

public enum ReviewError: Error { case invalidRequest, invalidAuthority, expired, invalidProof, alreadyDecided }

private func encoded<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(value)
}

/// Lab-only request format. No broker, OS account or execution path accepts it.
public struct ReviewRequest: Codable, Equatable, Sendable {
    public let domain: String
    public let id: UUID
    public let nonce: UUID
    public let operatingSystem: String
    public let account: String
    public let machine: String
    public let enrollment: UUID
    public let createdAt: Int64
    public let expiresAt: Int64
    public let argv: [String]
    public let workingDirectory: String
    public let timeoutSeconds: Int
    public let authentication: String

    public init(enrollment: UUID, now: Int64) {
        domain = "sudo-relay/native-review-lab/request/v1"
        id = UUID(); nonce = UUID(); machine = "local-receipt-lab"; self.enrollment = enrollment
        let version = ProcessInfo.processInfo.operatingSystemVersion
        operatingSystem = "macOS \(version.majorVersion).\(version.minorVersion)" + (version.patchVersion == 0 ? "" : ".\(version.patchVersion)")
        account = "test-user"
        createdAt = now; expiresAt = now + 300
        argv = ["/usr/bin/printf", "Review boundary test only"]
        workingDirectory = "/"; timeoutSeconds = 30; authentication = "touch-id"
    }

    public func bytes() throws -> Data { try encoded(self) }

    fileprivate func validate(now: Int64) throws {
        guard domain == "sudo-relay/native-review-lab/request/v1", machine == "local-receipt-lab",
              operatingSystem.utf8.count <= 40,
              operatingSystem.range(of: #"^macOS [0-9]+\.[0-9]+(?:\.[0-9]+)?$"#, options: .regularExpression) != nil,
              account == "test-user", authentication == "touch-id", workingDirectory == "/", timeoutSeconds == 30,
              argv.count >= 1, argv.count <= 16, argv[0].hasPrefix("/"),
              argv.allSatisfy({ $0.utf8.count <= 1024 && $0.unicodeScalars.allSatisfy { (32...126).contains($0.value) } }),
              createdAt >= 0, expiresAt > createdAt, expiresAt - createdAt <= 300
        else { throw ReviewError.invalidRequest }
        guard now >= createdAt, now < expiresAt else { throw ReviewError.expired }
    }
}

public struct AuthenticatedReview: Sendable {
    public let request: ReviewRequest
    private let requestBytes: Data

    public init(bytes: Data, signature: Data, authority: Curve25519.Signing.PublicKey, now: Int64) throws {
        guard bytes.count <= 8192, signature.count == 64 else { throw ReviewError.invalidRequest }
        guard authority.isValidSignature(signature, for: bytes) else { throw ReviewError.invalidAuthority }
        let request = try JSONDecoder().decode(ReviewRequest.self, from: bytes)
        guard try request.bytes() == bytes else { throw ReviewError.invalidRequest }
        try request.validate(now: now)
        self.request = request; self.requestBytes = bytes
    }

    public func decision(shareOutput: Bool, now: Int64) throws -> Data {
        try request.validate(now: now)
        return try encoded(ReviewDecision(domain: "sudo-relay/native-review-lab/decision/v1",
                                          request: requestBytes, shareOutput: shareOutput, authentication: "touch-id"))
    }

    public func commandText() -> String {
        return request.argv.map { argument in
            argument.unicodeScalars.allSatisfy { CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@%+=:,./-").contains($0) } && !argument.isEmpty
                ? argument : "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
        }.joined(separator: " ")
    }

    // All review text comes from the verified model, never from chat-supplied HTML or a digest.
    public func reviewText() throws -> String {
        let arguments = try request.argv.enumerated().map { index, argument in
            "argv[\(index)] = \(String(decoding: try encoded(argument), as: UTF8.self))"
        }.joined(separator: "\n")
        return """
        RECEIPT ONLY — NO COMMAND RUNS
        Machine: \(request.machine)
        OS: \(request.operatingSystem)
        Account: \(request.account)
        Enrollment: \(request.enrollment)
        Request: \(request.id)
        Nonce: \(request.nonce)
        Valid from/to (Unix seconds): \(request.createdAt) / \(request.expiresAt)
        Authentication: \(request.authentication)
        Directory: \(request.workingDirectory)
        Timeout: \(request.timeoutSeconds) seconds
        Environment: empty (lab does not execute)
        \(arguments)
        Output sharing: your checkbox choice below is included in the signed decision.
        Domain: \(request.domain)
        """
    }
}

private struct ReviewDecision: Codable {
    let domain: String
    let request: Data
    let shareOutput: Bool
    let authentication: String
}

public struct ReviewReceipt: Sendable {
    public let id: UUID
    public let decisionDigest: String
    public let shareOutput: Bool
}

/// In-memory receipt verifier, deliberately separate from UI and signing callbacks.
/// shortcut: process-local state only; durable recovery and protected enrollment remain deployment work.
// All mutable state and key operations are protected by lock; AppKit callers need synchronous completion.
public final class ReviewReceiptVerifier: @unchecked Sendable {
    private let lock = NSLock()
    private let request: ReviewRequest
    private let signer: P256.Signing.PublicKey
    private let authority: Curve25519.Signing.PrivateKey
    private var decided = false

    public init(signer: P256.Signing.PublicKey, now: Int64) {
        request = ReviewRequest(enrollment: UUID(), now: now)
        self.signer = signer; authority = Curve25519.Signing.PrivateKey()
    }

    public func issue() throws -> (bytes: Data, signature: Data, authority: Curve25519.Signing.PublicKey) {
        lock.lock(); defer { lock.unlock() }
        guard !decided else { throw ReviewError.alreadyDecided }
        let bytes = try request.bytes()
        return (bytes, try authority.signature(for: bytes), authority.publicKey)
    }

    public func deny() {
        lock.lock(); defer { lock.unlock() }
        decided = true
    }

    public func consume(decision bytes: Data, signature: Data, now: Int64) throws -> ReviewReceipt {
        lock.lock(); defer { lock.unlock() }
        guard !decided else { throw ReviewError.alreadyDecided }
        try request.validate(now: now)
        guard bytes.count <= 16384, signature.count <= 80 else { throw ReviewError.invalidProof }
        let decision = try JSONDecoder().decode(ReviewDecision.self, from: bytes)
        guard decision.domain == "sudo-relay/native-review-lab/decision/v1", decision.authentication == "touch-id",
              try decision.request == request.bytes(), try encoded(decision) == bytes,
              signer.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: signature), for: bytes)
        else { throw ReviewError.invalidProof }
        decided = true
        return ReviewReceipt(id: request.id, decisionDigest: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(),
                             shareOutput: decision.shareOutput)
    }
}
