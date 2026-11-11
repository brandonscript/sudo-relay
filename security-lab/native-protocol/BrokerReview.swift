import CryptoKit
import Foundation
import ReviewCore

/// Requires an authenticated IPC response and a machine identity from trusted enrollment.
/// This value never authenticates its own sender or holds a signing key.
struct BrokerReview: NativeReviewContent {
    private struct Prepared: Decodable, Sendable {
        let envelope: Envelope
        let approval_shared: String
        let approval_withheld: String
    }
    private struct Envelope: Decodable, Sendable {
        let version: Int
        let machine_id: String
        let id: String
        let nonce: String
        let created_at: Int64
        let expires_at: Int64
        let number: String
        let spec: Spec
    }
    private struct Spec: Decodable, Sendable {
        let command: Command
        let env: [String: String]
        let reason: String
        let timeout_secs: Int
        let output_needed: Bool
    }
    private enum Command: Decodable, Sendable {
        case argv([String])
        case script(interpreter: String, body: String)
        private enum CodingKeys: String, CodingKey { case kind, argv, interpreter, script }
        init(from decoder: any Decoder) throws {
            let value = try decoder.container(keyedBy: CodingKeys.self)
            switch try value.decode(String.self, forKey: .kind) {
            case "argv": self = .argv(try value.decode([String].self, forKey: .argv))
            case "script": self = .script(interpreter: try value.decode(String.self, forKey: .interpreter), body: try value.decode(String.self, forKey: .script))
            default: throw ReviewError.invalidRequest
            }
        }
    }

    private let enrolledSigningKey: Data?
    private let prepared: Prepared
    private let shared: Data
    private let withheld: Data
    let subtitle: String
    var createdAt: Int64 { prepared.envelope.created_at }
    var expiresAt: Int64 { prepared.envelope.expires_at }
    var requestID: String { prepared.envelope.id }
    var confirmationNumber: String { prepared.envelope.number }
    var commandLabel: String {
        switch prepared.envelope.spec.command {
        case .argv: return "Example command · Not executed"
        case .script(let interpreter, _): return "Script · \(interpreter) · Not executed"
        }
    }

    init(protectedEnrollment: URL, requestID: String) throws {
        struct Reference: Encodable { let enrollment: String; let id: String }
        struct Labels: Decodable { let machine_name: String; let operating_system: String; let account: String; let signing_key: String }
        struct Fetched: Decodable { let enrollment: Labels; let review: Prepared }
        let reference = try JSONEncoder().encode(Reference(enrollment: protectedEnrollment.path, id: requestID))
        var output = [UInt8](repeating: 0, count: 131072)
        let count = reference.withUnsafeBytes { input in
            output.withUnsafeMutableBufferPointer { destination in
                sudo_relay_fetch_review(input.bindMemory(to: UInt8.self).baseAddress, reference.count,
                    destination.baseAddress, destination.count)
            }
        }
        guard count > 0, count <= output.count else { throw ReviewError.invalidAuthority }
        let fetched = try JSONDecoder().decode(Fetched.self, from: Data(output.prefix(count)))
        guard fetched.enrollment.signing_key.hasPrefix("p256-sha256:") else { throw ReviewError.invalidAuthority }
        enrolledSigningKey = try Self.decodeHex(String(fetched.enrollment.signing_key.dropFirst("p256-sha256:".count)))
        prepared = fetched.review
        shared = try Self.decodeHex(prepared.approval_shared)
        withheld = try Self.decodeHex(prepared.approval_withheld)
        subtitle = "\(fetched.enrollment.machine_name) · \(fetched.enrollment.operating_system) · \(fetched.enrollment.account)"
    }

    init(authenticatedPending: Data, pairedMachine: String, machineName: String,
         operatingSystem: String, account: String, now: Int64) throws {
        guard now >= 0, authenticatedPending.count <= 65536, !pairedMachine.isEmpty,
              pairedMachine.utf8.count <= 256,
              [machineName, operatingSystem, account].allSatisfy({ !$0.isEmpty && $0.utf8.count <= 100
                  && $0.unicodeScalars.allSatisfy { (32...126).contains($0.value) } })
        else { throw ReviewError.invalidRequest }
        let machine = Array(pairedMachine.utf8)
        var output = [UInt8](repeating: 0, count: 131072)
        let count = authenticatedPending.withUnsafeBytes { input in
            machine.withUnsafeBufferPointer { machineBuffer in
                output.withUnsafeMutableBufferPointer { destination in
                    sudo_relay_prepare_review(input.bindMemory(to: UInt8.self).baseAddress, input.count,
                        machineBuffer.baseAddress, machineBuffer.count, UInt64(now), destination.baseAddress, destination.count)
                }
            }
        }
        guard count > 0, count <= output.count else { throw ReviewError.invalidRequest }
        enrolledSigningKey = nil
        prepared = try JSONDecoder().decode(Prepared.self, from: Data(output.prefix(count)))
        shared = try Self.decodeHex(prepared.approval_shared)
        withheld = try Self.decodeHex(prepared.approval_withheld)
        subtitle = "\(machineName) · \(operatingSystem) · \(account)"
    }

    /// Check the loaded key before asking for a fingerprint; the broker still verifies every signature.
    func verifySigningKey(_ publicKey: P256.Signing.PublicKey) throws {
        guard let enrolledSigningKey, enrolledSigningKey == publicKey.x963Representation else {
            throw ReviewError.invalidAuthority
        }
    }

    func decision(shareOutput: Bool, now: Int64) throws -> Data {
        guard now >= createdAt, now < expiresAt else { throw ReviewError.expired }
        return shareOutput ? shared : withheld
    }

    func commandText() -> String {
        switch prepared.envelope.spec.command {
        case .argv(let args): return args.map(quoteReviewArgument).joined(separator: " ")
        case .script(_, let body): return body
        }
    }

    func reviewText() throws -> String {
        let envelope = prepared.envelope
        let spec = envelope.spec
        let command: String
        switch spec.command {
        case .argv(let args):
            command = try args.enumerated().map { "argv[\($0.offset)] = \(try Self.json($0.element))" }.joined(separator: "\n")
        case .script(let interpreter, let body):
            command = "Interpreter: \(interpreter)\nComplete script:\n\(body)"
        }
        return """
        RECEIPT ONLY — NO COMMAND RUNS
        Target: \(subtitle)
        Machine identity: \(envelope.machine_id)
        Request: \(envelope.id)
        Nonce: \(envelope.nonce)
        Protocol version: \(envelope.version)
        Confirmation number: \(envelope.number)
        Valid from/to (Unix seconds): \(createdAt) / \(expiresAt)
        Directory: /
        Timeout: \(spec.timeout_secs) seconds
        Environment: \(try Self.json(spec.env))
        Agent's explanation: \(try Self.json(spec.reason))
        Agent requests output: \(spec.output_needed)
        \(command)
        Output sharing: your checkbox choice is included in the signed decision.
        """
    }

    private static func json<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(value), as: UTF8.self)
    }
    private static func decodeHex(_ value: String) throws -> Data {
        let bytes = Array(value.utf8)
        guard bytes.count.isMultiple(of: 2) else { throw ReviewError.invalidRequest }
        return try Data(stride(from: 0, to: bytes.count, by: 2).map {
            guard let byte = UInt8(String(decoding: bytes[$0..<$0 + 2], as: UTF8.self), radix: 16) else { throw ReviewError.invalidRequest }
            return byte
        })
    }
}
