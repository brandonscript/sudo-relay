import Foundation
import Security
import ReviewCore

// Receipt-only transport and proof verification; no command runner or human approval.
@objc(SudoRelayPeerReceiptProtocol)
protocol PeerReceiptProtocol: Sendable {
    func hello(reply: @escaping @Sendable (String) -> Void)
    func receipt(reply: @escaping @Sendable (String) -> Void)
    func status(_ id: String, reply: @escaping @Sendable (String) -> Void)
    func cancel(reply: @escaping @Sendable () -> Void)
    func review(reply: @escaping @Sendable (Data?, Data?, Data?) -> Void)
    func submit(_ decision: Data, signature: Data, reply: @escaping @Sendable (Bool) -> Void)
    func broker(_ request: Data, reply: @escaping @Sendable (Data?) -> Void)
}

struct PeerPolicy: Decodable {
    let client: String
    let service: String
    let verifier: String?

    static func load(from root: URL, bundle: Bundle = .main) throws -> PeerPolicy {
        let data: Data
        if let setting = bundle.object(forInfoDictionaryKey: "SudoRelayProtectedPeerPolicyPath") {
            guard let path = setting as? String else { throw ReviewError.invalidAuthority }
            let pathBytes = Array(path.utf8)
            var output = [UInt8](repeating: 0, count: 4096)
            let count = pathBytes.withUnsafeBufferPointer { input in
                output.withUnsafeMutableBufferPointer { buffer in
                    sudo_relay_read_peer_policy(input.baseAddress, input.count, buffer.baseAddress, buffer.count)
                }
            }
            guard count > 0 else { throw ReviewError.invalidAuthority }
            data = Data(output.prefix(count))
        } else {
            // Receipt-only fixtures self-enroll; this is not production pairing.
            guard bundle.object(forInfoDictionaryKey: "SudoRelayReceiptFixture") as? Bool == true else {
                throw ReviewError.invalidAuthority
            }
            data = try Data(contentsOf: root.appendingPathComponent("policy.json"))
        }
        guard data.count <= 4096 else { throw NSError(domain: "PeerLab", code: 1) }
        let policy = try JSONDecoder().decode(Self.self, from: data)
        for value in [policy.client, policy.service] + [policy.verifier].compactMap({ $0 }) {
            var requirement: SecRequirement?
            let result = SecRequirementCreateWithString(value as CFString, [], &requirement)
            guard result == errSecSuccess, requirement != nil else {
                throw NSError(domain: NSOSStatusErrorDomain, code: Int(result))
            }
        }
        return policy
    }
}

func report(_ event: String, error: Error? = nil) {
    var value: [String: String] = ["event": event]
    if let error {
        let error = error as NSError
        value["domain"] = error.domain; value["code"] = String(error.code)
    }
    if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data + Data([10]))
    }
}
