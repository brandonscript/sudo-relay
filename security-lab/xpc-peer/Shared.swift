import Foundation
import Security

// Receipt-only transport and proof verification; no command runner or human approval.
@objc(SudoRelayPeerReceiptProtocol)
protocol PeerReceiptProtocol: Sendable {
    func hello(reply: @escaping @Sendable (String) -> Void)
    func receipt(reply: @escaping @Sendable (String) -> Void)
    func review(reply: @escaping @Sendable (Data?, Data?, Data?) -> Void)
    func submit(_ decision: Data, signature: Data, reply: @escaping @Sendable (Bool) -> Void)
}

struct PeerPolicy: Decodable {
    let client: String
    let service: String

    static func load(from root: URL) throws -> PeerPolicy {
        let data = try Data(contentsOf: root.appendingPathComponent("policy.json"))
        guard data.count <= 4096 else { throw NSError(domain: "PeerLab", code: 1) }
        let policy = try JSONDecoder().decode(Self.self, from: data)
        for value in [policy.client, policy.service] {
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
