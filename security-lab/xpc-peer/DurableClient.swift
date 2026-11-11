import CryptoKit
import Foundation

@MainActor
private func brokerCall(_ proxy: any PeerReceiptProtocol, _ request: [String: Any]) async throws -> [String: Any] {
    let input = try JSONSerialization.data(withJSONObject: request)
    let response: Data? = await withCheckedContinuation { continuation in
        proxy.broker(input) { continuation.resume(returning: $0) }
    }
    guard let response, response.count <= 131072,
          let object = try JSONSerialization.jsonObject(with: response) as? [String: Any],
          object["receipt_only"] as? Bool == true, object["commands_executed"] as? Int == 0 else { throw ReviewError.invalidRequest }
    return object
}

@MainActor
func checkDurableXPC(_ proxy: any PeerReceiptProtocol, root: URL) async {
    do {
        // Fixture enrollment is controller-owned, not supplied by the peer's response.
        let config = try JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("broker-config.json"))) as! [String: Any]
        guard let machine = config["machine_id"] as? String else { throw ReviewError.invalidRequest }
        let canary = root.appendingPathComponent("must-not-exist")
        let response = try await brokerCall(proxy, ["method": "request_execution", "spec": [
            "command": ["kind": "argv", "argv": ["/usr/bin/touch", canary.path]],
            "reason": "Receipt-only XPC canary; never execute", "timeout_secs": 30,
        ]])
        guard let reply = response["reply"] as? [String: Any], reply["ok"] as? Bool == true,
              let pending = reply["value"] as? [String: Any], let envelope = pending["envelope"] as? [String: Any],
              let id = envelope["id"] as? String, let number = envelope["number"] as? String else { throw ReviewError.invalidRequest }
        // This method is reached only after the read-only XPC identity handshake succeeds.
        let now = { Int64(Date().timeIntervalSince1970) }
        let review = try BrokerReview(authenticatedPending: JSONSerialization.data(withJSONObject: pending), pairedMachine: machine,
            machineName: "local-receipt-lab", operatingSystem: "macOS test", account: "test-user", now: now())
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: root.appendingPathComponent("fixture-private.key")))
        let proof = try key.signature(for: review.decision(shareOutput: false, now: now())).derRepresentation
        let approval: [String: Any] = ["method": "approve", "id": id, "key_id": "native", "number": number,
            "share_output": false, "signature": proof.map { String(format: "%02x", $0) }.joined()]
        var changed = approval; changed["share_output"] = true
        let altered = try await brokerCall(proxy, changed)
        guard altered["approval_consumed"] as? Bool == false else { throw ReviewError.invalidProof }
        let accepted = try await brokerCall(proxy, approval)
        guard accepted["approval_consumed"] as? Bool == true else { throw ReviewError.invalidProof }
        let replay = try await brokerCall(proxy, approval)
        guard replay["approval_consumed"] as? Bool == false else { throw ReviewError.invalidProof }
        let status = try await brokerCall(proxy, ["method": "execution_status", "id": id])
        let statusReply = status["reply"] as? [String: Any]
        let value = statusReply?["value"] as? [String: Any]
        guard value?["state"] as? String == "consumed", !FileManager.default.fileExists(atPath: canary.path) else { throw ReviewError.invalidProof }
        report("durable-xpc-one-receipt-alteration-and-replay-rejected"); exit(0)
    } catch { report("durable-xpc-failed", error: error); exit(2) }
}
