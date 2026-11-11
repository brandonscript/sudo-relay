import AppKit
import Foundation

func receiptWasConsumed(_ result: [String: Any], requestID: String) -> Bool {
    struct Acknowledgement: Decodable {
        struct Reply: Decodable {
            struct Value: Decodable { let id: String; let state: String }
            let ok: Bool; let value: Value
        }
        let receipt_only: Bool
        let commands_executed: UInt32
        let approval_consumed: Bool
        let reply: Reply
    }
    guard let bytes = try? JSONSerialization.data(withJSONObject: result),
          let acknowledgement = try? JSONDecoder().decode(Acknowledgement.self, from: bytes)
    else { return false }
    return acknowledgement.receipt_only && acknowledgement.commands_executed == 0
        && acknowledgement.approval_consumed && acknowledgement.reply.ok
        && acknowledgement.reply.value.id == requestID && acknowledgement.reply.value.state == "consumed"
}

@MainActor
private func nativeBrokerCall(_ proxy: any PeerReceiptProtocol, _ request: [String: Any]) async throws -> [String: Any] {
    let input = try JSONSerialization.data(withJSONObject: request)
    let response: Data? = await withCheckedContinuation { continuation in
        proxy.broker(input) { continuation.resume(returning: $0) }
    }
    guard let response, response.count <= 131072,
          let value = try JSONSerialization.jsonObject(with: response) as? [String: Any],
          value["receipt_only"] as? Bool == true, value["commands_executed"] as? Int == 0
    else { throw ReviewError.invalidProof }
    return value
}

@MainActor
func reviewDurableNative(_ proxy: any PeerReceiptProtocol, root: URL, keyData: Data) async throws {
    struct Enrollment: Decodable { let machine_id: String }
    let enrollment = try JSONDecoder().decode(Enrollment.self, from: Data(contentsOf: root.appendingPathComponent("broker-config.json")))
    guard UUID(uuidString: enrollment.machine_id) != nil else { throw ReviewError.invalidAuthority }
    let canary = root.appendingPathComponent("must-not-exist")
    let response = try await nativeBrokerCall(proxy, ["method": "request_execution", "spec": [
        "command": ["kind": "argv", "argv": ["/usr/bin/touch", canary.path]],
        "reason": "Record one test receipt; this command must never execute", "timeout_secs": 30,
    ]])
    guard let reply = response["reply"] as? [String: Any], reply["ok"] as? Bool == true,
          let pending = reply["value"] as? [String: Any] else { throw ReviewError.invalidRequest }
    let now = { Int64(Date().timeIntervalSince1970) }
    let version = ProcessInfo.processInfo.operatingSystemVersion
    let os = "macOS \(version.majorVersion).\(version.minorVersion)" + (version.patchVersion == 0 ? "" : ".\(version.patchVersion)")
    let review = try BrokerReview(authenticatedPending: JSONSerialization.data(withJSONObject: pending), pairedMachine: enrollment.machine_id,
        machineName: "local-receipt-lab", operatingSystem: os, account: "test-user", now: now())
    let panel = try NativeReviewPanel(review: review)
    NSApplication.shared.activate(ignoringOtherApps: true)
    let approved = panel.runReview()
    var submitted = false
    do {
        guard approved else {
            _ = try await nativeBrokerCall(proxy, ["method": "cancel_execution", "id": review.requestID])
            report("native-durable-review-closed"); return
        }
        let share = panel.form.share.state == .on
        let decision = try review.decision(shareOutput: share, now: now())
        let signature = try BiometricSigning.signWithBiometrics(decision, keyData: keyData,
            reason: "Approve one test receipt for local-receipt-lab").derRepresentation
        _ = try review.decision(shareOutput: share, now: now())
        submitted = true
        let result = try await nativeBrokerCall(proxy, ["method": "approve", "id": review.requestID,
            "key_id": "native", "number": review.confirmationNumber, "share_output": share,
            "signature": signature.map { String(format: "%02x", $0) }.joined()])
        if result["approval_consumed"] as? Bool == false,
           let proofReply = result["reply"] as? [String: Any], proofReply["ok"] as? Bool == false,
           now() >= review.expiresAt { throw ReviewError.expired }
        guard receiptWasConsumed(result, requestID: review.requestID), !FileManager.default.fileExists(atPath: canary.path)
        else { throw ReviewError.invalidProof }
        report("native-durable-one-receipt-verified")
    } catch {
        if !submitted {
            if (try? await nativeBrokerCall(proxy, ["method": "cancel_execution", "id": review.requestID])) == nil {
                report("native-durable-cancellation-unconfirmed")
            }
        } else {
            report("native-durable-submission-outcome-unconfirmed")
            if case ReviewError.expired = error { throw error }
            throw ReviewError.submissionUnconfirmed
        }
        throw error
    }
}
