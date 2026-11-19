import CryptoKit
import Foundation

func checkDurableReceipt(root: URL) throws {
    let fm = FileManager.default
    let directory = fm.temporaryDirectory.appendingPathComponent("sudo-relay-durable-\(UUID().uuidString)")
    try fm.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? fm.removeItem(at: directory) }
    let state = directory.appendingPathComponent("state")
    let keys = state.appendingPathComponent("keys")
    try fm.createDirectory(at: state, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    try fm.createDirectory(at: keys, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let machine = UUID().uuidString.lowercased()
    let config = directory.appendingPathComponent("config.json")
    try JSONSerialization.data(withJSONObject: [
        "machine_id": machine, "agent_uid": getuid(), "approver_uid": getuid(), "socket_gid": getgid(),
        "state_dir": state.path, "socket": directory.appendingPathComponent("unused.sock").path,
    ]).write(to: config)
    let signingKey = P256.Signing.PrivateKey()
    let publicHex = signingKey.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined()
    guard fm.createFile(atPath: keys.appendingPathComponent("native.pub").path,
        contents: Data("p256-sha256:\(publicHex)".utf8), attributes: [.posixPermissions: 0o600]) else { throw ReviewError.invalidRequest }
    let executable = root.appendingPathComponent("target/debug/receipt-verifier")
    let first = try ReceiptProcess(executable: executable, config: config)
    defer { first.stop() }
    let canary = directory.appendingPathComponent("must-not-exist")
    let request: [String: Any] = ["method": "request_execution", "spec": [
        "command": ["kind": "argv", "argv": ["/usr/bin/touch", canary.path]],
        "reason": "Receipt-only canary; never execute", "timeout_secs": 30,
    ]]
    let response = try first.call(request)
    guard let reply = response["reply"] as? [String: Any], reply["ok"] as? Bool == true,
          let pending = reply["value"] as? [String: Any], let envelope = pending["envelope"] as? [String: Any],
          let id = envelope["id"] as? String, let number = envelope["number"] as? String else { throw ReviewError.invalidRequest }
    let now = { Int64(Date().timeIntervalSince1970) }
    let review = try BrokerReview(authenticatedPending: JSONSerialization.data(withJSONObject: pending), pairedMachine: machine,
        machineName: "local-receipt-lab", operatingSystem: "macOS test", account: "test-user", now: now())
    let decision = try review.decision(shareOutput: false, now: now())
    let signature = try signingKey.signature(for: decision).derRepresentation.map { String(format: "%02x", $0) }.joined()
    let approval: [String: Any] = ["method": "approve", "id": id, "key_id": "native", "number": number,
                                  "share_output": false, "signature": signature]
    var changed = approval; changed["share_output"] = true
    let altered = try first.call(changed)
    precondition(altered["approval_consumed"] as? Bool == false)
    let accepted = try first.call(approval)
    precondition(accepted["approval_consumed"] as? Bool == true)
    let replay = try first.call(approval)
    precondition(replay["approval_consumed"] as? Bool == false)
    first.stop()
    let replacement = try ReceiptProcess(executable: executable, config: config)
    defer { replacement.stop() }
    let status = try replacement.call(["method": "execution_status", "id": id])
    let statusReply = status["reply"] as? [String: Any]
    let statusValue = statusReply?["value"] as? [String: Any]
    precondition(statusValue?["state"] as? String == "uncertain")
    let replayAfterRestart = try replacement.call(approval)
    precondition(replayAfterRestart["approval_consumed"] as? Bool == false)
    let fresh = try replacement.call(request)
    guard let freshReply = fresh["reply"] as? [String: Any], let freshPending = freshReply["value"] as? [String: Any],
          let freshEnvelope = freshPending["envelope"] as? [String: Any], let freshID = freshEnvelope["id"] as? String,
          let freshNumber = freshEnvelope["number"] as? String else { throw ReviewError.invalidRequest }
    var transferred = approval; transferred["id"] = freshID; transferred["number"] = freshNumber
    let wrongRequest = try replacement.call(transferred)
    precondition(wrongRequest["approval_consumed"] as? Bool == false)
    _ = try replacement.call(["method": "cancel_execution", "id": freshID])
    precondition(!fm.fileExists(atPath: canary.path))
    print("Durable native receipt: altered sharing rejected, consumed once, replay rejected before/after process restart, cross-request transfer rejected, canary absent.")
}
