import AppKit
import CryptoKit
import Foundation
import ReviewCore

struct Prepared: Decodable {
    let approval_shared: String
    let approval_withheld: String
}

func prepare(_ input: Data, machine: String, now: UInt64, capacity: Int = 131072) -> (Int, Data) {
    let machineBytes = Array(machine.utf8)
    var output = [UInt8](repeating: 0xaa, count: capacity)
    let result = input.withUnsafeBytes { inputBytes in
        machineBytes.withUnsafeBufferPointer { machineBuffer in
            output.withUnsafeMutableBufferPointer { outputBuffer in
                sudo_relay_prepare_review(inputBytes.bindMemory(to: UInt8.self).baseAddress, input.count,
                    machineBuffer.baseAddress, machineBuffer.count, now, outputBuffer.baseAddress, outputBuffer.count)
            }
        }
    }
    return (result, Data(result >= 0 ? Array(output.prefix(result)) : output))
}

func unhex(_ value: String) -> Data {
    precondition(value.count % 2 == 0)
    let bytes = Array(value.utf8)
    return Data(stride(from: 0, to: bytes.count, by: 2).map {
        UInt8(String(decoding: bytes[$0..<$0 + 2], as: UTF8.self), radix: 16)!
    })
}

func checkPeerPolicyBoundary() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let policy = Data(#"{"client":"identifier \"test-client\"","service":"identifier \"test-service\""}"#.utf8)
    try policy.write(to: root.appendingPathComponent("policy.json"))
    func bundle(_ settings: [String: Any]) throws -> Bundle {
        let path = root.appendingPathComponent(UUID().uuidString + ".bundle")
        try FileManager.default.createDirectory(at: path.appendingPathComponent("Contents"), withIntermediateDirectories: true)
        var info = settings
        info["CFBundleIdentifier"] = UUID().uuidString
        let data = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        try data.write(to: path.appendingPathComponent("Contents/Info.plist"))
        return Bundle(url: path)!
    }
    let fixture = try bundle(["SudoRelayReceiptFixture": true])
    let loaded = try PeerPolicy.load(from: root, bundle: fixture)
    precondition(loaded.client == "identifier \"test-client\"")
    for settings: [String: Any] in [[:],
        ["SudoRelayReceiptFixture": true, "SudoRelayProtectedPeerPolicyPath": root.appendingPathComponent("policy.json").path],
        ["SudoRelayReceiptFixture": true, "SudoRelayProtectedPeerPolicyPath": root.appendingPathComponent("missing").path],
        ["SudoRelayReceiptFixture": true, "SudoRelayProtectedPeerPolicyPath": 123]] {
        do {
            _ = try PeerPolicy.load(from: root, bundle: bundle(settings))
            preconditionFailure("Unprotected policy or fallback accepted")
        } catch ReviewError.invalidAuthority { }
    }
}

@main
@MainActor
struct Check {
    static func main() throws {
        let root = URL(fileURLWithPath: CommandLine.arguments[1])
        let fixture = try Data(contentsOf: root.appendingPathComponent("ui/test/fixture.json"))
        let object = try JSONSerialization.jsonObject(with: fixture) as! [String: Any]
        let pending = object.filter { ["envelope", "signing_payload", "digest"].contains($0.key) }
        let input = try JSONSerialization.data(withJSONObject: pending)
        let (count, bytes) = prepare(input, machine: "fixture-machine", now: 1700000001)
        precondition(count > 0)
        let review = try JSONDecoder().decode(Prepared.self, from: bytes)
        precondition(review.approval_shared == object["approval_payload_shared"] as? String)
        precondition(review.approval_withheld == object["approval_payload_withheld"] as? String)
        let output = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        precondition(NSDictionary(dictionary: output["envelope"] as! [String: Any]) == NSDictionary(dictionary: object["envelope"] as! [String: Any]))

        // Public software-key vector only; no keychain, biometric prompt or command execution.
        let vector = try JSONDecoder().decode([String: String].self,
            from: Data(contentsOf: root.appendingPathComponent("ui/test/p256-fixture.json")))
        let key = try P256.Signing.PublicKey(x963Representation: unhex(vector["public_key_sec1"]!))
        for (decision, suffix) in [(review.approval_shared, "shared"), (review.approval_withheld, "withheld")] {
            let signature = try P256.Signing.ECDSASignature(derRepresentation: unhex(vector["signature_der_\(suffix)"]!))
            precondition(key.isValidSignature(signature, for: unhex(decision)))
        }
        precondition(prepare(input, machine: "other-machine", now: 1700000001).0 == -1)
        precondition(prepare(input, machine: "fixture-machine", now: 1700000300).0 == -1)
        let tooSmall = prepare(input, machine: "fixture-machine", now: 1700000001, capacity: 8)
        precondition(tooSmall.0 == -2 && tooSmall.1 == Data(repeating: 0xaa, count: 8))
        let native = try BrokerReview(authenticatedPending: input, pairedMachine: "fixture-machine",
            machineName: "local-receipt-lab", operatingSystem: "macOS test", account: "test-user", now: 1700000001)
        let shared = try native.decision(shareOutput: true, now: 1700000001)
        let withheld = try native.decision(shareOutput: false, now: 1700000001)
        precondition(shared == unhex(review.approval_shared) && withheld == unhex(review.approval_withheld))
        precondition(native.commandText() == "/usr/bin/printf hello")
        let details = try native.reviewText()
        for text in ["fixture-machine", "fixture-request", "Directory: /", "Timeout: 300 seconds", "LANG", "TZ", "Print hello", "Agent requests output: false"] {
            precondition(details.contains(text))
        }
        do { _ = try native.decision(shareOutput: true, now: 1700000300); preconditionFailure("expired decision returned") }
        catch ReviewError.expired { }
        _ = NSApplication.shared
        let form = try NativeReviewForm(review: native)
        precondition(form.requestText.string == native.commandText() && !form.requestText.isEditable)
        form.refresh(now: 1700000001)
        precondition(form.approve.isEnabled && form.share.state == .off)
        form.refresh(now: 1700000300)
        precondition(!form.approve.isEnabled && !form.share.isEnabled && form.deny.title == "Close")
        let scriptData = try Data(contentsOf: root.appendingPathComponent("ui/test/native-script-fixture.json"))
        let script = try BrokerReview(authenticatedPending: scriptData, pairedMachine: "fixture-machine",
            machineName: "local-receipt-lab", operatingSystem: "macOS test", account: "test-user", now: 1700000001)
        let scriptForm = try NativeReviewForm(review: script)
        precondition(scriptForm.requestText.string == "printf '%s\\n' 'literal café'\n# Receipt fixture; never executed.")
        precondition(script.commandLabel == "Script · /bin/bash · Not executed")
        let scriptDetails = try script.reviewText()
        precondition(scriptDetails.contains("Interpreter: /bin/bash") && scriptDetails.contains("Timeout: 3600 seconds"))
        precondition(scriptDetails.contains("Review the complete script") && scriptDetails.contains("Agent requests output: true"))
        do {
            _ = try BrokerReview(authenticatedPending: input, pairedMachine: "other-machine",
                machineName: "same-label", operatingSystem: "macOS test", account: "test-user", now: 1700000001)
            preconditionFailure("wrong machine accepted")
        } catch ReviewError.invalidRequest { }
        do {
            _ = try BrokerReview(protectedSocket: root.appendingPathComponent("untrusted.sock"), requestID: "test-reference",
                pairedMachine: "fixture-machine", machineName: "test-host", operatingSystem: "macOS test", account: "test-user", now: 1700000001)
            preconditionFailure("Unprotected native socket accepted")
        } catch ReviewError.invalidAuthority { }
        try checkPeerPolicyBoundary()
        try checkDurableReceipt(root: root)
        let accepted: [String: Any] = ["receipt_only": true, "commands_executed": 0, "approval_consumed": true,
            "reply": ["ok": true, "value": ["id": "expected", "state": "consumed"]]]
        precondition(receiptWasConsumed(accepted, requestID: "expected"))
        precondition(!receiptWasConsumed(accepted, requestID: "different"))
        for (field, value) in [("receipt_only", false as Any), ("commands_executed", 1 as Any),
                               ("approval_consumed", false as Any), ("reply", ["ok": false] as Any),
                               ("receipt_only", 1 as Any), ("commands_executed", false as Any)] {
            var changed = accepted; changed[field] = value
            precondition(!receiptWasConsumed(changed, requestID: "expected"))
        }
        print("Native protocol bridge: exact displayed model, both CBOR proofs, wrong host, expiry and buffer bounds passed. Nothing executed.")
    }
}
