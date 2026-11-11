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
print("Native protocol bridge: exact displayed model, both CBOR proofs, wrong host, expiry and buffer bounds passed. Nothing executed.")
