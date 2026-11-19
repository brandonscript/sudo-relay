// Public interoperability fixture only. The random software private key is never written.
import CryptoKit
import Foundation

guard CommandLine.arguments.count == 2 else { fatalError("Pass ui/test/fixture.json") }
let input = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
let fixture = try JSONDecoder().decode([String: FixtureValue].self, from: input)
func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
func decodeHex(_ value: String) throws -> Data {
    guard value.count % 2 == 0 else { throw CocoaError(.fileReadCorruptFile) }
    var bytes = Data()
    var position = value.startIndex
    while position < value.endIndex {
        let end = value.index(position, offsetBy: 2)
        guard let byte = UInt8(value[position..<end], radix: 16) else { throw CocoaError(.fileReadCorruptFile) }
        bytes.append(byte); position = end
    }
    return bytes
}
// Ignore the envelope object; sign only the two existing canonical CBOR test payloads.
enum FixtureValue: Decodable {
    case text(String), ignored
    init(from decoder: any Decoder) throws {
        let value = try decoder.singleValueContainer()
        if let text = try? value.decode(String.self) { self = .text(text) } else { self = .ignored }
    }
}
let key = P256.Signing.PrivateKey()
var result = ["algorithm": "p256-sha256", "public_key_sec1": hex(key.publicKey.x963Representation),
              "source": "CryptoKit software test key; no biometric assertion"]
for suffix in ["shared", "withheld"] {
    guard case let .text(payload)? = fixture["approval_payload_\(suffix)"] else { fatalError("Missing payload") }
    let bytes = try decodeHex(payload)
    let signature = try key.signature(for: bytes)
    precondition(key.publicKey.isValidSignature(signature, for: bytes))
    result["payload_\(suffix)"] = payload
    result["signature_der_\(suffix)"] = hex(signature.derRepresentation)
}
let encoder = JSONEncoder()
encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
let output = try encoder.encode(result)
FileHandle.standardOutput.write(output + Data([10]))
