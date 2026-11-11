import ApprovalProbe
import CryptoKit
import Foundation
import Testing

@Test func fixtureKeyReopensWithoutReplacementOrSilentRecovery() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("key.json")
    let key = P256.Signing.PrivateKey()
    // Fake wrapped bytes exercise storage only, never Secure Enclave reconstruction.
    #expect(throws: (any Error).self) {
        try FixtureSigningKey(wrappedKey: Data(repeating: 0, count: 4097), publicKey: key.publicKey.x963Representation)
    }
    #expect(throws: (any Error).self) {
        try FixtureSigningKey(wrappedKey: Data([1]), publicKey: Data([4]))
    }
    let record = try FixtureSigningKey(wrappedKey: Data([1, 2, 3]), publicKey: key.publicKey.x963Representation)
    #expect(throws: (any Error).self) { try FixtureSigningKey.load(from: path) }
    #expect(!FileManager.default.fileExists(atPath: path.path))
    try record.save(to: path)
    let bytes = try Data(contentsOf: path)
    #expect(throws: (any Error).self) { try record.save(to: path) }
    #expect(try Data(contentsOf: path) == bytes)
    let loaded = try FixtureSigningKey.load(from: path)
    #expect(loaded.wrappedKey == Data([1, 2, 3]))
    try loaded.verify(key.publicKey)
    #expect(throws: (any Error).self) { try loaded.verify(P256.Signing.PrivateKey().publicKey) }
    var invalidVersion = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    invalidVersion["version"] = 2
    for bad in [try JSONSerialization.data(withJSONObject: invalidVersion), Data("{}".utf8), Data(repeating: 0, count: 8193)] {
        try bad.write(to: path)
        #expect(throws: (any Error).self) { try FixtureSigningKey.load(from: path) }
        #expect(try Data(contentsOf: path) == bad)
    }
    try FileManager.default.removeItem(at: path)
    #expect(throws: (any Error).self) { try FixtureSigningKey.load(from: path) }
    #expect(!FileManager.default.fileExists(atPath: path.path))
}
