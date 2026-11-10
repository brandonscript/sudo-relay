import ApprovalProbe
import CryptoKit
import Foundation
import Testing

@Test func signatureBindsTheExactRequest() throws {
    let now = Date(timeIntervalSince1970: 1000)
    let original = Challenge(sequence: 1, now: now)
    let key = P256.Signing.PrivateKey()
    let signature = try key.signature(for: original.bytes())
    #expect(try original.verify(signature, key: key.publicKey, now: now))
    #expect(try !Challenge(sequence: 1, now: now).verify(signature, key: key.publicKey, now: now))
    #expect(try !original.verify(signature, key: P256.Signing.PrivateKey().publicKey, now: now))

    let text = String(decoding: try original.bytes(), as: UTF8.self)
    for modified in [
        text.replacingOccurrences(of: "Touch ID experiment only", with: "different command"),
        text.replacingOccurrences(of: "\"shareOutput\":false", with: "\"shareOutput\":true"),
        text.replacingOccurrences(of: "local-experiment-only", with: "another-machine"),
    ] {
        #expect(modified != text)
        #expect(!key.publicKey.isValidSignature(signature, for: Data(modified.utf8)))
    }
}

@Test func expirationRejectsAnOtherwiseValidSignature() throws {
    let challenge = Challenge(sequence: 1, now: Date(timeIntervalSince1970: 1000))
    let key = P256.Signing.PrivateKey()
    let signature = try key.signature(for: challenge.bytes())
    #expect(try challenge.verify(signature, key: key.publicKey, now: Date(timeIntervalSince1970: 1299)))
    #expect(try !challenge.verify(signature, key: key.publicKey, now: Date(timeIntervalSince1970: 1300)))
}
