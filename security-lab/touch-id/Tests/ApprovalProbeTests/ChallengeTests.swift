import ApprovalProbe
import CryptoKit
import Foundation
import LocalAuthentication
import Testing

@Test func onlyExplicitAuthenticatorCancellationSuppressesTheErrorNotice() {
    #expect(isAuthenticationCancellation(NSError(domain: LAError.errorDomain, code: LAError.Code.userCancel.rawValue)))
    for code in [LAError.Code.authenticationFailed, .systemCancel, .appCancel, .biometryLockout] {
        #expect(!isAuthenticationCancellation(NSError(domain: LAError.errorDomain, code: code.rawValue)))
    }
    #expect(!isAuthenticationCancellation(NSError(domain: "unrelated", code: LAError.Code.userCancel.rawValue)))
}

@Test func expectedExpiryClosesQuietlyButUnexpectedFailuresRemainVisible() {
    #expect(!requiresErrorNotice(ReviewError.expired))
    #expect(!requiresErrorNotice(NSError(domain: LAError.errorDomain, code: LAError.Code.userCancel.rawValue)))
    for error in [ReviewError.invalidRequest, .invalidAuthority, .invalidProof, .alreadyDecided] {
        #expect(requiresErrorNotice(error))
    }
    #expect(requiresErrorNotice(NSError(domain: "unrelated", code: 2)))
    #expect(requiresErrorNotice(NSError(domain: LAError.errorDomain, code: LAError.Code.authenticationFailed.rawValue)))
    #expect((ReviewError.expired as NSError).domain == "ApprovalProbe.ReviewError")
    #expect((ReviewError.expired as NSError).code == 2)
}

@Test func errorReportingOmitsAuthenticationMetadata() {
    let error = NSError(domain: "com.apple.LocalAuthentication", code: -1004, userInfo: [
        "BiometryDatabaseHash": "private-test-canary", NSLocalizedDescriptionKey: "private-test-canary",
    ])
    #expect(errorSummary(error) == "com.apple.LocalAuthentication -1004")
}

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
