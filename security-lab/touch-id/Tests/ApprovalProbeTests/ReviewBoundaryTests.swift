import AppKit
import ApprovalProbe
import CryptoKit
import Foundation
import Testing

private func edit(_ bytes: Data, key: String, value: Any) throws -> Data {
    var object = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    object[key] = value
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
}

@Test func reviewRequiresPinnedAuthorityAndRejectsTampering() async throws {
    let key = P256.Signing.PrivateKey()
    let verifier = ReviewReceiptVerifier(signer: key.publicKey, now: 1000)
    let packet = try verifier.issue()
    let review = try AuthenticatedReview(bytes: packet.bytes, signature: packet.signature, authority: packet.authority, now: 1000)
    #expect(try review.reviewText().contains("argv[1] = \"Review boundary test only\""))
    #expect(throws: (any Error).self) {
        try AuthenticatedReview(bytes: packet.bytes, signature: packet.signature, authority: Curve25519.Signing.PrivateKey().publicKey, now: 1000)
    }
    let changed = try edit(packet.bytes, key: "argv", value: ["/usr/bin/printf", "different command"])
    #expect(throws: (any Error).self) {
        try AuthenticatedReview(bytes: changed, signature: packet.signature, authority: packet.authority, now: 1000)
    }
}

@Test func authenticatedMalformedOrMisleadingRequestsFailClosed() throws {
    let authority = Curve25519.Signing.PrivateKey()
    let original = try ReviewRequest(enrollment: UUID(), now: 1000).bytes()
    let cases: [(String, Any)] = [
        ("authentication", "session"), ("domain", "sudo-relay/request/v2"), ("machine", "production"),
        ("argv", ["relative", "test"]), ("argv", ["/usr/bin/printf", "safe\u{202E}unsafe"]),
        ("argv", ["/usr/bin/printf", "line\nbreak"]), ("argv", ["/usr/bin/printf", String(repeating: "a", count: 1025)]),
        ("workingDirectory", "/tmp"), ("timeoutSeconds", 301), ("expiresAt", 1301),
        ("createdAt", -1), ("number", "01"), ("extra", "unreviewed field"),
    ]
    for (field, value) in cases {
        let modified = try edit(original, key: field, value: value)
        #expect(throws: (any Error).self) {
            try AuthenticatedReview(bytes: modified, signature: authority.signature(for: modified), authority: authority.publicKey, now: 1000)
        }
    }
    let oversized = Data(repeating: 65, count: 8193)
    #expect(throws: (any Error).self) {
        try AuthenticatedReview(bytes: oversized, signature: authority.signature(for: oversized), authority: authority.publicKey, now: 1000)
    }
}

@Test func verifierBindsRequestOutputModeAndEnrolledKey() async throws {
    let key = P256.Signing.PrivateKey()
    let verifier = ReviewReceiptVerifier(signer: key.publicKey, now: 1000)
    let packet = try verifier.issue()
    let review = try AuthenticatedReview(bytes: packet.bytes, signature: packet.signature, authority: packet.authority, now: 1000)
    let bytes = try review.decision(shareOutput: false, now: 1000)
    let signature = try key.signature(for: bytes).derRepresentation
    let changedRequest = try edit(packet.bytes, key: "argv", value: ["/usr/bin/printf", "changed"])
    for modified in [
        try edit(bytes, key: "shareOutput", value: true), try edit(bytes, key: "authentication", value: "session"),
        try edit(bytes, key: "request", value: changedRequest.base64EncodedString()), try edit(bytes, key: "extra", value: true),
    ] {
        #expect(throws: (any Error).self) { try verifier.consume(decision: modified, signature: signature, now: 1000) }
    }
    let wrongKey = try P256.Signing.PrivateKey().signature(for: bytes).derRepresentation
    #expect(throws: (any Error).self) { try verifier.consume(decision: bytes, signature: wrongKey, now: 1000) }
    // A genuine enrolled-key signature cannot authorize a different stored request or weaker mode.
    for modified in [try edit(bytes, key: "authentication", value: "session"),
                     try edit(bytes, key: "request", value: changedRequest.base64EncodedString())] {
        let validButWrong = try key.signature(for: modified).derRepresentation
        #expect(throws: (any Error).self) { try verifier.consume(decision: modified, signature: validButWrong, now: 1000) }
    }
    let receipt = try verifier.consume(decision: bytes, signature: signature, now: 1000)
    #expect(receipt.id == review.request.id && !receipt.shareOutput)
}

@Test func concurrentReplayAcceptsOneReceiptAndCannotTransferToAnotherVerifier() async throws {
    let key = P256.Signing.PrivateKey()
    let verifier = ReviewReceiptVerifier(signer: key.publicKey, now: 1000)
    let packet = try verifier.issue()
    let review = try AuthenticatedReview(bytes: packet.bytes, signature: packet.signature, authority: packet.authority, now: 1000)
    let bytes = try review.decision(shareOutput: true, now: 1000)
    let signature = try key.signature(for: bytes).derRepresentation
    let accepted = await withTaskGroup(of: Bool.self) { group in
        for _ in 0..<16 { group.addTask { (try? verifier.consume(decision: bytes, signature: signature, now: 1000)) != nil } }
        var count = 0
        for await success in group { if success { count += 1 } }
        return count
    }
    #expect(accepted == 1)
    let another = ReviewReceiptVerifier(signer: key.publicKey, now: 1000)
    #expect(throws: (any Error).self) { try another.consume(decision: bytes, signature: signature, now: 1000) }
}

@Test func denialAndExpiryDuringAuthenticationRejectLateSignatures() async throws {
    let key = P256.Signing.PrivateKey()
    for denied in [false, true] {
        let verifier = ReviewReceiptVerifier(signer: key.publicKey, now: 1000)
        let packet = try verifier.issue()
        let review = try AuthenticatedReview(bytes: packet.bytes, signature: packet.signature, authority: packet.authority, now: 1000)
        let bytes = try review.decision(shareOutput: false, now: 1299)
        let signature = try key.signature(for: bytes).derRepresentation
        if denied { verifier.deny() }
        #expect(throws: (any Error).self) {
            try verifier.consume(decision: bytes, signature: signature, now: denied ? 1299 : 1300)
        }
        #expect(throws: (any Error).self) { try review.decision(shareOutput: false, now: 1300) }
        #expect(throws: (any Error).self) {
            try AuthenticatedReview(bytes: packet.bytes, signature: packet.signature, authority: packet.authority, now: 999)
        }
    }
}

@MainActor
@Test func nativeReviewShowsDecisionWithoutDuplicateNumberEntry() async throws {
    let verifier = ReviewReceiptVerifier(signer: P256.Signing.PrivateKey().publicKey, now: 1000)
    let packet = try verifier.issue()
    let review = try AuthenticatedReview(bytes: packet.bytes, signature: packet.signature, authority: packet.authority, now: 1000)
    let form = try NativeReviewForm(review: review)
    #expect(form.frame.width == 580 && form.frame.height == 466)
    for view in form.subviews {
        #expect(!view.isHidden && !view.frame.isEmpty && form.bounds.contains(view.frame))
    }
    #expect(form.requestText.string == review.commandText())
    #expect(form.requestText.string.contains("/usr/bin/printf 'Review boundary test only'"))
    #expect(!form.requestText.string.contains("Nonce:") && !form.requestText.isEditable)
    #expect(form.share.state == .off)
    #expect(!form.subviews.contains { ($0 as? NSTextField)?.isEditable == true })
    let labels = form.subviews.compactMap { ($0 as? NSTextField)?.stringValue }
    #expect(labels.contains("What you’re approving") && !labels.contains { $0.contains("Execution limit") })
    form.refresh(now: 1000)
    #expect(form.expiry.stringValue == "Approve within 5:00" && form.approve.isEnabled)
    #expect(form.approve.keyEquivalent == "\r")
    form.refresh(now: 1299)
    #expect(form.expiry.stringValue == "Approve within 0:01" && form.approve.isEnabled)
    form.refresh(now: 1300)
    #expect(form.expiry.stringValue == "Approval expired" && !form.approve.isEnabled && !form.share.isEnabled)
    #expect(try review.reviewText().contains("Nonce:"))
}

@Test func nativeCommandPreviewPreservesArgumentBoundaries() throws {
    let authority = Curve25519.Signing.PrivateKey()
    let original = try ReviewRequest(enrollment: UUID(), now: 1000).bytes()
    let bytes = try edit(original, key: "argv", value: ["/usr/bin/printf", "", "a b", "a'b", "$(id)"])
    let review = try AuthenticatedReview(bytes: bytes, signature: authority.signature(for: bytes), authority: authority.publicKey, now: 1000)
    #expect(review.commandText().contains("/usr/bin/printf '' 'a b' 'a'\\''b' '$(id)'"))
}
