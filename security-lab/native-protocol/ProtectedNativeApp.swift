import AppKit
import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Receipt-only interactive entry point. No enrollment, key creation or software fallback.
@main
@MainActor
struct ProtectedNativeApp {
    static func main() {
        guard getuid() != 0, CommandLine.arguments.count == 3 else { exit(2) }
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        Task { @MainActor in
            do {
                let decision = try ProtectedReceiptDecision(
                    enrollment: URL(fileURLWithPath: CommandLine.arguments[1]),
                    requestID: CommandLine.arguments[2])
                let panel = try NativeReviewPanel(review: decision.review)
                app.activate(ignoringOtherApps: true)
                guard panel.runReview() else {
                    if Int64(Date().timeIntervalSince1970) < decision.review.expiresAt {
                        try decision.deny()
                    }
                    exit(0)
                }
                let wrapped = try loadSigningKey(account: decision.review.signingKeyAccount)
                let context = BiometricSigning.context()
                context.interactionNotAllowed = true
                defer { context.invalidate() }
                let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrapped,
                    authenticationContext: context)
                try decision.approve(publicKey: key.publicKey, shareOutput: panel.form.share.state == .on) { bytes in
                    try BiometricSigning.signWithBiometrics(bytes, keyData: wrapped,
                        reason: "Approve one sudo-relay test receipt").derRepresentation
                }
                FileHandle.standardOutput.write(Data("One protected receipt verified. Nothing executed.\n".utf8))
                exit(0)
            } catch {
                // Deliberate authentication cancellation and expiry remain quiet.
                if requiresErrorNotice(error) {
                    let notice = reviewFailureNotice(error)
                    let alert = NSAlert()
                    alert.messageText = notice.title
                    alert.informativeText = notice.message
                    alert.addButton(withTitle: "Close")
                    alert.runModal()
                }
                FileHandle.standardError.write(Data("Protected review stopped: \(errorSummary(error))\n".utf8))
                exit(1)
            }
        }
        app.run()
    }

    private static func loadSigningKey(account: String) throws -> Data {
        // Deployment must restrict this data-protection Keychain item to the signed reviewer.
        // Fail rather than prompting to grant a new process access or searching another store.
        let context = BiometricSigning.context()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "sudo-relay.receipt-signer.v1",
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data, !data.isEmpty, data.count <= 4096 else {
            throw ReviewError.invalidAuthority
        }
        return data
    }
}
