import AppKit
import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Separate disposable-Linux execution reviewer; never loads receipt signing keys.
@main
@MainActor
struct ExecutionNativeApp {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard getuid() != 0, arguments == ["--enroll"] || arguments.count == 2 else { exit(2) }
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        Task { @MainActor in
            do {
                let store = try ReceiptSigningKeyStore(purpose: .executionTrial)
                if arguments == ["--enroll"] {
                    try enroll(store: store)
                    exit(0)
                }
                if arguments[0] == "--remove-key" {
                    try removeKey(store: store, account: arguments[1])
                    exit(0)
                }
                let decision = try ExecutionDecision(
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
                let wrapped = try store.load(account: decision.signingKeyAccount)
                let context = BiometricSigning.context()
                context.interactionNotAllowed = true
                defer { context.invalidate() }
                let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrapped,
                    authenticationContext: context)
                try decision.approve(publicKey: key.publicKey, shareOutput: panel.form.share.state == .on) { bytes in
                    try BiometricSigning.signWithBiometrics(bytes, keyData: wrapped,
                        reason: "Approve one command in disposable Linux").derRepresentation
                }
                FileHandle.standardOutput.write(Data("Execution approval accepted. Check MCP status for completion.\n".utf8))
                exit(0)
            } catch {
                // Deliberate authentication cancellation and expiry remain quiet.
                if requiresErrorNotice(error) {
                    let notice = executionFailureNotice(error)
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

    private static func publicKey(_ wrapped: Data) throws -> P256.Signing.PublicKey {
        let context = BiometricSigning.context()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrapped,
            authenticationContext: context).publicKey
    }

    private static func confirm(title: String, message: String, action: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: action)
        alert.addButton(withTitle: "Cancel")
        NSApplication.shared.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
    }

    private static func enroll(store: ReceiptSigningKeyStore) throws {
        guard confirm(title: "Set up a Linux trial approval key",
            message: "Create a separate Touch ID key for the disposable Linux execution trial. Only its public key is exported. Administrator pairing is still required before commands can run.",
            action: "Set up with Touch ID") else { return }
        let wrapped = try BiometricSigning.makeBiometricKey()
        let key = try publicKey(wrapped)
        let challenge = Data("sudo-relay/disposable-linux-key-setup/v1:\(UUID().uuidString)".utf8)
        let signature = try BiometricSigning.signWithBiometrics(challenge, keyData: wrapped,
            reason: "Set up one sudo-relay Linux trial key")
        guard key.isValidSignature(signature, for: challenge) else { throw ReviewError.invalidProof }
        let account = try store.store(wrapped, publicKey: key)
        print("Stored Linux-trial key fingerprint: \(account)")
        do {
            let loaded = try store.load(account: account)
            guard try publicKey(loaded).x963Representation == key.x963Representation else {
                throw ReviewError.invalidAuthority
            }
            struct PublicCandidate: Encodable {
                let version = 1
                let receipt_only = false
                let purpose = "execution-lab-public-key-candidate-not-paired"
                let signing_key: String
                let keychain_account: String
                let keychain_group: String
                let approver_uid: UInt32
            }
            let candidate = PublicCandidate(signing_key: "p256-sha256:" + key.x963Representation.map {
                String(format: "%02x", $0)
            }.joined(), keychain_account: account, keychain_group: store.group, approver_uid: getuid())
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let output = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(
                "Downloads/sudo-relay-execution-key-\(account).json")
            try encoder.encode(candidate).write(to: output, options: .withoutOverwriting)
            print("Test key stored and read back. Public candidate: \(output.path)")
            print("No verifier paired. Nothing executed.")
        } catch {
            // Avoid leaving an unreported key when readback or public export fails.
            try store.remove(account: account)
            throw error
        }
    }

    private static func removeKey(store: ReceiptSigningKeyStore, account: String) throws {
        try ReceiptSigningKeyStore.validateAccount(account)
        guard confirm(title: "Remove this test approval key?", message: "Key fingerprint: \(account)\nThis removes only its local Linux-trial key. Broker revocation is a separate step.",
                      action: "Remove with Touch ID") else { return }
        let wrapped = try store.load(account: account)
        let key = try publicKey(wrapped)
        guard ReceiptSigningKeyStore.account(for: key) == account else { throw ReviewError.invalidAuthority }
        let challenge = Data("sudo-relay/disposable-linux-key-removal/v1:\(UUID().uuidString)".utf8)
        let signature = try BiometricSigning.signWithBiometrics(challenge, keyData: wrapped,
            reason: "Remove one sudo-relay Linux trial key")
        guard key.isValidSignature(signature, for: challenge) else { throw ReviewError.invalidProof }
        try store.remove(account: account)
        print("Test key removed. Nothing executed.")
    }
}
