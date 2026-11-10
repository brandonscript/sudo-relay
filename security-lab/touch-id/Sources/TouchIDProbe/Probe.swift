import AppKit
import ApprovalProbe
import CryptoKit
import LocalAuthentication
import Security

enum ProbeError: Error {
    case unavailable, cancelled, noninteractiveSigningSucceeded, invalidSignature, invalidAccessControl
}

@main
@MainActor
struct Probe {
    static func context() -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        return context
    }

    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard arguments == ["--check"] || arguments == ["--run"] else {
            print("Use --check for capability only, or --run for two human-confirmed signing trials.")
            exit(2)
        }
        guard getuid() != 0 else { print("Run as an ordinary user."); exit(2) }
        let capability = context()
        var error: NSError?
        let available = capability.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        let touchID = capability.biometryType == .touchID
        print("Secure Enclave available: \(SecureEnclave.isAvailable)")
        print("Biometric authentication available: \(available)")
        print("Touch ID reported: \(touchID)")
        if let error { print("Capability result: \(errorSummary(error))") }
        capability.invalidate()
        guard arguments == ["--run"] else { return }
        guard available, SecureEnclave.isAvailable, touchID else {
            print("Touch ID test unavailable; no key created and no fallback attempted.")
            exit(1)
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.activate(ignoringOtherApps: true)
        do {
            try run()
            notice("Two signatures verified", "Nothing executed. Tell the researcher whether each request prompted for Touch ID.")
        } catch {
            print("Experiment stopped without further attempts: \(errorSummary(error))")
            notice("Experiment stopped", "No command ran. No fallback was attempted.\n\(errorSummary(error))")
            exit(1)
        }
    }

    static func run() throws {
        var keyData: Data?
        for sequence in 1...2 {
            let challenge = Challenge(sequence: sequence)
            let bytes = try challenge.bytes()
            let review = NSAlert()
            review.messageText = "Touch ID test \(sequence) of 2"
            review.informativeText = "Nothing executes. This signs a fixed experiment request using a temporary Secure Enclave key. No sudo password is used.\n\nExact signed request:\n\(String(decoding: bytes, as: UTF8.self))\n\nThe key's encrypted representation stays in this process and is discarded on exit."
            review.addButton(withTitle: "Sign test request")
            review.addButton(withTitle: "Cancel")
            guard review.runModal() == .alertFirstButtonReturn else { throw ProbeError.cancelled }
            if keyData == nil {
                var error: Unmanaged<CFError>?
                guard let access = SecAccessControlCreateWithFlags(
                    nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    [.privateKeyUsage, .biometryCurrentSet], &error
                ) else {
                    if let error { throw error.takeRetainedValue() }
                    throw ProbeError.invalidAccessControl
                }
                let creation = context()
                creation.interactionNotAllowed = true
                defer { creation.invalidate() }
                keyData = try SecureEnclave.P256.Signing.PrivateKey(
                    accessControl: access, authenticationContext: creation
                ).dataRepresentation
            }
            guard let keyData else { throw ProbeError.unavailable }

            let blocked = context()
            blocked.interactionNotAllowed = true
            do {
                let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData, authenticationContext: blocked)
                _ = try key.signature(for: bytes)
                blocked.invalidate()
                throw ProbeError.noninteractiveSigningSucceeded
            } catch ProbeError.noninteractiveSigningSucceeded {
                throw ProbeError.noninteractiveSigningSucceeded
            } catch {
                print("Test \(sequence): noninteractive attempt produced no signature (\(errorSummary(error))).")
            }
            blocked.invalidate()

            let approval = context()
            approval.localizedReason = "Sign sudo-relay harmless test \(sequence) of 2"
            defer { approval.invalidate() }
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData, authenticationContext: approval)
            let signature = try key.signature(for: bytes)
            guard try challenge.verify(signature, key: key.publicKey) else { throw ProbeError.invalidSignature }
            print("Test \(sequence): signature verified; nothing executed.")
        }
    }

    static func notice(_ title: String, _ message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "Close")
        alert.runModal()
    }
}
