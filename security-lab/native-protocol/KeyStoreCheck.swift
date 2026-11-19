import CryptoKit
import Foundation

@main
struct KeyStoreCheck {
    static func rejects(_ action: () throws -> Void) {
        do { try action(); fatalError("Invalid key-store input was accepted") }
        catch ReviewError.invalidAuthority { }
        catch { fatalError("Unexpected validation error") }
    }

    static func main() throws {
        let group = "ABCDEFGHIJ.com.sudorelay.receiptlab.astra"
        let valid: [String: Any] = ["keychain-access-groups": [group],
            "com.apple.application-identifier": group, "com.apple.developer.team-identifier": "ABCDEFGHIJ"]
        let accepted = try ReceiptSigningKeyStore.authorizedGroup(valid)
        precondition(accepted == group)
        for mutation: [String: Any] in [
            ["keychain-access-groups": [group, "ABCDEFGHIJ.other"]],
            ["keychain-access-groups": ["ABCDEFGHIJ.other"]],
            ["com.apple.application-identifier": "ABCDEFGHIJ.other"],
            ["com.apple.developer.team-identifier": "ZZZZZZZZZZ"],
            ["com.apple.security.get-task-allow": true],
        ] {
            rejects { _ = try ReceiptSigningKeyStore.authorizedGroup(valid.merging(mutation) { _, new in new }) }
        }
        rejects { _ = try ReceiptSigningKeyStore.authorizedGroup([:]) }
        let key = P256.Signing.PrivateKey().publicKey
        let account = ReceiptSigningKeyStore.account(for: key)
        try ReceiptSigningKeyStore.validateAccount(account)
        for invalid in ["", "../key", String(repeating: "a", count: 63), String(repeating: "g", count: 64), String(repeating: "A", count: 64)] {
            rejects { try ReceiptSigningKeyStore.validateAccount(invalid) }
        }
        print("Key-store boundary validation passed; no Keychain or biometric operations performed.")
    }
}
