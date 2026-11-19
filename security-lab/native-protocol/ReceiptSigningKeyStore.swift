import CryptoKit
import Foundation
import Security

/// Lab-only key storage; never imports keys or searches the file-based Keychain.
struct ReceiptSigningKeyStore {
    enum Purpose: String {
        case receipt = "sudo-relay.receipt-signer.v1"
        case executionTrial = "sudo-relay.disposable-linux-signer.v1"
    }
    let group: String
    private let purpose: Purpose

    init(purpose: Purpose = .receipt) throws {
        self.purpose = purpose
        var code: SecCode?
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let entitlements = values[kSecCodeInfoEntitlementsDict as String] as? [String: Any] else {
            throw ReviewError.invalidAuthority
        }
        group = try Self.authorizedGroup(entitlements)
    }

    static func authorizedGroup(_ entitlements: [String: Any]) throws -> String {
        guard let groups = entitlements["keychain-access-groups"] as? [String], groups.count == 1,
              let team = entitlements["com.apple.developer.team-identifier"] as? String,
              team.count == 10, team.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) }),
              groups[0] == "\(team).com.sudorelay.receiptlab.astra",
              entitlements["com.apple.application-identifier"] as? String == groups[0],
              entitlements["com.apple.security.get-task-allow"] as? Bool != true else {
            throw ReviewError.invalidAuthority
        }
        return groups[0]
    }

    static func account(for publicKey: P256.Signing.PublicKey) -> String {
        SHA256.hash(data: publicKey.x963Representation).map { String(format: "%02x", $0) }.joined()
    }

    static func validateAccount(_ account: String) throws {
        guard account.utf8.count == 64,
              account.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw ReviewError.invalidAuthority
        }
    }

    private func query(account: String) throws -> [String: Any] {
        try Self.validateAccount(account)
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: purpose.rawValue,
                kSecAttrAccount as String: account,
                kSecAttrAccessGroup as String: group,
                kSecUseDataProtectionKeychain as String: true,
                kSecAttrSynchronizable as String: false]
    }

    func load(account: String) throws -> Data {
        var query = try query(account: account)
        let context = BiometricSigning.context()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        query[kSecUseAuthenticationContext as String] = context
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw NSError(domain: "sudo-relay.receipt-keychain", code: Int(status)) }
        guard let data = result as? Data, !data.isEmpty, data.count <= 4096 else { throw ReviewError.invalidAuthority }
        return data
    }

    func store(_ wrapped: Data, publicKey: P256.Signing.PublicKey) throws -> String {
        guard !wrapped.isEmpty, wrapped.count <= 4096 else { throw ReviewError.invalidAuthority }
        let account = Self.account(for: publicKey)
        var query = try query(account: account)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        query[kSecValueData as String] = wrapped
        // Add-only: never overwrite or silently repair an existing key.
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: "sudo-relay.receipt-keychain", code: Int(status)) }
        return account
    }

    func remove(account: String) throws {
        let query = try query(account: account)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else { throw NSError(domain: "sudo-relay.receipt-keychain", code: Int(status)) }
    }
}
