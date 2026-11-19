import Foundation
import LocalAuthentication
import Security

// Only a public disposable marker: never query the reviewer's signing-key service.
let arguments = CommandLine.arguments
guard arguments.count == 4, UUID(uuidString: arguments[3]) != nil else { exit(2) }
let context = LAContext()
context.interactionNotAllowed = true
defer { context.invalidate() }
var query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "sudo-relay.keychain-boundary-test.v1",
    kSecAttrAccount as String: arguments[3],
    kSecUseDataProtectionKeychain as String: true,
    kSecUseAuthenticationContext as String: context,
    kSecAttrSynchronizable as String: false,
]
if arguments[2] != "unscoped" { query[kSecAttrAccessGroup as String] = arguments[2] }
let marker = Data("Public receipt-only access-test marker; not a credential.".utf8)
let status: OSStatus
switch arguments[1] {
case "create":
    query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    query[kSecValueData as String] = marker
    status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { print("create failed: \(status)"); exit(1) }
case "read", "denied":
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    status = SecItemCopyMatching(query as CFDictionary, &result)
    if arguments[1] == "read" {
        guard status == errSecSuccess, result as? Data == marker else {
            print("read failed: \(status)"); exit(1)
        }
    } else {
        guard status == errSecMissingEntitlement || status == errSecItemNotFound else {
            print("denial not established: \(status)"); exit(1)
        }
    }
case "delete":
    status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess else { print("delete failed: \(status)"); exit(1) }
default: exit(2)
}
#if SUBSTITUTE
print("substitute \(arguments[1]): \(status)")
#else
print("probe \(arguments[1]): \(status)")
#endif
