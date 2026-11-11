import CryptoKit
import Foundation
import LocalAuthentication
import Security

public enum BiometricSigningError: Error { case invalidAccessControl, noninteractiveSigningSucceeded }

public enum BiometricSigning {
    public static func context() -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        return context
    }

    public static func makeBiometricKey() throws -> Data {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                         [.privateKeyUsage, .biometryCurrentSet], &error) else {
            if let error { throw error.takeRetainedValue() }
            throw BiometricSigningError.invalidAccessControl
        }
        let creation = context()
        creation.interactionNotAllowed = true
        defer { creation.invalidate() }
        return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: creation).dataRepresentation
    }

    public static func signWithBiometrics(_ bytes: Data, keyData: Data, reason: String) throws -> P256.Signing.ECDSASignature {
        let blocked = context()
        blocked.interactionNotAllowed = true
        defer { blocked.invalidate() }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData, authenticationContext: blocked)
            _ = try key.signature(for: bytes)
            throw BiometricSigningError.noninteractiveSigningSucceeded
        } catch BiometricSigningError.noninteractiveSigningSucceeded {
            throw BiometricSigningError.noninteractiveSigningSucceeded
        } catch {
            print("Noninteractive attempt produced no signature (\(errorSummary(error))).")
        }
        let approval = context()
        approval.localizedReason = reason
        defer { approval.invalidate() }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData, authenticationContext: approval)
        let signature = try key.signature(for: bytes)
        FileHandle.standardOutput.write(Data("Interactive signature returned; verifying receipt next.\n".utf8))
        return signature
    }

}
