import CryptoKit
import Foundation

/// Restart experiment only: this same-user file is not protected enrollment or a Keychain item.
public struct FixtureSigningKey: Codable {
    public let version: Int
    public let wrappedKey: Data
    public let publicKey: Data

    public init(wrappedKey: Data, publicKey: Data) throws {
        version = 1
        self.wrappedKey = wrappedKey
        self.publicKey = publicKey
        try validate()
    }

    private func validate() throws {
        guard version == 1, !wrappedKey.isEmpty, wrappedKey.count <= 4096 else { throw ReviewError.invalidRequest }
        _ = try P256.Signing.PublicKey(x963Representation: publicKey)
    }

    public func save(to path: URL) throws {
        try validate()
        try JSONEncoder().encode(self).write(to: path, options: .withoutOverwriting)
    }

    public static func load(from path: URL) throws -> FixtureSigningKey {
        let file = try FileHandle(forReadingFrom: path)
        defer { try? file.close() }
        let bytes = try file.read(upToCount: 8193) ?? Data()
        guard bytes.count <= 8192 else { throw ReviewError.invalidRequest }
        let value = try JSONDecoder().decode(Self.self, from: bytes)
        try value.validate()
        return value
    }

    public func verify(_ actual: P256.Signing.PublicKey) throws {
        guard publicKey == actual.x963Representation else { throw ReviewError.invalidAuthority }
    }
}
