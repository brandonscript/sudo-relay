import Foundation
import Security

/// Receipt-lab child process only. Owners serialize access; failures never restart the child.
final class ReceiptProcess {
    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private var started = false
    private let requirement: SecRequirement?
    private var childCode: SecCode?

    init(executable: URL, config: URL, expectedCode: String? = nil) throws {
        var parsed: SecRequirement?
        if let expectedCode {
            guard SecRequirementCreateWithString(expectedCode as CFString, [], &parsed) == errSecSuccess,
                  let parsed else { throw ReviewError.invalidAuthority }
            var fileCode: SecStaticCode?
            guard SecStaticCodeCreateWithPath(executable as CFURL, [], &fileCode) == errSecSuccess,
                  let fileCode,
                  SecStaticCodeCheckValidity(fileCode, SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)), parsed) == errSecSuccess
            else { throw ReviewError.invalidAuthority }
        }
        requirement = parsed
        process.executableURL = executable
        process.arguments = [config.path]
        process.environment = ["SUDO_RELAY_RECEIPT_LAB": "1"]
        process.standardInput = input; process.standardOutput = output
        try process.run()
        started = true
        if let requirement {
            let attributes = [kSecGuestAttributePid as String: process.processIdentifier] as CFDictionary
            guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &childCode) == errSecSuccess,
                  let childCode, SecCodeCheckValidity(childCode, [], requirement) == errSecSuccess
            else { stop(); throw ReviewError.invalidAuthority }
        }
    }

    func call(_ request: [String: Any]) throws -> [String: Any] {
        let response = try exchange(JSONSerialization.data(withJSONObject: request))
        guard let value = try JSONSerialization.jsonObject(with: response) as? [String: Any] else { throw ReviewError.invalidRequest }
        return value
    }

    func exchange(_ request: Data) throws -> Data {
        if let requirement {
            guard process.isRunning, let childCode,
                  SecCodeCheckValidity(childCode, [], requirement) == errSecSuccess
            else { throw ReviewError.invalidAuthority }
        }
        guard request.count < 65536, !request.contains(10), !request.contains(13) else { throw ReviewError.invalidRequest }
        var bytes = request; bytes.append(10)
        try input.fileHandleForWriting.write(contentsOf: bytes)
        var response = Data()
        while response.count <= 131072 {
            guard let byte = try output.fileHandleForReading.read(upToCount: 1), !byte.isEmpty else { throw ReviewError.invalidRequest }
            if byte == Data([10]) { break }
            response.append(byte)
        }
        guard response.count <= 131072,
              let value = try JSONSerialization.jsonObject(with: response) as? [String: Any],
              value["receipt_only"] as? Bool == true, value["commands_executed"] as? Int == 0
        else { throw ReviewError.invalidRequest }
        return response
    }

    func stop() {
        guard started else { return }
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
        started = false
    }
    deinit { stop() }
}

