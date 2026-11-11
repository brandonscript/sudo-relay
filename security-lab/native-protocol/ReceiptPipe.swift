import Foundation

/// Receipt-lab child process only. Owners serialize access; failures never restart the child.
final class ReceiptProcess {
    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private var started = false

    init(executable: URL, config: URL) throws {
        process.executableURL = executable
        process.arguments = [config.path]
        process.environment = ProcessInfo.processInfo.environment.merging(["SUDO_RELAY_RECEIPT_LAB": "1"]) { _, new in new }
        process.standardInput = input; process.standardOutput = output
        try process.run()
        started = true
    }

    func call(_ request: [String: Any]) throws -> [String: Any] {
        let response = try exchange(JSONSerialization.data(withJSONObject: request))
        guard let value = try JSONSerialization.jsonObject(with: response) as? [String: Any] else { throw ReviewError.invalidRequest }
        return value
    }

    func exchange(_ request: Data) throws -> Data {
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

