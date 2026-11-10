import Foundation

@main
struct Client {
    static func main() throws {
        guard getuid() != 0 else { exit(2) }
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard arguments.isEmpty || arguments == ["--characterize-without-handshake"] else { exit(2) }
        let root = Bundle.main.bundleURL.deletingLastPathComponent()
        let policy = try PeerPolicy.load(from: root)
        let connection = NSXPCConnection(serviceName: "local.sudo-relay.peer-service")
        connection.remoteObjectInterface = NSXPCInterface(with: PeerReceiptProtocol.self)
        connection.setCodeSigningRequirement(policy.service)
        connection.resume()
        let proxy = connection.remoteObjectProxyWithErrorHandler { @Sendable error in
            report("peer-rejected", error: error)
            exit(1)
        } as! PeerReceiptProtocol
        let sendReceipt: @Sendable () -> Void = {
            proxy.receipt { receipt in
                guard receipt == "peer-check-receipt-only" else { report("invalid-reply"); exit(2) }
                report("receipt-received")
                exit(0)
            }
        }
        if arguments.isEmpty {
            // Peer checks on replies do not prevent an initial call's remote side effects.
            proxy.hello { response in
                guard response == "peer-check-hello" else { report("invalid-hello"); exit(2) }
                report("peer-verified")
                sendReceipt()
            }
        } else {
            // Explicit negative control in this disposable lab only; never a production option.
            sendReceipt()
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
            report("timeout-not-a-security-pass"); exit(2)
        }
        withExtendedLifetime(connection) { dispatchMain() }
    }
}
