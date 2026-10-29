import AegisCore
import Flutter
import Foundation
import NetworkExtension

/// The Flutter channel `aegisborne/client` on iOS (lib/client.dart). Joined
/// servers live in the App Group container, shared with the packet tunnel
/// (AegisTunnel), which runs the connection; the app starts and stops it
/// through NETunnelProviderManager and asks it for status. Results are the
/// Rust core's JSON, as on Android.
final class AegisChannel {
    static let appGroup = "group.borne.aegis.app"
    static let tunnelBundle = "borne.aegis.app.tunnel"
    private let queue = DispatchQueue(label: "aegis.core")
    /// The VPN configuration, once loaded.
    private var manager: NETunnelProviderManager?

    static var dir: String {
        let base = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
            ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("aegis").path
    }

    /// Call the core; returns its JSON text.
    static func core(_ f: () -> UnsafeMutablePointer<CChar>?) -> String {
        guard let p = f() else { return failure("no answer") }
        defer { aegis_free(p) }
        return String(cString: p)
    }

    static func text(_ value: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: value) else { return "{}" }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    static func object(_ text: String) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] ?? [:]
    }

    static func failure(_ message: String) -> String { text(["ok": false, "error": message]) }
    static let ok = #"{"ok":true}"#

    func register(messenger: FlutterBinaryMessenger) {
        let channel = FlutterMethodChannel(name: "aegisborne/client", binaryMessenger: messenger)
        channel.setMethodCallHandler { [weak self] call, result in
            self?.handle(call, result)
        }
    }

    private func handle(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any] ?? [:]
        let dir = Self.dir
        switch call.method {
        case "servers":
            background(result) { Self.core { aegis_servers(dir) } }
        case "select":
            let id = args["id"] as? String ?? ""
            background(result) { Self.core { aegis_select(dir, id) } }
        case "enroll":
            let code = args["code"] as? String ?? ""
            background(result) { Self.core { aegis_enroll(dir, code) } }
        case "forget":
            forget(args["id"] as? String ?? "", result)
        case "connect":
            connect(result)
        case "disconnect":
            withManager { manager in
                manager?.connection.stopVPNTunnel()
                result(Self.ok)
            }
        case "status":
            status(result)
        case "sharedText":
            // Sharing an invitation into the app needs a share extension.
            result(nil)
        default:
            // Moving from the old Android app and app updates: Android only.
            result(FlutterMethodNotImplemented)
        }
    }

    private func background(_ result: @escaping FlutterResult, _ work: @escaping () -> String) {
        queue.async {
            let out = work()
            DispatchQueue.main.async { result(out) }
        }
    }

    /// The saved VPN configuration for the tunnel, if there is one.
    private func withManager(_ done: @escaping (NETunnelProviderManager?) -> Void) {
        if let manager {
            done(manager)
            return
        }
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            let found = managers?.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.tunnelBundle
            }
            DispatchQueue.main.async {
                self.manager = found
                done(found)
            }
        }
    }

    /// Save the VPN configuration (iOS asks the user the first time) and
    /// start the tunnel for the selected server.
    private func connect(_ result: @escaping FlutterResult) {
        let servers = Self.object(Self.core { aegis_servers(Self.dir) })
        let selected = servers["selected"] as? String
        let host = (servers["servers"] as? [[String: Any]])?
            .first { $0["id"] as? String == selected }?["server"] as? String
        withManager { existing in
            let manager = existing ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.tunnelBundle
            proto.serverAddress = host ?? "AegisBorne"
            manager.protocolConfiguration = proto
            manager.localizedDescription = "AegisBorne"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error {
                    DispatchQueue.main.async {
                        result(Self.failure("iOS didn't allow the VPN configuration: \(error.localizedDescription)"))
                    }
                    return
                }
                // Reload before starting, or the first start fails.
                manager.loadFromPreferences { _ in
                    DispatchQueue.main.async {
                        self.manager = manager
                        do {
                            try manager.connection.startVPNTunnel()
                            result(Self.ok)
                        } catch {
                            result(Self.failure("Could not start the VPN: \(error.localizedDescription)"))
                        }
                    }
                }
            }
        }
    }

    /// The tunnel's status from the extension while it runs; otherwise
    /// disconnected, with why the last connection ended.
    private func status(_ result: @escaping FlutterResult) {
        withManager { manager in
            guard let manager, let session = manager.connection as? NETunnelProviderSession else {
                result(Self.text(["ok": true, "state": "disconnected"]))
                return
            }
            switch session.status {
            case .connected, .connecting, .reasserting:
                let connecting = Self.text(["ok": true, "state": "connecting"])
                do {
                    try session.sendProviderMessage(Data("status".utf8)) { data in
                        let text = data.flatMap { String(data: $0, encoding: .utf8) }
                        DispatchQueue.main.async { result(text ?? connecting) }
                    }
                } catch {
                    result(connecting)
                }
            default:
                session.fetchLastDisconnectError { error in
                    var out: [String: Any] = ["ok": true, "state": "disconnected"]
                    if let error, (error as NSError).domain == "AegisBorne" {
                        out["error"] = error.localizedDescription
                    }
                    DispatchQueue.main.async { result(Self.text(out)) }
                }
            }
        }
    }

    /// Remove a server; when it is the connected one, stop the tunnel first
    /// (the extension uses its identity while connected).
    private func forget(_ id: String, _ result: @escaping FlutterResult) {
        let dir = Self.dir
        let remove = { self.background(result) { Self.core { aegis_forget(dir, id) } } }
        withManager { manager in
            guard let manager, let session = manager.connection as? NETunnelProviderSession,
                  session.status != .disconnected, session.status != .invalid
            else {
                remove()
                return
            }
            do {
                try session.sendProviderMessage(Data("status".utf8)) { data in
                    let status = Self.object(data.flatMap { String(data: $0, encoding: .utf8) } ?? "")
                    guard status["server_id"] as? String == id else {
                        DispatchQueue.main.async { remove() }
                        return
                    }
                    session.stopVPNTunnel()
                    self.queue.async {
                        // Up to 10 s for the extension to let go.
                        for _ in 0..<50 where session.status != .disconnected {
                            Thread.sleep(forTimeInterval: 0.2)
                        }
                        DispatchQueue.main.async { remove() }
                    }
                }
            } catch {
                remove()
            }
        }
    }
}
