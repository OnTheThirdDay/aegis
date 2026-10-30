import AegisCore
import Flutter
import Foundation
import NetworkExtension
import UIKit

/// The Flutter channel `aegisborne/client` on iOS (lib/client.dart). Joined
/// servers live in the App Group container, shared with the packet tunnel
/// (AegisTunnel), which runs the connection; the app starts and stops it
/// through NETunnelProviderManager and asks it for status. Results are the
/// Rust core's JSON, as on Android.
///
/// Diagnostics record in the extension (where the connection runs): while
/// it runs the app passes the calls on; otherwise starting a recording
/// connects with it, and the last outcome (and a report the extension
/// saved because it couldn't send it) comes from the shared container.
final class AegisChannel {
    static let appGroup = "group.borne.aegis.app"
    static let tunnelBundle = "borne.aegis.app.tunnel"
    private let queue = DispatchQueue(label: "aegis.core")
    /// The VPN configuration, once loaded.
    private var manager: NETunnelProviderManager?
    /// The install link of the update the server offered last.
    private var updateLink: String?

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
        // iPhones sold in mainland China ask whether an app may use the
        // network the first time it uses Apple's networking; the core's own
        // sockets never trigger the question and fail until it's allowed.
        if let url = URL(string: "https://captive.apple.com/hotspot-detect.html") {
            URLSession.shared.dataTask(with: url) { _, _, _ in }.resume()
        }
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
            connect(nil, result)
        case "diagStatus":
            diag("diag-status", local: { aegis_diag_status(dir) }, result)
        case "diagStart":
            let minutes = args["minutes"] as? Int ?? 15
            diag("diag-start:\(minutes)", local: nil, result) {
                // Not running: record from the connection's start.
                self.connect(["diagMinutes": NSNumber(value: minutes)], result)
            }
        case "diagStop":
            let send = args["send"] as? Bool ?? false
            diag("diag-stop:\(send ? 1 : 0)", local: { aegis_diag_stop(dir, send ? 1 : 0) }, result)
        case "diagSend":
            diag("diag-send", local: { aegis_diag_send(dir) }, result)
        case "diagDiscard":
            diag("diag-discard", local: { aegis_diag_discard(dir) }, result)
        case "diagShare":
            share(result)
        case "checkUpdate":
            // A newer app from the server: installed like the first time,
            // through iOS (ADR-0017, ADR-0019).
            queue.async {
                let text = Self.core { aegis_check_update(dir) }
                let link = Self.object(text)["install"] as? String
                DispatchQueue.main.async {
                    self.updateLink = link
                    result(text)
                }
            }
        case "installUpdate":
            guard let link = updateLink, let url = URL(string: link) else {
                result(Self.failure("No update is offered."))
                return
            }
            // iOS asks the user, closes the app and installs the new version.
            UIApplication.shared.open(url) { opened in
                result(opened ? Self.ok : Self.failure("iOS didn't open the install link."))
            }
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

    /// The extension's session while it runs (connecting or connected).
    private func running(_ done: @escaping (NETunnelProviderSession?) -> Void) {
        withManager { manager in
            guard let session = manager?.connection as? NETunnelProviderSession else { return done(nil) }
            switch session.status {
            case .connected, .connecting, .reasserting: done(session)
            default: done(nil)
            }
        }
    }

    /// A diagnostics call: to the extension while it runs; otherwise to the
    /// core here (`local`), or `otherwise`.
    private func diag(
        _ message: String,
        local: (() -> UnsafeMutablePointer<CChar>?)?,
        _ result: @escaping FlutterResult,
        otherwise: (() -> Void)? = nil
    ) {
        running { session in
            if let session {
                do {
                    try session.sendProviderMessage(Data(message.utf8)) { data in
                        let text = data.flatMap { String(data: $0, encoding: .utf8) }
                        DispatchQueue.main.async { result(text ?? Self.failure("The VPN didn't answer.")) }
                    }
                } catch {
                    result(Self.failure("The VPN didn't answer: \(error.localizedDescription)"))
                }
            } else if let local {
                self.background(result) { Self.core(local) }
            } else {
                otherwise?()
            }
        }
    }

    /// Offer the recorded report to another app (chat, mail, AirDrop): one
    /// the extension saved after it couldn't send it, or a fresh one from
    /// the running extension.
    private func share(_ result: @escaping FlutterResult) {
        let present = { (path: String?) in
            DispatchQueue.main.async {
                guard let path, FileManager.default.fileExists(atPath: path) else {
                    result(Self.failure("There is no report to share. Record one first."))
                    return
                }
                let sheet = UIActivityViewController(activityItems: [URL(fileURLWithPath: path)], applicationActivities: nil)
                let root = UIApplication.shared.connectedScenes
                    .compactMap { ($0 as? UIWindowScene)?.keyWindow?.rootViewController }
                    .first
                guard let root else {
                    result(Self.failure("Could not show the share sheet."))
                    return
                }
                // iPad: anchored to the screen.
                sheet.popoverPresentationController?.sourceView = root.view
                sheet.popoverPresentationController?.sourceRect = CGRect(x: root.view.bounds.midX, y: root.view.bounds.midY, width: 0, height: 0)
                root.present(sheet, animated: true)
                result(Self.ok)
            }
        }
        // The report an earlier extension saved (it couldn't send it).
        let savedEarlier = {
            let status = Self.object(Self.core { aegis_diag_status(Self.dir) })
            return (status["result"] as? [String: Any])?["file"] as? String
        }
        running { session in
            guard let session else {
                present(savedEarlier())
                return
            }
            // A fresh report from the running extension; when it recorded
            // nothing (it started after the recording), the earlier one.
            do {
                try session.sendProviderMessage(Data("diag-save".utf8)) { data in
                    let saved = Self.object(data.flatMap { String(data: $0, encoding: .utf8) } ?? "")
                    present(saved["path"] as? String ?? savedEarlier())
                }
            } catch {
                present(savedEarlier())
            }
        }
    }

    /// Save the VPN configuration (iOS asks the user the first time) and
    /// start the tunnel for the selected server, with `options` for the
    /// extension.
    private func connect(_ options: [String: NSObject]?, _ result: @escaping FlutterResult) {
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
                            try manager.connection.startVPNTunnel(options: options)
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
