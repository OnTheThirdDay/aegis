import AegisCore
import NetworkExtension

/// The VPN: a packet tunnel extension around the Rust core. It sets up the
/// interface from the core's settings and lets the core run the connection
/// on it (the core finds the interface's descriptor itself). Its own
/// traffic to the gateway doesn't go through the tunnel. The app talks to
/// it for status and diagnostics (`handleAppMessage`); servers are shared
/// through the App Group container.
///
/// Diagnostics record in this process, so they end with it: a connection
/// that fails ends the tunnel at once. The app can therefore start a
/// recording with the connection (the `diagMinutes` start option), and
/// before this process ends the core saves the recording to the shared
/// container and sends it (`aegis_diag_finish`), so the app can share it
/// when the gateway was out of reach.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    static let appGroup = "group.borne.aegis.app"
    private let queue = DispatchQueue(label: "aegis.tunnel")
    private var watch: DispatchSourceTimer?

    /// Each joined server's identity and client state (shared with the app).
    static var dir: String {
        let base = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("aegis").path
    }

    /// Call the core; returns its JSON text.
    static func core(_ f: () -> UnsafeMutablePointer<CChar>?) -> String {
        guard let p = f() else { return #"{"ok":false,"error":"no answer"}"# }
        defer { aegis_free(p) }
        return String(cString: p)
    }

    static func object(_ text: String) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] ?? [:]
    }

    /// The phone's model and system version, for diagnostics.
    static var about: String {
        var info = utsname()
        uname(&info)
        let model = withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        return "\(model), iOS \(ProcessInfo.processInfo.operatingSystemVersionString)"
    }

    /// Before this process ends: note why, then save and send a recording.
    private static func finishDiagnostics(_ why: String?) {
        if let why { _ = core { aegis_diag_note(why) } }
        _ = core { aegis_diag_finish(dir) }
    }

    static func failure(_ message: String) -> NSError {
        NSError(domain: "AegisBorne", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    /// A prefix length as a dotted IPv4 mask.
    static func mask(_ prefix: Int) -> String {
        let bits: UInt32 = prefix <= 0 ? 0 : UInt32.max << UInt32(32 - min(prefix, 32))
        return [24, 16, 8, 0].map { String((bits >> UInt32($0)) & 0xff) }.joined(separator: ".")
    }

    static func routes(_ value: Any?) -> [(String, Int)] {
        (value as? [[String: Any]] ?? []).compactMap { r in
            guard let address = r["address"] as? String, let prefix = r["prefix"] as? Int else { return nil }
            return (address, prefix)
        }
    }

    /// The interface from the core's settings: everything but local
    /// networks goes through the tunnel, and names resolve at the gateway.
    static func settings(_ cfg: [String: Any]) -> NEPacketTunnelNetworkSettings? {
        guard let address = cfg["address"] as? String, let prefix = cfg["prefix"] as? Int,
              let address6 = cfg["address6"] as? String, let prefix6 = cfg["prefix6"] as? Int,
              let dns = cfg["dns"] as? String, let mtu = cfg["mtu"] as? Int
        else { return nil }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let v4 = NEIPv4Settings(addresses: [address], subnetMasks: [mask(prefix)])
        v4.includedRoutes = routes(cfg["routes"]).map {
            NEIPv4Route(destinationAddress: $0.0, subnetMask: mask($0.1))
        }
        settings.ipv4Settings = v4
        let v6 = NEIPv6Settings(addresses: [address6], networkPrefixLengths: [NSNumber(value: prefix6)])
        v6.includedRoutes = routes(cfg["routes6"]).map {
            NEIPv6Route(destinationAddress: $0.0, networkPrefixLength: NSNumber(value: $0.1))
        }
        settings.ipv6Settings = v6
        let resolver = NEDNSSettings(servers: [dns])
        resolver.matchDomains = [""]
        settings.dnsSettings = resolver
        settings.mtu = NSNumber(value: mtu)
        return settings
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        if let minutes = (options?["diagMinutes"] as? NSNumber)?.uint32Value {
            _ = Self.core { aegis_diag_start(Self.dir, minutes, Self.about) }
        }
        let fail = { (message: String) in
            self.queue.async {
                Self.finishDiagnostics(message)
                completionHandler(Self.failure(message))
            }
        }
        let cfg = Self.object(Self.core { aegis_vpn_config() })
        guard let settings = Self.settings(cfg) else {
            fail("The VPN settings are incomplete.")
            return
        }
        setTunnelNetworkSettings(settings) { error in
            if let error {
                fail("iOS refused the VPN settings: \(error.localizedDescription)")
                return
            }
            self.queue.async {
                let started = Self.object(Self.core { aegis_start_tunnel(Self.dir) })
                if started["ok"] as? Bool == true {
                    self.watchCore()
                    completionHandler(nil)
                } else {
                    fail(started["error"] as? String ?? "Could not connect.")
                }
            }
        }
    }

    /// End the tunnel when the core disconnected by itself (an expired
    /// certificate, a removed device); the app shows the reason.
    private func watchCore() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 2, repeating: 2)
        timer.setEventHandler { [weak self] in
            let status = Self.object(Self.core { aegis_status() })
            guard status["state"] as? String == "disconnected" else { return }
            self?.watch?.cancel()
            self?.watch = nil
            Self.finishDiagnostics(nil)
            self?.cancelTunnelWithError(Self.failure(status["error"] as? String ?? "Disconnected."))
        }
        watch = timer
        timer.resume()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        watch?.cancel()
        watch = nil
        queue.async {
            _ = Self.core { aegis_stop() }
            Self.finishDiagnostics(reason == .userInitiated ? nil : "iOS stopped the VPN (reason \(reason.rawValue))")
            completionHandler()
        }
    }

    /// The app asks for "status" (the core's state and counters) and runs
    /// diagnostics here: "diag-status", "diag-start:<minutes>",
    /// "diag-stop:<1 to send>", "diag-send", "diag-save", "diag-discard".
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let parts = (String(data: messageData, encoding: .utf8) ?? "")
            .split(separator: ":", maxSplits: 1).map(String.init)
        let name = parts.first ?? ""
        let value = parts.count > 1 ? parts[1] : ""
        let dir = Self.dir
        let call: (() -> String)?
        switch name {
        case "status": call = { Self.core { aegis_status() } }
        case "diag-status": call = { Self.core { aegis_diag_status(dir) } }
        case "diag-start":
            let minutes = UInt32(value) ?? 15
            call = { Self.core { aegis_diag_start(dir, minutes, Self.about) } }
        case "diag-stop":
            let send: Int32 = value == "1" ? 1 : 0
            call = { Self.core { aegis_diag_stop(dir, send) } }
        case "diag-send": call = { Self.core { aegis_diag_send(dir) } }
        case "diag-save": call = { Self.core { aegis_diag_save(dir) } }
        case "diag-discard": call = { Self.core { aegis_diag_discard(dir) } }
        default: call = nil
        }
        guard let call else {
            completionHandler?(nil)
            return
        }
        // Sending blocks on the network: off the caller's thread.
        DispatchQueue.global(qos: .userInitiated).async {
            completionHandler?(Data(call().utf8))
        }
    }
}
