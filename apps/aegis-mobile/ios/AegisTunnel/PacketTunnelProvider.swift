import AegisCore
import NetworkExtension

/// The VPN: a packet tunnel extension around the Rust core. It sets up the
/// interface from the core's settings and lets the core run the connection
/// on it (the core finds the interface's descriptor itself). Its own
/// traffic to the gateway doesn't go through the tunnel. The app talks to
/// it for status (`handleAppMessage`); servers are shared through the App
/// Group container.
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
        let cfg = Self.object(Self.core { aegis_vpn_config() })
        guard let settings = Self.settings(cfg) else {
            completionHandler(Self.failure("The VPN settings are incomplete."))
            return
        }
        setTunnelNetworkSettings(settings) { error in
            if let error {
                completionHandler(error)
                return
            }
            self.queue.async {
                let started = Self.object(Self.core { aegis_start_tunnel(Self.dir) })
                if started["ok"] as? Bool == true {
                    self.watchCore()
                    completionHandler(nil)
                } else {
                    completionHandler(Self.failure(started["error"] as? String ?? "Could not connect."))
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
            completionHandler()
        }
    }

    /// The app asks for "status": the core's state and counters.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard String(data: messageData, encoding: .utf8) == "status" else {
            completionHandler?(nil)
            return
        }
        completionHandler?(Data(Self.core { aegis_status() }.utf8))
    }
}
