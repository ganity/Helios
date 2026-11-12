import Foundation
import Network
import NetworkExtension
import Darwin

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let queue = DispatchQueue(label: "com.helios.packet-tunnel", qos: .userInitiated)
    private var timer: DispatchSourceTimer?
    private var monitor: NWPathMonitor?
    private var startCompletion: ((Error?) -> Void)?
    private var running = false
    private var settingsReady = false
    private var reading = false
    private var generation = UUID()
    private var unavailable = false
    private var ticks = 0
    private var pathSignature: String?
    private var candidates: [[String: Any]] = []
    private var connectionSettings: [String: Any] = [:]
    private var containerPath = ""
    private var candidateIndex = 0
    private var recoveryAttempts = 0
    private var retryAt: Date?

    private func startCore() throws {
        let value: [String: Any] = ["node": candidates[candidateIndex], "settings": connectionSettings]
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        let json = String(decoding: data, as: UTF8.self)
        let result = json.withCString { node in containerPath.withCString { helios_tunnel_start(node, $0) } }
        guard result == 0 else { throw HeliosContainer.error(snapshot()["message"] as? String ?? "无法启动转发核心") }
    }

    private func recover(_ message: String) -> Bool {
        let failover = connectionSettings["auto_failover"] as? Bool ?? false
        let reconnect = connectionSettings["auto_reconnect"] as? Bool ?? false
        guard reconnect || (failover && recoveryAttempts < candidates.count - 1) else { return false }
        if retryAt == nil {
            recoveryAttempts += 1
            if failover { candidateIndex = (candidateIndex + 1) % candidates.count }
            retryAt = Date().addingTimeInterval(min(60, pow(2, Double(min(recoveryAttempts, 6)))))
            reasserting = true
            NSLog("Helios: recovering tunnel (%@)", message)
        }
        return true
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        queue.async {
            guard !self.running else { completionHandler(HeliosContainer.error("VPN 已在运行")); return }
            self.startCompletion = completionHandler
            self.generation = UUID()
            let generation = self.generation
            do {
                guard let configuration = self.protocolConfiguration as? NETunnelProviderProtocol,
                      let node = configuration.providerConfiguration?["node"] as? String,
                      node.utf8.count <= 16384 else { throw HeliosContainer.error("缺少有效的节点配置，请在 Helios 中重新连接") }
                guard let nodeValue = try JSONSerialization.jsonObject(with: Data(node.utf8)) as? [String: Any] else { throw HeliosContainer.error("节点配置无效") }
                self.containerPath = try HeliosContainer.url().path
                let preferences = configuration.providerConfiguration ?? [:]
                if let json = preferences["settings"] as? String {
                    guard json.utf8.count <= 4096 else { throw HeliosContainer.error("连接设置过大") }
                    self.connectionSettings = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] ?? [:]
                }
                self.candidates = [nodeValue]
                if let json = preferences["nodes"] as? String {
                    guard json.utf8.count <= 262144,
                          let nodes = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]], nodes.count <= 64 else { throw HeliosContainer.error("备用节点配置无效") }
                    self.candidates += nodes.filter { ($0["token_file"] as? String) != (nodeValue["token_file"] as? String) }
                }
                self.candidateIndex = 0
                self.recoveryAttempts = 0
                self.retryAt = nil
                self.running = true
                self.settingsReady = false
                self.ticks = 0
                do { try self.startCore() }
                catch { if !self.recover(error.localizedDescription) { throw error } }
                let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
                settings.mtu = 1500
                let ipv4 = NEIPv4Settings(addresses: ["10.88.0.2"], subnetMasks: ["255.255.255.255"])
                ipv4.includedRoutes = [NEIPv4Route.default()]
                settings.ipv4Settings = ipv4
                let ipv6 = NEIPv6Settings(addresses: ["fd88::2"], networkPrefixLengths: [128])
                ipv6.includedRoutes = [NEIPv6Route.default()]
                settings.ipv6Settings = ipv6
                let dns = NEDNSSettings(servers: ["10.88.0.1"])
                dns.matchDomains = [""]
                settings.dnsSettings = dns
                self.setTunnelNetworkSettings(settings) { error in
                    self.queue.async {
                        guard self.running, self.generation == generation else { return }
                        if let error { self.fail(error); return }
                        self.settingsReady = true
                    }
                }
                self.pump()
                self.watchNetwork()
                self.queue.asyncAfter(deadline: .now() + 25) {
                    if self.running, self.generation == generation, self.startCompletion != nil {
                        self.fail(HeliosContainer.error("VPN 启动超时"))
                    }
                }
            } catch { self.fail(error) }
        }
    }

    private func pump() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        self.timer = timer
        timer.schedule(deadline: .now(), repeating: .milliseconds(10), leeway: .milliseconds(2))
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            self.ticks += 1
            if self.ticks % 25 == 1 {
                if let retryAt = self.retryAt {
                    if !self.unavailable, Date() >= retryAt {
                        self.retryAt = nil
                        helios_tunnel_stop()
                        do { try self.startCore() }
                        catch { if !self.recover(error.localizedDescription) { self.fail(error) } }
                    }
                    return
                }
                if self.ticks % 3000 == 1, !self.unavailable, self.startCompletion == nil { helios_tunnel_recheck() }
                let status = self.snapshot()
                let phase = status["phase"] as? Int ?? 5
                if phase == 5 || phase == 4 {
                    let message = status["message"] as? String ?? "转发核心已停止"
                    if !self.recover(message) { self.fail(HeliosContainer.error(message)) }
                    return
                }
                if phase == 2, self.settingsReady {
                    self.reasserting = self.unavailable
                    if !self.unavailable, let completion = self.startCompletion { self.startCompletion = nil; completion(nil) }
                    self.readPackets()
                    if self.ticks % 3000 == 1 { self.recoveryAttempts = 0 }
                } else if phase == 3 { self.reasserting = true }
            }
            var packets: [Data] = []
            var protocols: [NSNumber] = []
            var buffer = [UInt8](repeating: 0, count: 1500)
            for _ in 0..<64 {
                let count = buffer.withUnsafeMutableBufferPointer { helios_tunnel_pop($0.baseAddress, $0.count) }
                if count <= 0 { break }
                let bytes = Data(buffer.prefix(Int(count)))
                guard let first = bytes.first else { continue }
                packets.append(bytes)
                protocols.append(NSNumber(value: first >> 4 == 6 ? AF_INET6 : AF_INET))
            }
            if !packets.isEmpty, !self.packetFlow.writePackets(packets, withProtocols: protocols) {
                self.fail(HeliosContainer.error("系统拒绝写回 VPN 数据包"))
            }
        }
        timer.resume()
    }

    private func readPackets() {
        guard running, settingsReady, !reading else { return }
        reading = true
        let generation = generation
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.queue.async {
                guard self.running, self.generation == generation else { return }
                self.reading = false
                for packet in packets {
                    // The bounded core drops bursts on overflow; TCP retransmits without growing memory.
                    _ = packet.withUnsafeBytes { buffer in
                        helios_tunnel_push(buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count)
                    }
                }
                self.readPackets()
            }
        }
    }

    private func watchNetwork() {
        unavailable = false
        pathSignature = nil
        let monitor = NWPathMonitor()
        self.monitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, self.running else { return }
            if path.status != .satisfied {
                self.unavailable = true
                self.reasserting = true
                return
            }
            let signature = path.availableInterfaces.filter { path.usesInterfaceType($0.type) }
                .map { "\($0.type):\($0.name)" }.sorted().joined(separator: ",")
                + ":v4=\(path.supportsIPv4):v6=\(path.supportsIPv6)"
            let changed = self.pathSignature.map { $0 != signature } ?? false
            if self.unavailable || changed { helios_tunnel_network_changed() }
            self.unavailable = false
            self.pathSignature = signature
        }
        monitor.start(queue: queue)
    }

    private func snapshot() -> [String: Any] {
        var buffer = [UInt8](repeating: 0, count: 65536)
        let count = buffer.withUnsafeMutableBufferPointer { helios_tunnel_snapshot($0.baseAddress, $0.count) }
        guard count <= buffer.count else { return ["phase": 5, "message": "状态数据超过限制"] }
        var value = (try? JSONSerialization.jsonObject(with: Data(buffer.prefix(count))) as? [String: Any]) ?? [:]
        if candidates.indices.contains(candidateIndex) {
            value["nodeName"] = candidates[candidateIndex]["name"]
            value["server"] = candidates[candidateIndex]["server"]
        }
        if retryAt != nil { value["phase"] = 3; value["message"] = "正在重连或切换备用节点" }
        return value
    }

    override func wake() {
        queue.async {
            guard self.running else { return }
            helios_tunnel_recheck()
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        queue.async {
            if let message = try? JSONSerialization.jsonObject(with: messageData) as? [String: String],
               message["command"] == "clearLogs" { helios_tunnel_clear_logs() }
            completionHandler?(try? JSONSerialization.data(withJSONObject: self.snapshot()))
        }
    }

    private func cleanup() {
        running = false
        retryAt = nil
        candidates = []
        connectionSettings = [:]
        generation = UUID()
        reading = false
        settingsReady = false
        timer?.cancel(); timer = nil
        monitor?.cancel(); monitor = nil
        helios_tunnel_stop()
        reasserting = false
    }

    private func fail(_ error: Error) {
        let completion = startCompletion
        startCompletion = nil
        cleanup()
        if let completion { completion(error) } else { cancelTunnelWithError(error) }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            let pending = self.startCompletion
            self.startCompletion = nil
            self.cleanup()
            pending?(HeliosContainer.error("连接已取消"))
            completionHandler()
        }
    }
}
