import Foundation
import NetworkExtension

/// This controller and every preference operation run on the UIKit main queue.
final class VPNController {
    static let shared = VPNController()
    private var manager: NETunnelProviderManager?
    private var timer: Timer?
    private var observer: NSObjectProtocol?
    private var pending: UUID?
    private var queuedConnect: [String: Any]?
    private var stopRequested = false
    private var polling = false
    private var loading = false
    private var failure: String?
    private var previousStatus: NEVPNStatus = .invalid
    private var pollID: UUID?
    private var providerID: String { (Bundle.main.bundleIdentifier ?? "com.helios.mobile") + ".PacketTunnel" }

    func start() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange,
            object: nil, queue: .main) { [weak self] _ in self?.refresh() }
        resume()
        load()
    }

    func resume() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.refresh() }
        refresh()
    }
    func pause() { timer?.invalidate(); timer = nil }

    private func load() {
        guard !loading else { return }
        loading = true
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self else { return }
                self.loading = false
                if let error { self.fail(error); return }
                self.manager = managers?.first {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.providerID
                }
                self.refresh()
            }
        }
    }

    func command(_ json: String) {
        do {
            guard let value = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
                  let command = value["command"] as? String else { throw HeliosContainer.error("无效的 VPN 请求") }
            switch command {
            case "connect":
                try connect(value)
            case "disconnect":
                stop(restart: nil)
            case "clearLogs": send(["command": "clearLogs"])
            default: throw HeliosContainer.error("不支持的 VPN 请求")
            }
        } catch { fail(error) }
    }

    private func stop(restart: [String: Any]?) {
        pollID = nil
        polling = false
        queuedConnect = restart
        failure = nil
        stopRequested = true
        guard pending == nil, !loading else { return }
        stopRequested = false
        let token = UUID()
        pending = token
        guard let manager else { pending = nil; refresh(); return }
        // Persist this before stopping, otherwise on-demand may immediately restart the old node.
        manager.isOnDemandEnabled = false
        manager.saveToPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self, self.pending == token else { return }
                self.pending = nil
                if let error {
                    self.queuedConnect = nil
                    manager.connection.stopVPNTunnel()
                    self.fail(error)
                    return
                }
                manager.connection.stopVPNTunnel()
                self.refresh()
            }
        }
    }

    private func connect(_ request: [String: Any]) throws {
        guard let node = request["node"] as? [String: Any] else { throw HeliosContainer.error("缺少节点配置") }
        guard !loading, pending == nil else { throw HeliosContainer.error("正在处理 VPN 配置，请稍后再试") }
        pollID = nil
        polling = false
        if let status = manager?.connection.status, status != .disconnected && status != .invalid {
            stop(restart: request)
            publish(["status": "正在切换节点，重建 VPN 连接"])
            return
        }
        // Only metadata and paths go into system preferences. The token stays in the shared container.
        let json = try JSONSerialization.data(withJSONObject: node, options: [.sortedKeys])
        guard json.count <= 16384, let nodeJSON = String(data: json, encoding: .utf8),
              let address = node["server"] as? String else { throw HeliosContainer.error("节点配置无效") }
        let token = UUID()
        failure = nil
        publish(["status": "正在保存 VPN 配置，请完成系统授权"])
        let manager = self.manager ?? NETunnelProviderManager()
        self.manager = manager
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = providerID
        configuration.serverAddress = address
        let settings = request["settings"] as? [String: Any] ?? [:]
        let nodes = request["nodes"] as? [[String: Any]] ?? []
        guard nodes.count <= 64 else { pending = nil; throw HeliosContainer.error("备用节点最多 64 个") }
        let settingsData = try JSONSerialization.data(withJSONObject: settings, options: [.sortedKeys])
        let nodesData = try JSONSerialization.data(withJSONObject: nodes, options: [.sortedKeys])
        guard nodesData.count <= 262144 else { pending = nil; throw HeliosContainer.error("备用节点配置过大") }
        configuration.providerConfiguration = ["node": nodeJSON, "version": 2,
            "settings": String(decoding: settingsData, as: UTF8.self), "nodes": String(decoding: nodesData, as: UTF8.self)]
        configuration.disconnectOnSleep = false
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "Helios · 曜光"
        manager.isEnabled = true
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        manager.onDemandRules = [rule]
        manager.isOnDemandEnabled = settings["auto_reconnect"] as? Bool ?? false
        pending = token
        manager.saveToPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self, self.pending == token else { return }
                if let error {
                    self.pending = nil
                    if self.stopRequested { self.stop(restart: self.queuedConnect) } else { self.fail(error) }
                    return
                }
                manager.loadFromPreferences { [weak self] error in
                    DispatchQueue.main.async {
                        guard let self, self.pending == token else { return }
                        self.pending = nil
                        if self.stopRequested { self.stop(restart: self.queuedConnect); return }
                        if let error { self.fail(error); return }
                        do { try manager.connection.startVPNTunnel(); self.refresh() }
                        catch { self.fail(error) }
                    }
                }
            }
        }
    }

    private func refresh() {
        guard pending == nil, !loading else { return }
        if stopRequested { stop(restart: queuedConnect); return }
        let status = manager?.connection.status ?? .disconnected
        if (status == .disconnected || status == .invalid), let request = queuedConnect {
            queuedConnect = nil
            do { try connect(request) } catch { fail(error) }
            return
        }
        let previous = previousStatus
        previousStatus = status
        if status == .connected { failure = nil }
        if status == .disconnected, previous != .disconnected, previous != .invalid,
           let connection = manager?.connection {
            connection.fetchLastDisconnectError { [weak self] error in
                DispatchQueue.main.async {
                    guard let self, self.manager?.connection.status == .disconnected else { return }
                    if let error { self.failure = error.localizedDescription; self.refresh() }
                }
            }
        }
        let label: String
        switch status {
        case .connecting: label = "正在连接并验证节点"
        case .connected: label = "已连接 · 全部代理"
        case .reasserting: label = "网络变化，正在恢复连接"
        case .disconnecting: label = "正在断开"
        case .invalid: label = "未连接"
        default: label = "未连接"
        }
        publish(["status": failure ?? label])
        if status == .connected || status == .reasserting { send(["command": "status"]) }
        if status == .disconnected || status == .invalid {
            // Do not display stale active-flow counters after a system-initiated stop.
            publish(["snapshot": ["uploaded": 0, "downloaded": 0, "active": 0, "logs": failure ?? ""]])
        }
    }

    private func send(_ message: [String: String]) {
        guard !polling, let session = manager?.connection as? NETunnelProviderSession,
              let data = try? JSONSerialization.data(withJSONObject: message) else { return }
        polling = true
        let request = UUID()
        pollID = request
        do {
            try session.sendProviderMessage(data) { [weak self] reply in
                DispatchQueue.main.async {
                    guard let self else { return }
                    guard self.pollID == request else { return }
                    self.polling = false
                    guard let reply, reply.count <= 65536,
                          let snapshot = try? JSONSerialization.jsonObject(with: reply) as? [String: Any] else { return }
                    let status = self.manager?.connection.status
                    if status == .connected || status == .reasserting {
                        let phase = snapshot["phase"] as? Int
                        let name = snapshot["nodeName"] as? String ?? ""
                        if phase == 3 { self.publish(["status": "正在恢复连接 · " + name]) }
                        else if phase == 2 { self.publish(["status": "已连接 · 全部代理 · " + name]) }
                        self.publish(["snapshot": snapshot])
                    }
                }
            }
            // A terminated extension may never reply. Do not block later status polls indefinitely.
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
                if self?.pollID == request { self?.polling = false; self?.pollID = nil }
            }
        } catch { polling = false }
    }

    private func fail(_ error: Error) {
        failure = error.localizedDescription
        publish(["status": "连接失败：" + error.localizedDescription])
    }

    func publish(_ value: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: value),
              let json = String(data: data, encoding: .utf8) else { return }
        json.withCString { helios_ios_update($0) }
    }
}
