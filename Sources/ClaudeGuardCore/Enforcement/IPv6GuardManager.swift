import Foundation
import Darwin

public struct NetworkServiceIPv6Item: Codable, Sendable, Equatable, Identifiable {
    public var id: String { serviceName }
    public var serviceName: String
    /// `"Automatic"` / `"Link-local"` / `"Manual"` / `"Off"` / `"Unknown"`
    public var mode: String
    public var assignedIPv6: String?

    public init(serviceName: String, mode: String, assignedIPv6: String? = nil) {
        self.serviceName = serviceName
        self.mode = mode
        self.assignedIPv6 = assignedIPv6
    }

    public var isPublicIPv6Blocked: Bool {
        let lower = mode.lowercased()
        return lower.contains("link-local") || lower == "off"
    }
}

public struct SystemIPv6Status: Codable, Sendable, Equatable {
    public var services: [NetworkServiceIPv6Item]

    public init(services: [NetworkServiceIPv6Item] = []) {
        self.services = services
    }

    public var isPublicIPv6DisabledOnAll: Bool {
        !services.isEmpty && services.allSatisfy(\.isPublicIPv6Blocked)
    }

    public var summaryText: String {
        if services.isEmpty {
            return "未检测到可管理的物理网络服务"
        }
        if isPublicIPv6DisabledOnAll {
            return "已关闭公网 IPv6（仅本地链接 · 保留 AirDrop，共 \(services.count) 个接口）"
        }
        let openNames = services.filter { !$0.isPublicIPv6Blocked }.map { "\($0.serviceName): \($0.mode)" }
        return "公网 IPv6 开启中（\(openNames.joined(separator: "、"))）"
    }
}

/// 管理系统级物理网卡的公网 IPv6 开关（采用 `-setv6linklocal` 关闭运营商公网 IPv6 防直连泄漏，同时完整保留 `fe80::` AirDrop / Handoff 能力）。
public enum IPv6GuardManager {
    private struct BackupRecord: Codable {
        var automaticServices: [String]
        var savedAt: Date
    }

    private static let excludedServiceKeywords = [
        "tailscale", "wireguard", "v2ray", "sing-box", "clash", "surge", "shadowrocket", "openvpn", "utun"
    ]

    /// 列出本机所有已启用的物理/桥接网络服务（如 `Wi-Fi`、`Thunderbolt Bridge`、`iPhone USB`）。
    public static func listManageableServices() -> [String] {
        guard let output = runCapture("/usr/sbin/networksetup", ["-listallnetworkservices"]) else {
            return []
        }
        var services: [String] = []
        for (idx, rawLine) in output.split(whereSeparator: \.isNewline).enumerated() {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }
            if idx == 0 && line.contains("asterisk") { continue }
            if line.hasPrefix("*") || line.hasPrefix("-") { continue }
            let lower = line.lowercased()
            if excludedServiceKeywords.contains(where: { lower.contains($0) }) {
                continue
            }
            services.append(line)
        }
        return services
    }

    /// 解析 `networksetup -getinfo` 输出文本（专门兼容 macOS 的特性：当 IPv6 处于 `Link-local` 仅本地链接模式时，
    /// `networksetup -getinfo` 不会输出 `IPv6:` 行，但会输出 `IPv6 IP address: none`）。
    public static func parseNetworkSetupInfo(_ info: String) -> (mode: String, assignedIPv6: String?) {
        var explicitMode: String?
        var sawIPv6AddressLine = false
        var ipAddr: String?

        for raw in info.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let lower = line.lowercased()
            if lower.hasPrefix("ipv6:") {
                let val = String(line.dropFirst("ipv6:".count)).trimmingCharacters(in: .whitespaces)
                if !val.isEmpty {
                    explicitMode = val
                }
            } else if lower.hasPrefix("ipv6 configuration:") {
                let val = String(line.dropFirst("ipv6 configuration:".count)).trimmingCharacters(in: .whitespaces)
                if !val.isEmpty {
                    explicitMode = val
                }
            } else if lower.hasPrefix("ipv6 ip address:") {
                sawIPv6AddressLine = true
                let val = String(line.dropFirst("ipv6 ip address:".count)).trimmingCharacters(in: .whitespaces)
                if !val.isEmpty && val.lowercased() != "none" {
                    ipAddr = val
                }
            }
        }

        if let explicitMode {
            return (explicitMode, ipAddr)
        }
        // macOS `networksetup -getinfo` 在 ConfigMethod=LinkLocal 时省略 `IPv6:` 行，但仍输出 `IPv6 IP address: none`
        if sawIPv6AddressLine && ipAddr == nil {
            return ("Link-local", nil)
        }
        return ("Unknown", ipAddr)
    }

    /// 读取各网络服务当前的 IPv6 模式（`Automatic` / `Link-local` / `Off` / `Manual`）。
    public static func inspectStatus() -> SystemIPv6Status {
        let names = listManageableServices()
        var items: [NetworkServiceIPv6Item] = []

        for name in names {
            guard let info = runCapture("/usr/sbin/networksetup", ["-getinfo", name]) else {
                continue
            }
            let parsed = parseNetworkSetupInfo(info)
            items.append(NetworkServiceIPv6Item(serviceName: name, mode: parsed.mode, assignedIPv6: parsed.assignedIPv6))
        }
        return SystemIPv6Status(services: items)
    }

    /// 构造供 `claudeguard-helper` 校验并执行的 `ipv6.policy` 文本。
    public static func buildPolicyPayload(disablePublicIPv6: Bool, services: [String]) -> String {
        let valid = services.filter { !$0.isEmpty && !$0.hasPrefix("-") && !$0.hasPrefix("*") }
        guard !valid.isEmpty else { return "" }
        let header = disablePublicIPv6 ? "linklocal" : "automatic"
        return ([header] + valid).joined(separator: "\n") + "\n"
    }

    /// 一键切换「关闭系统公网 IPv6（Link-Local Only）」或「恢复自动获取（Automatic）」。
    /// 若已部署特权助手则直接免密秒级执行；未部署时自动回退至原生管理员密码授权框。
    @discardableResult
    public static func setPublicIPv6Disabled(
        _ disable: Bool,
        paths: GuardPaths = .live
    ) throws -> SystemIPv6Status {
        try paths.ensureDirectoriesExist()
        let current = inspectStatus()
        guard !current.services.isEmpty else { return current }

        let targetServices: [String]
        if disable {
            // 仅在尚未保存过快照时记录原先处于 Automatic 的接口，避免重复点击覆盖原始状态
            if !FileManager.default.fileExists(atPath: paths.ipv6BackupFile.path) {
                let autoOnes = current.services
                    .filter { $0.mode.lowercased() == "automatic" }
                    .map(\.serviceName)
                if !autoOnes.isEmpty,
                   let data = try? JSONEncoder().encode(BackupRecord(automaticServices: autoOnes, savedAt: Date())) {
                    try? data.write(to: paths.ipv6BackupFile, options: .atomic)
                }
            }
            // 不篡改用户自己配了静态 Manual IPv6 的特殊网卡，仅将非 Link-local/Off/Manual 的接口切为 Link-local
            let candidates = current.services
                .filter { $0.mode.lowercased() != "manual" }
                .map(\.serviceName)
            targetServices = candidates
        } else {
            if let data = try? Data(contentsOf: paths.ipv6BackupFile),
               let backup = try? JSONDecoder().decode(BackupRecord.self, from: data),
               !backup.automaticServices.isEmpty {
                let existingSet = Set(current.services.map(\.serviceName))
                targetServices = backup.automaticServices.filter { existingSet.contains($0) }
            } else {
                targetServices = current.services
                    .filter { $0.mode.lowercased().contains("link-local") }
                    .map(\.serviceName)
            }
        }

        guard !targetServices.isEmpty else {
            if !disable {
                try? FileManager.default.removeItem(at: paths.ipv6BackupFile)
                try? FileManager.default.removeItem(at: paths.pendingIPv6PolicyFile)
            }
            return inspectStatus()
        }

        if PrivilegedInstaller.isHelperInstalled(paths: paths) {
            let payload = buildPolicyPayload(disablePublicIPv6: disable, services: targetServices)
            try Data(payload.utf8).write(to: paths.pendingIPv6PolicyFile, options: .atomic)
            try touchTriggerInPlace(paths.pendingRequestFile)

            for _ in 0..<25 {
                usleep(80_000)
                let refreshed = inspectStatus()
                if refreshed.isPublicIPv6DisabledOnAll == disable {
                    break
                }
            }
            // 执行完毕后清理单次策略文件，兼容新旧版 helper 且避免常规 hosts 同步重复触发 networksetup
            try? FileManager.default.removeItem(at: paths.pendingIPv6PolicyFile)
            if !disable {
                try? FileManager.default.removeItem(at: paths.ipv6BackupFile)
            }
        } else {
            let flag = disable ? "-setv6linklocal" : "-setv6automatic"
            let cmds = targetServices.map { "/usr/sbin/networksetup \(flag) \(shellQuote($0))" }
            try runAdminShell(cmds.joined(separator: " && "))
            if !disable {
                try? FileManager.default.removeItem(at: paths.ipv6BackupFile)
                try? FileManager.default.removeItem(at: paths.pendingIPv6PolicyFile)
            }
        }

        return inspectStatus()
    }

    private static func runCapture(_ executable: String, _ args: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
        } catch {
            return nil
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func touchTriggerInPlace(_ fileURL: URL) throws {
        let stamp = "\(Date().timeIntervalSince1970)\n"
        let fd = open(fileURL.path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { close(fd) }
        stamp.withCString { ptr in
            _ = write(fd, ptr, strlen(ptr))
        }
        fsync(fd)
    }

    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func runAdminShell(_ command: String) throws {
        let escaped = command
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", "do shell script \"\(escaped)\" with administrator privileges"]
        let errPipe = Pipe()
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = errPipe
        try proc.run()
        proc.waitUntilExit()
        if proc.terminationStatus != 0 {
            let errText = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            if errText.contains("-128") {
                throw NSError(domain: "ClaudeGuard.IPv6", code: -128, userInfo: [NSLocalizedDescriptionKey: "已取消管理员密码授权。"])
            }
            throw NSError(domain: "ClaudeGuard.IPv6", code: Int(proc.terminationStatus), userInfo: [NSLocalizedDescriptionKey: "切换系统 IPv6 失败：\(errText.trimmingCharacters(in: .whitespacesAndNewlines))"])
        }
    }
}
