import Foundation

/// 单条带备注的 IP 或 CIDR 白名单记录。
public struct AllowedIPEntry: Codable, Sendable, Equatable, Identifiable {
    public var id: UUID
    public var cidrOrIP: String
    public var label: String
    public var isEnabled: Bool
    public var createdAt: Date

    public init(
        id: UUID = UUID(),
        cidrOrIP: String,
        label: String,
        isEnabled: Bool = true,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.cidrOrIP = cidrOrIP.trimmingCharacters(in: .whitespacesAndNewlines)
        self.label = label.trimmingCharacters(in: .whitespacesAndNewlines)
        self.isEnabled = isEnabled
        self.createdAt = createdAt
    }
}

/// 出口探测通道组合模式。
public enum ExitCheckMode: String, Codable, Sendable, CaseIterable, Identifiable {
    /// 同时检查 HTTP + UDP STUN + 已启用目标的真实链路（推荐 V2rayN TUN 模式使用）
    case all = "all"
    /// 检查 HTTP + 已启用目标的真实链路，跳过 UDP STUN（适合仅开启系统 HTTP 代理模式）
    case httpAndTrace = "http_trace"
    /// 检查 UDP STUN + 已启用目标的真实链路
    case stunAndTrace = "stun_trace"

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .all:
            return "严格全检（HTTP + STUN + 目标链路）"
        case .httpAndTrace:
            return "代理链路（HTTP + 目标链路）"
        case .stunAndTrace:
            return "UDP 优先（STUN + 目标链路）"
        }
    }

    public var shortTitle: String {
        switch self {
        case .all: return "全通道严格"
        case .httpAndTrace: return "HTTP + 目标链路"
        case .stunAndTrace: return "STUN + 目标链路"
        }
    }

    public var subtitle: String {
        switch self {
        case .all:
            return "推荐开启 V2rayN TUN 模式时使用：要求通用 HTTP、UDP STUN 与各应用真实域名出口全部合规。"
        case .httpAndTrace:
            return "适合仅开启“系统代理”模式（UDP 直连）时使用：校验 HTTP 与各应用真实域名出口，避免 STUN 直连误拦。"
        case .stunAndTrace:
            return "利用毫秒级 UDP STUN 搭配目标域名真实链路进行快速校验。"
        }
    }

    public var includesHTTP: Bool {
        self == .all || self == .httpAndTrace
    }

    public var includesSTUN: Bool {
        self == .all || self == .stunAndTrace
    }
}

/// IP 白名单与国家/地区码的组合放行逻辑。
public enum AdmissionRuleMode: String, Codable, Sendable, CaseIterable, Identifiable {
    /// 必须命中已启用的 IP / CIDR 白名单（最严格，默认）
    case ipOnly = "ip_only"
    /// 命中 IP 白名单 或 出口属于允许的国家/地区码 任一即放行
    case ipOrRegion = "ip_or_region"
    /// 既要命中 IP 白名单，且目标真实链路地区也必须属于允许列表
    case ipAndRegion = "ip_and_region"

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .ipOnly:
            return "仅允许固定 IP / 网段白名单（推荐）"
        case .ipOrRegion:
            return "命中 IP 白名单 或 允许的国家/地区即放行"
        case .ipAndRegion:
            return "双重校验（必须同时满足 IP 白名单与允许地区）"
        }
    }
}

/// 用户持久化配置模型。
public struct GuardConfig: Codable, Sendable, Equatable {
    public var configRevision: UInt64
    public var protectionEnabled: Bool
    public var exitCheckMode: ExitCheckMode
    public var admissionRuleMode: AdmissionRuleMode
    public var allowedIPs: [AllowedIPEntry]
    public var allowedRegions: [String]
    public var detectIPChange: Bool

    public var pollIntervalSeconds: Double
    public var showInterceptAlert: Bool
    public var launchAtLogin: Bool

    /// Claude 专属附加特性
    public var protectClaudeCLI: Bool
    public var realClaudeCLIPath: String?
    public var blockClaudeAutoUpdates: Bool

    /// 可选显式指定本地 HTTP 代理（默认自动跟随 macOS 系统代理与 TUN 路由）
    public var useCustomHTTPProxy: Bool
    public var customHTTPProxyURL: String

    /// 首次引导完成标记
    public var onboardingCompleted: Bool

    /// 守护目标列表（内置 + 自定义）
    public var targets: [GuardedTarget]

    public init(
        configRevision: UInt64 = 1,
        protectionEnabled: Bool = true,
        exitCheckMode: ExitCheckMode = .all,
        admissionRuleMode: AdmissionRuleMode = .ipOnly,
        allowedIPs: [AllowedIPEntry] = [],
        allowedRegions: [String] = [],
        detectIPChange: Bool = false,
        pollIntervalSeconds: Double = 3.0,
        showInterceptAlert: Bool = true,
        launchAtLogin: Bool = true,
        protectClaudeCLI: Bool = true,
        realClaudeCLIPath: String? = nil,
        blockClaudeAutoUpdates: Bool = true,
        useCustomHTTPProxy: Bool = false,
        customHTTPProxyURL: String = "",
        onboardingCompleted: Bool = false,
        targets: [GuardedTarget] = GuardedTarget.defaultTargets
    ) {
        self.configRevision = configRevision
        self.protectionEnabled = protectionEnabled
        self.exitCheckMode = exitCheckMode
        self.admissionRuleMode = admissionRuleMode
        self.allowedIPs = allowedIPs
        self.allowedRegions = allowedRegions
        self.detectIPChange = detectIPChange
        self.pollIntervalSeconds = pollIntervalSeconds
        self.showInterceptAlert = showInterceptAlert
        self.launchAtLogin = launchAtLogin
        self.protectClaudeCLI = protectClaudeCLI
        self.realClaudeCLIPath = realClaudeCLIPath
        self.blockClaudeAutoUpdates = blockClaudeAutoUpdates
        self.useCustomHTTPProxy = useCustomHTTPProxy
        self.customHTTPProxyURL = customHTTPProxyURL
        self.onboardingCompleted = onboardingCompleted
        self.targets = targets
    }

    public var enabledTargets: [GuardedTarget] {
        targets.filter(\.isEnabled)
    }

    public var enabledAllowedIPs: [AllowedIPEntry] {
        allowedIPs.filter(\.isEnabled)
    }

    public var normalizedAllowedRegions: Set<String> {
        Set(
            allowedRegions
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() }
                .filter { $0.count == 2 }
        )
    }

    public var clampedPollInterval: Double {
        min(max(pollIntervalSeconds, 1.0), 60.0)
    }
}

/// 线程安全的配置读写管理器（带原子写入与内置预设合并升级）。
public final class ConfigStore: Sendable {
    public let paths: GuardPaths
    private let lock = NSLock()

    public init(paths: GuardPaths = .live) {
        self.paths = paths
    }

    public func load() -> GuardConfig {
        lock.lock()
        defer { lock.unlock() }
        guard let data = try? Data(contentsOf: paths.configFile) else {
            return GuardConfig()
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard var decoded = try? decoder.decode(GuardConfig.self, from: data) else {
            // 配置文件损坏时 Fail-closed：开启保护且不放行任何规则
            return GuardConfig(protectionEnabled: true, allowedIPs: [], allowedRegions: [])
        }
        // 确保新增的内置预设不会因为旧配置文件缺失而丢失
        let existingIDs = Set(decoded.targets.map(\.id))
        for preset in GuardedTarget.defaultTargets where !existingIDs.contains(preset.id) {
            decoded.targets.append(preset)
        }
        return decoded
    }

    @discardableResult
    public func save(_ config: GuardConfig) throws -> GuardConfig {
        lock.lock()
        defer { lock.unlock() }
        try paths.ensureDirectoriesExist()
        var updated = config
        updated.configRevision &+= 1
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(updated)
        try data.write(to: paths.configFile, options: .atomic)
        return updated
    }
}
