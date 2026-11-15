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

    /// 进程级时区对齐配置（不影响 macOS 系统时区）
    /// 总开关：用户可勾选关闭，默认开启
    public var timezoneAlignmentEnabled: Bool
    public var timezoneAlignmentMode: TimezoneAlignmentMode
    public var manualTimeZoneIdentifier: String
    public var relaunchDockAppsWithTimezone: Bool

    /// 综合总开关后实际生效的时区策略（总开关关闭时恒为 `.disabled`）
    public var effectiveTimezoneAlignmentMode: TimezoneAlignmentMode {
        timezoneAlignmentEnabled ? timezoneAlignmentMode : .disabled
    }

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
        timezoneAlignmentEnabled: Bool = true,
        timezoneAlignmentMode: TimezoneAlignmentMode = .autoFromExit,
        manualTimeZoneIdentifier: String = "America/Los_Angeles",
        relaunchDockAppsWithTimezone: Bool = true,
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
        self.timezoneAlignmentEnabled = timezoneAlignmentEnabled
        self.timezoneAlignmentMode = timezoneAlignmentMode
        self.manualTimeZoneIdentifier = manualTimeZoneIdentifier
        self.relaunchDockAppsWithTimezone = relaunchDockAppsWithTimezone
        self.onboardingCompleted = onboardingCompleted
        self.targets = targets
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.configRevision = try c.decodeIfPresent(UInt64.self, forKey: .configRevision) ?? 1
        self.protectionEnabled = try c.decodeIfPresent(Bool.self, forKey: .protectionEnabled) ?? true
        self.exitCheckMode = try c.decodeIfPresent(ExitCheckMode.self, forKey: .exitCheckMode) ?? .all
        self.admissionRuleMode = try c.decodeIfPresent(AdmissionRuleMode.self, forKey: .admissionRuleMode) ?? .ipOnly
        self.allowedIPs = try c.decodeIfPresent([AllowedIPEntry].self, forKey: .allowedIPs) ?? []
        self.allowedRegions = try c.decodeIfPresent([String].self, forKey: .allowedRegions) ?? []
        self.detectIPChange = try c.decodeIfPresent(Bool.self, forKey: .detectIPChange) ?? false
        self.pollIntervalSeconds = try c.decodeIfPresent(Double.self, forKey: .pollIntervalSeconds) ?? 3.0
        self.showInterceptAlert = try c.decodeIfPresent(Bool.self, forKey: .showInterceptAlert) ?? true
        self.launchAtLogin = try c.decodeIfPresent(Bool.self, forKey: .launchAtLogin) ?? true
        self.protectClaudeCLI = try c.decodeIfPresent(Bool.self, forKey: .protectClaudeCLI) ?? true
        self.realClaudeCLIPath = try c.decodeIfPresent(String.self, forKey: .realClaudeCLIPath)
        self.blockClaudeAutoUpdates = try c.decodeIfPresent(Bool.self, forKey: .blockClaudeAutoUpdates) ?? true
        self.useCustomHTTPProxy = try c.decodeIfPresent(Bool.self, forKey: .useCustomHTTPProxy) ?? false
        self.customHTTPProxyURL = try c.decodeIfPresent(String.self, forKey: .customHTTPProxyURL) ?? ""
        let storedMode = try c.decodeIfPresent(TimezoneAlignmentMode.self, forKey: .timezoneAlignmentMode) ?? .autoFromExit
        // 兼容旧配置：旧版用 mode == .disabled 表示关闭，迁移为总开关关闭
        self.timezoneAlignmentEnabled = try c.decodeIfPresent(Bool.self, forKey: .timezoneAlignmentEnabled) ?? (storedMode != .disabled)
        self.timezoneAlignmentMode = storedMode == .disabled ? .autoFromExit : storedMode
        self.manualTimeZoneIdentifier = try c.decodeIfPresent(String.self, forKey: .manualTimeZoneIdentifier) ?? "America/Los_Angeles"
        self.relaunchDockAppsWithTimezone = try c.decodeIfPresent(Bool.self, forKey: .relaunchDockAppsWithTimezone) ?? true
        self.onboardingCompleted = try c.decodeIfPresent(Bool.self, forKey: .onboardingCompleted) ?? false
        self.targets = try c.decodeIfPresent([GuardedTarget].self, forKey: .targets) ?? GuardedTarget.defaultTargets
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
        // 内置预设的进程匹配与网络封禁字段随程序版本刷新（保留用户的启用开关），避免旧配置沿用过宽/过时的规则
        for idx in decoded.targets.indices where decoded.targets[idx].isBuiltIn {
            if let preset = GuardedTarget.defaultTargets.first(where: { $0.id == decoded.targets[idx].id }) {
                var refreshed = preset
                refreshed.isEnabled = decoded.targets[idx].isEnabled
                decoded.targets[idx] = refreshed
            }
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
