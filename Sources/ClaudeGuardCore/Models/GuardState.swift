import Foundation

/// 全局门禁判定结论。
public enum GuardVerdict: String, Codable, Sendable, Equatable {
    /// 所有启用通道与目标链路均通过白名单/地区校验，允许运行与联网
    case allowed
    /// 明确检测到出口不合规、规则为空或触发 IP 跳变锁：封锁网络 + 终止已启用守护进程
    case blocked
    /// 网络离线或探测超时未拿到完整结果：Fail-closed 封锁域名并阻止新启动，但容忍已在运行中的会话渡过短暂抖动
    case offline
    /// 用户主动暂停防护：解封网络，不拦截启动
    case paused

    public var shouldBlockDomains: Bool {
        switch self {
        case .allowed, .paused:
            return false
        case .blocked, .offline:
            return true
        }
    }

    public var shouldBlockFreshLaunch: Bool {
        switch self {
        case .allowed, .paused:
            return false
        case .blocked, .offline:
            return true
        }
    }

    public var shouldTerminateRunningApps: Bool {
        self == .blocked
    }

    public var title: String {
        switch self {
        case .allowed: return "已受保护 · 允许通行"
        case .blocked: return "已熔断拦截 · 网络已封锁"
        case .offline: return "出口未确认 · 默认封锁中"
        case .paused:  return "防护已暂停"
        }
    }

    public var sfSymbolName: String {
        switch self {
        case .allowed: return "checkmark.shield.fill"
        case .blocked: return "xmark.shield.fill"
        case .offline: return "exclamationmark.shield.fill"
        case .paused:  return "shield.slash"
        }
    }
}

/// 单个通用通道（HTTP / STUN）的探测快照。
public struct ChannelProbeSnapshot: Codable, Sendable, Equatable {
    public var channel: String
    public var ip: String?
    public var matchedEntryLabel: String?
    public var passed: Bool
    public var latencyMs: Int?
    public var errorDescription: String?

    public init(
        channel: String,
        ip: String? = nil,
        matchedEntryLabel: String? = nil,
        passed: Bool = false,
        latencyMs: Int? = nil,
        errorDescription: String? = nil
    ) {
        self.channel = channel
        self.ip = ip
        self.matchedEntryLabel = matchedEntryLabel
        self.passed = passed
        self.latencyMs = latencyMs
        self.errorDescription = errorDescription
    }
}

/// 单个被守护目标真实链路（`cdn-cgi/trace`）的探测快照。
public struct TargetProbeSnapshot: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var targetName: String
    public var ip: String?
    public var countryCode: String?
    public var matchedRuleSummary: String?
    public var passed: Bool
    public var latencyMs: Int?
    public var errorDescription: String?

    public init(
        id: String,
        targetName: String,
        ip: String? = nil,
        countryCode: String? = nil,
        matchedRuleSummary: String? = nil,
        passed: Bool = false,
        latencyMs: Int? = nil,
        errorDescription: String? = nil
    ) {
        self.id = id
        self.targetName = targetName
        self.ip = ip
        self.countryCode = countryCode
        self.matchedRuleSummary = matchedRuleSummary
        self.passed = passed
        self.latencyMs = latencyMs
        self.errorDescription = errorDescription
    }
}

/// 本机代理软件与虚拟网卡环境快照。
public struct ProxyEnvironmentSnapshot: Codable, Sendable, Equatable {
    public var isV2rayNInstalled: Bool
    public var isV2rayNRunning: Bool
    public var v2rayNAppPath: String?
    public var activeTUNInterfaces: [String]
    public var systemHTTPProxy: String?

    public init(
        isV2rayNInstalled: Bool = false,
        isV2rayNRunning: Bool = false,
        v2rayNAppPath: String? = nil,
        activeTUNInterfaces: [String] = [],
        systemHTTPProxy: String? = nil
    ) {
        self.isV2rayNInstalled = isV2rayNInstalled
        self.isV2rayNRunning = isV2rayNRunning
        self.v2rayNAppPath = v2rayNAppPath
        self.activeTUNInterfaces = activeTUNInterfaces
        self.systemHTTPProxy = systemHTTPProxy
    }

    public var summaryBadge: String {
        if !activeTUNInterfaces.isEmpty {
            return "TUN 已启用 (\(activeTUNInterfaces.joined(separator: ", ")))"
        }
        if let proxy = systemHTTPProxy, !proxy.isEmpty {
            return "系统代理 (\(proxy))"
        }
        if isV2rayNInstalled && !isV2rayNRunning {
            return "v2rayN 未运行（直连状态）"
        }
        return "未检测到代理接管（直连状态）"
    }
}

/// 守护进程每次巡检后原子写入 `state.json` 的全局唯一真相（供 GUI 与 `claudeguard-cli` 共享）。
public struct SharedGuardState: Codable, Sendable, Equatable {
    public var verdict: GuardVerdict
    public var reason: String
    public var primaryIP: String?
    public var primaryCountryCode: String?
    public var matchedWhitelistLabel: String?
    public var jumpLatched: Bool
    public var jumpBeforeIP: String?
    public var jumpAfterIP: String?
    public var httpSnapshot: ChannelProbeSnapshot?
    public var stunSnapshot: ChannelProbeSnapshot?
    public var targetSnapshots: [TargetProbeSnapshot]
    public var proxyEnvironment: ProxyEnvironmentSnapshot
    public var configRevision: UInt64
    public var exitCheckMode: ExitCheckMode
    public var pollIntervalSeconds: Double
    public var helperInstalled: Bool
    public var updatedAt: Date

    public init(
        verdict: GuardVerdict = .offline,
        reason: String = "正在初始化出口检测…",
        primaryIP: String? = nil,
        primaryCountryCode: String? = nil,
        matchedWhitelistLabel: String? = nil,
        jumpLatched: Bool = false,
        jumpBeforeIP: String? = nil,
        jumpAfterIP: String? = nil,
        httpSnapshot: ChannelProbeSnapshot? = nil,
        stunSnapshot: ChannelProbeSnapshot? = nil,
        targetSnapshots: [TargetProbeSnapshot] = [],
        proxyEnvironment: ProxyEnvironmentSnapshot = ProxyEnvironmentSnapshot(),
        configRevision: UInt64 = 0,
        exitCheckMode: ExitCheckMode = .all,
        pollIntervalSeconds: Double = 3.0,
        helperInstalled: Bool = false,
        updatedAt: Date = Date()
    ) {
        self.verdict = verdict
        self.reason = reason
        self.primaryIP = primaryIP
        self.primaryCountryCode = primaryCountryCode
        self.matchedWhitelistLabel = matchedWhitelistLabel
        self.jumpLatched = jumpLatched
        self.jumpBeforeIP = jumpBeforeIP
        self.jumpAfterIP = jumpAfterIP
        self.httpSnapshot = httpSnapshot
        self.stunSnapshot = stunSnapshot
        self.targetSnapshots = targetSnapshots
        self.proxyEnvironment = proxyEnvironment
        self.configRevision = configRevision
        self.exitCheckMode = exitCheckMode
        self.pollIntervalSeconds = pollIntervalSeconds
        self.helperInstalled = helperInstalled
        self.updatedAt = updatedAt
    }

    /// 判断 `state.json` 是否在有效新鲜期内，且与当前配置版本一致。
    public func isFresh(for config: GuardConfig, now: Date = Date()) -> Bool {
        let maxAge = max(7.0, config.clampedPollInterval + 4.0)
        let age = now.timeIntervalSince(updatedAt)
        return age >= -2.0 && age <= maxAge && configRevision == config.configRevision
    }
}

public final class SharedStateStore: Sendable {
    public let paths: GuardPaths

    public init(paths: GuardPaths = .live) {
        self.paths = paths
    }

    public func read() -> SharedGuardState? {
        guard let data = try? Data(contentsOf: paths.stateFile) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(SharedGuardState.self, from: data)
    }

    public func write(_ state: SharedGuardState) throws {
        try paths.ensureDirectoriesExist()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(state)
        try data.write(to: paths.stateFile, options: .atomic)
    }
}
