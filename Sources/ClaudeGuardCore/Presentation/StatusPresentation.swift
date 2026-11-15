import Foundation

// 菜单栏状态面板的纯数据呈现层：把 `SharedGuardState` + `GuardConfig` 翻译成
// “判定 + 线路图 + 明细行 + 唯一主操作”，不依赖 SwiftUI，便于单元测试。

// MARK: - 线路图（三线归一）

/// 一条探测线路（HTTP、目标网站真实链路、UDP）。
public struct RouteLane: Equatable, Sendable, Identifiable {
    public enum State: Equatable, Sendable {
        /// 出口命中规则
        case pass
        /// 拿到出口，但未通过规则
        case fail
        /// 目标域名已被封锁，暂时无法复核
        case sealed
        /// 探测超时或未返回
        case missing
        /// 防护暂停，不判定
        case idle
    }

    public var id: String
    public var label: String
    public var ip: String?
    public var latencyMs: Int?
    public var state: State
    /// 该线路的出口与主出口不同（例如 UDP 绕开代理直连）
    public var diverges: Bool

    public init(id: String, label: String, ip: String? = nil, latencyMs: Int? = nil, state: State, diverges: Bool = false) {
        self.id = id
        self.label = label
        self.ip = ip
        self.latencyMs = latencyMs
        self.state = state
        self.diverges = diverges
    }
}

/// 线路收敛到的主出口。
public struct RouteExit: Equatable, Sendable {
    public enum State: Equatable, Sendable {
        case pass
        case fail
        case unknown
        case idle
    }

    public var ip: String?
    public var countryCode: String?
    public var colo: String?
    public var state: State

    public init(ip: String? = nil, countryCode: String? = nil, colo: String? = nil, state: State) {
        self.ip = ip
        self.countryCode = countryCode
        self.colo = colo
        self.state = state
    }

    /// 形如「美国 · LAX」的出口说明。
    public var metaText: String {
        var parts: [String] = []
        if let cc = countryCode?.uppercased(), !cc.isEmpty {
            parts.append(RoutePresenter.regionName(for: cc))
        }
        if let colo, !colo.isEmpty {
            parts.append(colo.uppercased())
        }
        return parts.joined(separator: " · ")
    }
}

public struct RoutePresentation: Equatable, Sendable {
    /// 已排序：收敛线路在前（HTTP → 目标网站 → UDP），分叉线路在后
    public var lanes: [RouteLane]
    public var exit: RouteExit

    public init(lanes: [RouteLane], exit: RouteExit) {
        self.lanes = lanes
        self.exit = exit
    }

    /// VoiceOver 朗读用的完整描述。
    public var accessibilitySummary: String {
        var parts: [String] = []
        for lane in lanes {
            switch lane.state {
            case .pass:
                parts.append("\(lane.label) 通过")
            case .fail:
                if lane.diverges, let ip = lane.ip {
                    parts.append("\(lane.label) 直连 \(ip)，未通过")
                } else {
                    parts.append("\(lane.label) 未通过")
                }
            case .sealed:
                parts.append("\(lane.label) 已封锁")
            case .missing:
                parts.append("\(lane.label) 未响应")
            case .idle:
                parts.append("\(lane.label) 未检查")
            }
        }
        if let ip = exit.ip {
            parts.append("出口 \(ip)\(exit.metaText.isEmpty ? "" : "，\(exit.metaText)")")
        } else {
            parts.append("出口未获取")
        }
        return parts.joined(separator: "；")
    }
}

public enum RoutePresenter {
    /// 目标网站线路最多显示的条数（避免面板过高）
    public static let maxTargetLanes = 2

    public static func make(state: SharedGuardState, config: GuardConfig) -> RoutePresentation {
        let paused = !config.protectionEnabled || state.verdict == .paused
        var lanes: [RouteLane] = []

        func lane(id: String, label: String, ip: String?, latency: Int?, passed: Bool) -> RouteLane {
            if paused { return RouteLane(id: id, label: label, ip: ip, latencyMs: latency, state: .idle) }
            guard let ip else { return RouteLane(id: id, label: label, latencyMs: latency, state: .missing) }
            return RouteLane(id: id, label: label, ip: ip, latencyMs: latency, state: passed ? .pass : .fail)
        }

        if config.exitCheckMode.includesHTTP {
            let snap = state.httpSnapshot
            lanes.append(lane(id: "http", label: "HTTP", ip: snap?.ip, latency: snap?.latencyMs, passed: snap?.passed ?? false))
        }

        let domainsSealed = state.verdict.shouldBlockDomains && state.targetSnapshots.isEmpty
        let traceTargets = config.enabledTargets.filter { $0.traceURL != nil }.prefix(maxTargetLanes)
        for target in traceTargets {
            let label = traceHost(for: target) ?? target.name
            if let snap = state.targetSnapshots.first(where: { $0.id == target.id }) {
                lanes.append(lane(id: "target:\(target.id)", label: label, ip: snap.ip, latency: snap.latencyMs, passed: snap.passed))
            } else if paused {
                lanes.append(RouteLane(id: "target:\(target.id)", label: label, state: .idle))
            } else if domainsSealed {
                lanes.append(RouteLane(id: "target:\(target.id)", label: label, state: .sealed))
            } else {
                lanes.append(RouteLane(id: "target:\(target.id)", label: label, state: .missing))
            }
        }

        if config.exitCheckMode.includesSTUN {
            let snap = state.stunSnapshot
            lanes.append(lane(id: "udp", label: "UDP", ip: snap?.ip, latency: snap?.latencyMs, passed: snap?.passed ?? false))
        }

        // 主出口：优先取通过线路的出口，其次取出现最多的出口
        let observed = lanes.compactMap(\.ip)
        let exitIP = lanes.first(where: { $0.state == .pass })?.ip
            ?? mostCommon(observed)
            ?? state.primaryIP

        for idx in lanes.indices {
            if let ip = lanes[idx].ip, let exitIP, ip != exitIP {
                lanes[idx].diverges = true
            }
        }
        // 分叉线路放到最下方，其余保持固定顺序
        lanes = lanes.filter { !$0.diverges } + lanes.filter(\.diverges)

        let converging = lanes.filter { !$0.diverges && $0.ip != nil && $0.ip == exitIP }
        let exitState: RouteExit.State
        if paused {
            exitState = .idle
        } else if exitIP == nil || converging.isEmpty {
            exitState = exitIP == nil ? .unknown : (state.verdict == .allowed ? .pass : .fail)
        } else if converging.allSatisfy({ $0.state == .pass }) {
            exitState = .pass
        } else {
            exitState = .fail
        }

        var cc: String?
        var colo: String?
        if let exitIP {
            if let t = state.targetSnapshots.first(where: { $0.ip == exitIP && $0.countryCode != nil }) {
                cc = t.countryCode
                colo = t.colo
            } else if state.primaryIP == exitIP {
                cc = state.primaryCountryCode
                colo = state.primaryColo
            }
        }

        return RoutePresentation(lanes: lanes, exit: RouteExit(ip: exitIP, countryCode: cc, colo: colo, state: exitState))
    }

    static func traceHost(for target: GuardedTarget) -> String? {
        guard let raw = target.traceURL, let host = URL(string: raw)?.host else { return nil }
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }

    private static func mostCommon(_ values: [String]) -> String? {
        var counts: [String: Int] = [:]
        for v in values { counts[v, default: 0] += 1 }
        // 次序稳定：数量相同取先出现者
        return values.max { (counts[$0] ?? 0) < (counts[$1] ?? 0) }
    }

    /// 国家/地区码的中文名（如 US → 美国）。
    public static func regionName(for code: String) -> String {
        Locale(identifier: "zh-Hans").localizedString(forRegionCode: code) ?? code
    }
}

// MARK: - 判定与唯一主操作

public struct VerdictPresentation: Equatable, Sendable {
    public enum Tone: Equatable, Sendable {
        case pass
        case block
        case hold
        case neutral
    }

    public enum Action: Equatable, Sendable {
        case openSetup
        case resumeProtection
        case trustNewExit
        case launchV2rayN
        case openV2rayN
        case disablePublicIPv6
        case launchTarget(id: String)
    }

    public var tone: Tone
    /// SF Symbol 名称
    public var symbol: String
    public var title: String
    public var message: String
    public var action: Action?
    public var actionTitle: String?
    /// 主操作下方的一句说明
    public var hint: String?

    public init(tone: Tone, symbol: String, title: String, message: String, action: Action? = nil, actionTitle: String? = nil, hint: String? = nil) {
        self.tone = tone
        self.symbol = symbol
        self.title = title
        self.message = message
        self.action = action
        self.actionTitle = actionTitle
        self.hint = hint
    }
}

public enum VerdictPresenter {
    public struct Context: Sendable {
        public var helperInstalled: Bool
        public var publicIPv6Disabled: Bool
        /// 本机已安装的守护目标 ID（由界面层通过 LaunchServices 查询后传入）
        public var installedTargetIDs: Set<String>

        public init(helperInstalled: Bool, publicIPv6Disabled: Bool, installedTargetIDs: Set<String>) {
            self.helperInstalled = helperInstalled
            self.publicIPv6Disabled = publicIPv6Disabled
            self.installedTargetIDs = installedTargetIDs
        }
    }

    public static func make(state: SharedGuardState, config: GuardConfig, context: Context) -> VerdictPresentation {
        let proxy = state.proxyEnvironment
        let v2rayNStopped = proxy.isV2rayNInstalled && !proxy.isV2rayNRunning
        let appName = config.enabledTargets.first.map { shortName($0.name) } ?? "受保护的应用"

        if !config.onboardingCompleted || !context.helperInstalled {
            return VerdictPresentation(
                tone: .neutral, symbol: "shield",
                title: "还差一步",
                message: "完成初始设置后，ClaudeGuard 才会开始守护。",
                action: .openSetup, actionTitle: "打开初始设置…"
            )
        }

        if !config.protectionEnabled || state.verdict == .paused {
            return VerdictPresentation(
                tone: .neutral, symbol: "pause.fill",
                title: "守护已暂停",
                message: "受保护的应用可以直接联网，ClaudeGuard 不做检查。",
                action: .resumeProtection, actionTitle: "恢复守护"
            )
        }

        switch state.verdict {
        case .allowed:
            let message: String
            if let label = state.matchedWhitelistLabel, !label.isEmpty {
                message = "出口一致，落在白名单「\(label)」内。"
            } else if let cc = state.primaryCountryCode {
                message = "出口一致，位于允许的地区（\(RoutePresenter.regionName(for: cc))）。"
            } else {
                message = "所有探测线路都符合放行规则。"
            }
            if let target = config.enabledTargets.first(where: { context.installedTargetIDs.contains($0.id) }) {
                return VerdictPresentation(
                    tone: .pass, symbol: "checkmark",
                    title: "可以放心使用", message: message,
                    action: .launchTarget(id: target.id), actionTitle: "打开 \(shortName(target.name))"
                )
            }
            return VerdictPresentation(tone: .pass, symbol: "checkmark", title: "可以放心使用", message: message)

        case .offline:
            if v2rayNStopped {
                return VerdictPresentation(
                    tone: .hold, symbol: "clock",
                    title: "正在确认出口",
                    message: "暂时拿不到出口信息，v2rayN 也没有运行。确认之前不放行。",
                    action: .launchV2rayN, actionTitle: "启动 v2rayN",
                    hint: "v2rayN 连上后会自动放行，不需要其他操作。"
                )
            }
            return VerdictPresentation(
                tone: .hold, symbol: "clock",
                title: "正在确认出口",
                message: "暂时拿不到完整的出口信息。确认之前，不允许新启动受保护的应用。"
            )

        case .blocked:
            if state.jumpLatched {
                let before = state.jumpBeforeIP ?? "原出口"
                let after = state.jumpAfterIP ?? state.primaryIP ?? "新出口"
                return VerdictPresentation(
                    tone: .block, symbol: "arrow.left.arrow.right",
                    title: "出口变了",
                    message: "\(before) → \(after)。确认是你自己切换了节点，再放行。",
                    action: .trustNewExit, actionTitle: "信任新出口"
                )
            }

            if !hasAnyRule(config) {
                return VerdictPresentation(
                    tone: .block, symbol: "xmark",
                    title: "还没有白名单",
                    message: "打开 v2rayN，确认连上后，把当前出口加入白名单。",
                    action: v2rayNStopped ? .launchV2rayN : nil,
                    actionTitle: v2rayNStopped ? "启动 v2rayN" : nil
                )
            }

            if v2rayNStopped {
                return VerdictPresentation(
                    tone: .block, symbol: "xmark",
                    title: "已拦截 \(appName)",
                    message: "出口是本机真实 IP，v2rayN 似乎没有运行。",
                    action: .launchV2rayN, actionTitle: "启动 v2rayN",
                    hint: "v2rayN 连上后会自动放行，不需要其他操作。"
                )
            }

            let http = state.httpSnapshot
            let stun = state.stunSnapshot
            if let http, http.passed, let stun, let stunIP = stun.ip, !stun.passed, stunIP != http.ip {
                if stunIP.contains(":") && !context.publicIPv6Disabled {
                    return VerdictPresentation(
                        tone: .block, symbol: "xmark",
                        title: "已拦截：UDP 直连",
                        message: "网页流量走了代理，但 UDP 通过公网 IPv6 直连了本机网络。",
                        action: .disablePublicIPv6, actionTitle: "关闭公网 IPv6",
                        hint: "只关闭运营商分配的公网 IPv6，AirDrop 不受影响。"
                    )
                }
                return VerdictPresentation(
                    tone: .block, symbol: "xmark",
                    title: "已拦截：UDP 直连",
                    message: "网页流量走了代理，但 UDP 绕开代理，直连了本机网络。",
                    action: proxy.isV2rayNInstalled ? .openV2rayN : nil,
                    actionTitle: proxy.isV2rayNInstalled ? "打开 v2rayN" : nil,
                    hint: "在 v2rayN 中开启 TUN 模式后，UDP 也会走代理。"
                )
            }

            let generalPassed = (http?.passed ?? true) && (stun?.passed ?? true)
            if generalPassed, let leaked = state.targetSnapshots.first(where: { $0.ip != nil && !$0.passed }) {
                let host = config.targets.first(where: { $0.id == leaked.id }).flatMap(RoutePresenter.traceHost(for:)) ?? leaked.targetName
                return VerdictPresentation(
                    tone: .block, symbol: "xmark",
                    title: "已拦截：分流漏网",
                    message: "\(host) 没有走代理，直连了 \(leaked.ip ?? "本机网络")。检查 v2rayN 的分流规则。",
                    action: proxy.isV2rayNInstalled ? .openV2rayN : nil,
                    actionTitle: proxy.isV2rayNInstalled ? "打开 v2rayN" : nil,
                    hint: "改好后点右上角的重新检测。"
                )
            }

            let message: String
            if let ip = state.primaryIP {
                message = "出口 \(ip) 不在白名单里。"
            } else {
                message = state.reason
            }
            return VerdictPresentation(tone: .block, symbol: "xmark", title: "已拦截 \(appName)", message: message)

        case .paused:
            // 已在上方处理
            return VerdictPresentation(tone: .neutral, symbol: "pause.fill", title: "守护已暂停", message: "")
        }
    }

    /// 去掉括号里的补充说明：`Claude (Desktop + Claude Code)` → `Claude`。
    public static func shortName(_ raw: String) -> String {
        if let paren = raw.firstIndex(of: "(") {
            return String(raw[..<paren]).trimmingCharacters(in: .whitespaces)
        }
        return raw
    }

    static func hasAnyRule(_ cfg: GuardConfig) -> Bool {
        switch cfg.admissionRuleMode {
        case .ipOnly:
            return !cfg.enabledAllowedIPs.isEmpty
        case .ipOrRegion:
            return !cfg.enabledAllowedIPs.isEmpty || !cfg.normalizedAllowedRegions.isEmpty
        case .ipAndRegion:
            return !cfg.enabledAllowedIPs.isEmpty && !cfg.normalizedAllowedRegions.isEmpty
        }
    }
}

// MARK: - 明细行

public struct StatusDetailRow: Equatable, Sendable, Identifiable {
    public var id: String { label }
    public var symbol: String
    public var label: String
    public var value: String

    public init(symbol: String, label: String, value: String) {
        self.symbol = symbol
        self.label = label
        self.value = value
    }
}

public enum StatusDetailPresenter {
    public static func make(state: SharedGuardState, config: GuardConfig, helperInstalled: Bool) -> [StatusDetailRow] {
        var rows: [StatusDetailRow] = [
            StatusDetailRow(symbol: "network", label: "代理", value: proxySummary(state.proxyEnvironment))
        ]
        // 只有完成初始设置后才会真正下发封锁（见 GuardCoordinator.performSingleCheckPass）
        if config.onboardingCompleted && config.protectionEnabled && state.verdict.shouldBlockDomains && helperInstalled {
            let name = config.enabledTargets.first.map { VerdictPresenter.shortName($0.name) } ?? "受保护应用"
            rows.append(StatusDetailRow(symbol: "lock", label: "网络", value: "已封锁 \(name) 相关域名"))
        } else if let tz = state.effectiveTimeZone {
            rows.insert(StatusDetailRow(symbol: "clock", label: "时区", value: timeZoneSummary(tz)), at: 0)
        }
        return rows
    }

    public static func proxySummary(_ env: ProxyEnvironmentSnapshot) -> String {
        if !env.activeTUNInterfaces.isEmpty {
            return env.isV2rayNRunning ? "v2rayN · TUN 模式" : "TUN 已启用"
        }
        if let proxy = env.systemHTTPProxy, !proxy.isEmpty {
            return env.isV2rayNRunning ? "v2rayN · 系统代理" : "系统代理 \(proxy)"
        }
        if env.isV2rayNInstalled && !env.isV2rayNRunning {
            return "v2rayN 未运行"
        }
        return "未检测到代理"
    }

    /// 形如「北美太平洋时间 · UTC−8」。
    public static func timeZoneSummary(_ identifier: String, now: Date = Date()) -> String {
        guard let tz = TimeZone(identifier: identifier) else { return identifier }
        let name = tz.localizedName(for: .generic, locale: Locale(identifier: "zh-Hans")) ?? identifier
        let seconds = tz.secondsFromGMT(for: now)
        let sign = seconds >= 0 ? "+" : "−"
        let hours = abs(seconds) / 3600
        let mins = (abs(seconds) % 3600) / 60
        let offset = mins == 0 ? "UTC\(sign)\(hours)" : String(format: "UTC%@%d:%02d", sign, hours, mins)
        return "\(name) · \(offset)"
    }
}
