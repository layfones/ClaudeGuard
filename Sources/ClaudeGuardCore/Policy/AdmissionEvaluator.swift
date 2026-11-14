import Foundation

/// 综合评估三路探测结果（HTTP + UDP STUN + 各目标 `cdn-cgi/trace` 真实链路）、
/// 白名单/允许国家码组合与持久化 IP 跳变锁，输出唯一确定的 `GuardVerdict` 与诊断快照。
public enum AdmissionEvaluator {
    public struct EvaluationInput: Sendable {
        public var config: GuardConfig
        public var httpResult: HTTPExitProber.Result?
        public var stunResult: STUNProber.Result?
        /// 仅当域名未处于 `/etc/hosts` 沉洞封禁态（或刚解封复核）时传入目标真实链路结果
        public var targetSnapshots: [TargetProbeSnapshot]
        public var verifyTargetTraces: Bool

        public init(
            config: GuardConfig,
            httpResult: HTTPExitProber.Result?,
            stunResult: STUNProber.Result?,
            targetSnapshots: [TargetProbeSnapshot],
            verifyTargetTraces: Bool
        ) {
            self.config = config
            self.httpResult = httpResult
            self.stunResult = stunResult
            self.targetSnapshots = targetSnapshots
            self.verifyTargetTraces = verifyTargetTraces
        }
    }

    public struct EvaluationOutput: Sendable, Equatable {
        public var verdict: GuardVerdict
        public var reason: String
        public var primaryIP: String?
        public var primaryCountryCode: String?
        public var matchedWhitelistLabel: String?
        public var jumpLatched: Bool
        public var jumpBeforeIP: String?
        public var jumpAfterIP: String?
        public var routeLeakDetectedNow: Bool
        public var httpSnapshot: ChannelProbeSnapshot?
        public var stunSnapshot: ChannelProbeSnapshot?
        public var targetSnapshots: [TargetProbeSnapshot]
    }

    /// 评估单个 IP +（可选）国家码是否满足当前 `GuardConfig` 的准入规则。
    public static func evaluateSingleEndpoint(
        ip: String,
        countryCode: String?,
        config: GuardConfig
    ) -> (passed: Bool, summary: String, matchedEntry: AllowedIPEntry?) {
        let enabledEntries = config.enabledAllowedIPs
        let allowedRegions = config.normalizedAllowedRegions

        let matchedIP = CIDRMatcher.firstMatchingEntry(for: ip, in: enabledEntries)
        let normalizedCC = countryCode?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        let regionMatched: Bool = {
            guard let cc = normalizedCC, !allowedRegions.isEmpty else { return false }
            return allowedRegions.contains(cc)
        }()

        switch config.admissionRuleMode {
        case .ipOnly:
            guard !enabledEntries.isEmpty else {
                return (false, "尚未添加启用中的 IP 白名单规则", nil)
            }
            if let entry = matchedIP {
                let tag = entry.label.isEmpty ? entry.cidrOrIP : entry.label
                return (true, "命中白名单「\(tag)」", entry)
            }
            return (false, "出口 \(ip) 不在 IP 白名单中", nil)

        case .ipOrRegion:
            guard !enabledEntries.isEmpty || !allowedRegions.isEmpty else {
                return (false, "白名单 IP 与允许地区均为空", nil)
            }
            if let entry = matchedIP {
                let tag = entry.label.isEmpty ? entry.cidrOrIP : entry.label
                return (true, "命中白名单「\(tag)」", entry)
            }
            if regionMatched, let cc = normalizedCC {
                return (true, "命中允许地区 (\(cc))", nil)
            }
            if let cc = normalizedCC {
                return (false, "出口 \(ip) (\(cc)) 未命中白名单或允许地区", nil)
            }
            return (false, "出口 \(ip) 未命中白名单（且未获取到地区码）", nil)

        case .ipAndRegion:
            guard !enabledEntries.isEmpty && !allowedRegions.isEmpty else {
                return (false, "双重校验模式需同时配置 IP 白名单与允许地区", nil)
            }
            guard let entry = matchedIP else {
                return (false, "出口 \(ip) 不在 IP 白名单中", nil)
            }
            guard let cc = normalizedCC else {
                return (false, "出口 \(ip) 命中白名单，但未能确认国家/地区码", entry)
            }
            guard regionMatched else {
                return (false, "出口 \(ip) 地区为 \(cc)，不在允许地区列表中", entry)
            }
            let tag = entry.label.isEmpty ? entry.cidrOrIP : entry.label
            return (true, "同时命中「\(tag)」与地区 \(cc)", entry)
        }
    }

    public static func evaluate(
        input: EvaluationInput,
        stateStore: AdmissionStateStore
    ) -> EvaluationOutput {
        let cfg = input.config

        // 1. 用户主动暂停防护
        if !cfg.protectionEnabled {
            return EvaluationOutput(
                verdict: .paused,
                reason: "防护已由用户手动暂停，网络处于放行状态。",
                primaryIP: input.httpResult?.ip ?? input.stunResult?.ip,
                primaryCountryCode: input.httpResult?.countryCode,
                matchedWhitelistLabel: nil,
                jumpLatched: false,
                jumpBeforeIP: nil,
                jumpAfterIP: nil,
                routeLeakDetectedNow: false,
                httpSnapshot: buildChannelSnapshot("HTTP", from: input.httpResult, config: cfg),
                stunSnapshot: buildSTUNSnapshot(from: input.stunResult, config: cfg),
                targetSnapshots: input.targetSnapshots
            )
        }

        // 2. 空配置门禁：绝不裸奔放行
        let hasAnyRule: Bool = {
            switch cfg.admissionRuleMode {
            case .ipOnly:
                return !cfg.enabledAllowedIPs.isEmpty
            case .ipOrRegion:
                return !cfg.enabledAllowedIPs.isEmpty || !cfg.normalizedAllowedRegions.isEmpty
            case .ipAndRegion:
                return !cfg.enabledAllowedIPs.isEmpty && !cfg.normalizedAllowedRegions.isEmpty
            }
        }()

        let httpSnap = cfg.exitCheckMode.includesHTTP ? buildChannelSnapshot("HTTP", from: input.httpResult, config: cfg) : nil
        let stunSnap = cfg.exitCheckMode.includesSTUN ? buildSTUNSnapshot(from: input.stunResult, config: cfg) : nil

        var evaluatedTargets: [TargetProbeSnapshot] = []
        for var snap in input.targetSnapshots {
            if let ip = snap.ip {
                let res = evaluateSingleEndpoint(
                    ip: ip,
                    countryCode: snap.countryCode ?? input.httpResult?.countryCode,
                    config: cfg
                )
                snap.passed = res.passed
                snap.matchedRuleSummary = res.summary
            } else {
                snap.passed = false
            }
            evaluatedTargets.append(snap)
        }

        let primaryIP = evaluatedTargets.first(where: { $0.ip != nil })?.ip
            ?? httpSnap?.ip
            ?? stunSnap?.ip
        let primaryCC = evaluatedTargets.first(where: { $0.countryCode != nil })?.countryCode
            ?? input.httpResult?.countryCode
        let primaryLabel = httpSnap?.matchedEntryLabel
            ?? stunSnap?.matchedEntryLabel

        if !hasAnyRule {
            return EvaluationOutput(
                verdict: .blocked,
                reason: "尚未配置任何有效白名单规则，默认锁死网络防直连泄漏。",
                primaryIP: primaryIP,
                primaryCountryCode: primaryCC,
                matchedWhitelistLabel: nil,
                jumpLatched: false,
                jumpBeforeIP: nil,
                jumpAfterIP: nil,
                routeLeakDetectedNow: false,
                httpSnapshot: httpSnap,
                stunSnapshot: stunSnap,
                targetSnapshots: evaluatedTargets
            )
        }

        // 3. 采集当前观测到的各通道出口 IP（用于 IP 跳变检测）
        var observedChannels: [String: String] = [:]
        if let ip = httpSnap?.ip { observedChannels["http"] = ip }
        if let ip = stunSnap?.ip { observedChannels["stun"] = ip }
        for t in evaluatedTargets {
            if let ip = t.ip { observedChannels["target:\(t.id)"] = ip }
        }

        // 4. 先检查持久化分流泄漏锁与 IP 跳变锁（一旦检测到跳变立即落盘锁定）
        let latchOutcome = stateStore.withExclusiveAccess { persisted -> (routeLeak: String?, jumpBefore: String?, jumpAfter: String?, latched: Bool) in
            if persisted.routeLeakLatched {
                return (persisted.routeLeakMessage ?? "检测到目标域名分流异常，已锁定拦截。", nil, nil, false)
            }
            if cfg.detectIPChange {
                if !persisted.jumpLatched {
                    for key in observedChannels.keys.sorted() {
                        if let current = observedChannels[key],
                           let baseline = persisted.baselineIPs[key],
                           current != baseline {
                            persisted.jumpLatched = true
                            persisted.jumpChannel = key
                            persisted.jumpBeforeIP = baseline
                            persisted.jumpAfterIP = current
                            break
                        }
                    }
                }
                if persisted.jumpLatched {
                    return (nil, persisted.jumpBeforeIP, persisted.jumpAfterIP, true)
                }
            }
            return (nil, nil, nil, false)
        }

        if let leakReason = latchOutcome.routeLeak {
            return EvaluationOutput(
                verdict: .blocked,
                reason: leakReason,
                primaryIP: primaryIP,
                primaryCountryCode: primaryCC,
                matchedWhitelistLabel: primaryLabel,
                jumpLatched: false,
                jumpBeforeIP: nil,
                jumpAfterIP: nil,
                routeLeakDetectedNow: false,
                httpSnapshot: httpSnap,
                stunSnapshot: stunSnap,
                targetSnapshots: evaluatedTargets
            )
        }

        if latchOutcome.latched {
            let beforeStr = latchOutcome.jumpBefore ?? "原节点"
            let afterStr = latchOutcome.jumpAfter ?? (primaryIP ?? "新节点")
            return EvaluationOutput(
                verdict: .blocked,
                reason: "检测到出口 IP 发生跳变（\(beforeStr) → \(afterStr)），已自动锁死，请确认是否信任新出口。",
                primaryIP: primaryIP,
                primaryCountryCode: primaryCC,
                matchedWhitelistLabel: primaryLabel,
                jumpLatched: true,
                jumpBeforeIP: latchOutcome.jumpBefore,
                jumpAfterIP: latchOutcome.jumpAfter,
                routeLeakDetectedNow: false,
                httpSnapshot: httpSnap,
                stunSnapshot: stunSnap,
                targetSnapshots: evaluatedTargets
            )
        }

        // 5. 明确的未通过（已拿到 IP，但不符合规则）优先判为 .blocked（高于另一通道超时的 .offline）
        if let hs = httpSnap, hs.ip != nil, !hs.passed {
            return EvaluationOutput(
                verdict: .blocked,
                reason: hs.errorDescription ?? "HTTP 出口未通过白名单检查",
                primaryIP: primaryIP,
                primaryCountryCode: primaryCC,
                matchedWhitelistLabel: nil,
                jumpLatched: false,
                jumpBeforeIP: nil,
                jumpAfterIP: nil,
                routeLeakDetectedNow: false,
                httpSnapshot: httpSnap,
                stunSnapshot: stunSnap,
                targetSnapshots: evaluatedTargets
            )
        }

        if let ss = stunSnap, ss.ip != nil, !ss.passed {
            return EvaluationOutput(
                verdict: .blocked,
                reason: ss.errorDescription ?? "UDP STUN 出口 (\(ss.ip!)) 未通过白名单检查（可能存在 UDP 直连泄漏）",
                primaryIP: primaryIP,
                primaryCountryCode: primaryCC,
                matchedWhitelistLabel: nil,
                jumpLatched: false,
                jumpBeforeIP: nil,
                jumpAfterIP: nil,
                routeLeakDetectedNow: false,
                httpSnapshot: httpSnap,
                stunSnapshot: stunSnap,
                targetSnapshots: evaluatedTargets
            )
        }

        if input.verifyTargetTraces {
            if let failedTarget = evaluatedTargets.first(where: { $0.ip != nil && !$0.passed }) {
                let leakMsg = "\(failedTarget.targetName) 真实链路出口 \(failedTarget.ip ?? "") 未通过白名单（分流规则可能漏网直连）！"
                // 若通用通道通过但目标自身域名未通过，持久化锁定防震荡
                let generalPassed = (httpSnap?.passed ?? true) && (stunSnap?.passed ?? true)
                if generalPassed {
                    stateStore.withExclusiveAccess { persisted in
                        persisted.routeLeakLatched = true
                        persisted.routeLeakMessage = leakMsg
                    }
                }
                return EvaluationOutput(
                    verdict: .blocked,
                    reason: leakMsg,
                    primaryIP: failedTarget.ip ?? primaryIP,
                    primaryCountryCode: failedTarget.countryCode ?? primaryCC,
                    matchedWhitelistLabel: nil,
                    jumpLatched: false,
                    jumpBeforeIP: nil,
                    jumpAfterIP: nil,
                    routeLeakDetectedNow: generalPassed,
                    httpSnapshot: httpSnap,
                    stunSnapshot: stunSnap,
                    targetSnapshots: evaluatedTargets
                )
            }
        }

        // 6. 检查必需通道是否缺失结果（超时 / 断网 → .offline Fail-closed）
        if cfg.exitCheckMode.includesHTTP && httpSnap?.ip == nil {
            return EvaluationOutput(
                verdict: .offline,
                reason: httpSnap?.errorDescription ?? "暂时无法确认 HTTP 出口 IP，默认保持域名封锁。",
                primaryIP: primaryIP,
                primaryCountryCode: primaryCC,
                matchedWhitelistLabel: nil,
                jumpLatched: false,
                jumpBeforeIP: nil,
                jumpAfterIP: nil,
                routeLeakDetectedNow: false,
                httpSnapshot: httpSnap,
                stunSnapshot: stunSnap,
                targetSnapshots: evaluatedTargets
            )
        }

        if cfg.exitCheckMode.includesSTUN && stunSnap?.ip == nil {
            return EvaluationOutput(
                verdict: .offline,
                reason: stunSnap?.errorDescription ?? "暂时无法确认 UDP STUN 出口 IP，默认保持域名封锁。",
                primaryIP: primaryIP,
                primaryCountryCode: primaryCC,
                matchedWhitelistLabel: nil,
                jumpLatched: false,
                jumpBeforeIP: nil,
                jumpAfterIP: nil,
                routeLeakDetectedNow: false,
                httpSnapshot: httpSnap,
                stunSnapshot: stunSnap,
                targetSnapshots: evaluatedTargets
            )
        }

        if input.verifyTargetTraces {
            if let missingTarget = evaluatedTargets.first(where: { $0.ip == nil }) {
                return EvaluationOutput(
                    verdict: .offline,
                    reason: "\(missingTarget.targetName) 链路探测超时（\(missingTarget.errorDescription ?? "未响应")），暂不放行。",
                    primaryIP: primaryIP,
                    primaryCountryCode: primaryCC,
                    matchedWhitelistLabel: nil,
                    jumpLatched: false,
                    jumpBeforeIP: nil,
                    jumpAfterIP: nil,
                    routeLeakDetectedNow: false,
                    httpSnapshot: httpSnap,
                    stunSnapshot: stunSnap,
                    targetSnapshots: evaluatedTargets
                )
            }
        }

        // 7. 所有启用通道与目标链路全部通过！记录初始基准 IP
        stateStore.withExclusiveAccess { persisted in
            for (k, v) in observedChannels where persisted.baselineIPs[k] == nil {
                persisted.baselineIPs[k] = v
            }
        }

        let summaryReason: String
        if let label = primaryLabel, !label.isEmpty {
            summaryReason = "出口校验通过 · 当前节点「\(label)」"
        } else if let cc = primaryCC {
            summaryReason = "出口校验通过 · 地区 \(cc)"
        } else {
            summaryReason = "所有受检通道均符合白名单规则"
        }

        return EvaluationOutput(
            verdict: .allowed,
            reason: summaryReason,
            primaryIP: primaryIP,
            primaryCountryCode: primaryCC,
            matchedWhitelistLabel: primaryLabel,
            jumpLatched: false,
            jumpBeforeIP: nil,
            jumpAfterIP: nil,
            routeLeakDetectedNow: false,
            httpSnapshot: httpSnap,
            stunSnapshot: stunSnap,
            targetSnapshots: evaluatedTargets
        )
    }

    /// 用户手动点击「信任当前新出口」或「重试分流检测」时调用：用新探测到的快照更新基准并解除锁存。
    public static func acknowledgeCurrentExits(
        observedChannels: [String: String],
        stateStore: AdmissionStateStore
    ) {
        stateStore.withExclusiveAccess { persisted in
            persisted.jumpLatched = false
            persisted.jumpChannel = nil
            persisted.jumpBeforeIP = nil
            persisted.jumpAfterIP = nil
            persisted.routeLeakLatched = false
            persisted.routeLeakMessage = nil
            if !observedChannels.isEmpty {
                persisted.baselineIPs = observedChannels
            }
        }
    }

    private static func buildChannelSnapshot(
        _ name: String,
        from result: HTTPExitProber.Result?,
        config: GuardConfig
    ) -> ChannelProbeSnapshot {
        guard let res = result, let ip = res.ip else {
            return ChannelProbeSnapshot(
                channel: name,
                ip: nil,
                passed: false,
                latencyMs: result?.latencyMs,
                errorDescription: result?.errorDescription ?? "未能获取 \(name) 出口 IP"
            )
        }
        let check = evaluateSingleEndpoint(ip: ip, countryCode: res.countryCode, config: config)
        return ChannelProbeSnapshot(
            channel: name,
            ip: ip,
            matchedEntryLabel: check.matchedEntry.map { $0.label.isEmpty ? $0.cidrOrIP : $0.label },
            passed: check.passed,
            latencyMs: res.latencyMs,
            errorDescription: check.passed ? nil : check.summary
        )
    }

    private static func buildSTUNSnapshot(
        from result: STUNProber.Result?,
        config: GuardConfig
    ) -> ChannelProbeSnapshot {
        guard let res = result, let ip = res.ip else {
            return ChannelProbeSnapshot(
                channel: "STUN",
                ip: nil,
                passed: false,
                latencyMs: result?.latencyMs,
                errorDescription: result?.errorDescription ?? "未能获取 UDP STUN 出口 IP"
            )
        }
        // STUN 协议不含国家码；若规则是 ipOrRegion 且白名单为空（纯国家码模式），STUN 只负责确认 UDP 可通或校验 IP 白名单
        if config.admissionRuleMode == .ipOrRegion && config.enabledAllowedIPs.isEmpty && !config.normalizedAllowedRegions.isEmpty {
            return ChannelProbeSnapshot(
                channel: "STUN",
                ip: ip,
                matchedEntryLabel: "按地区放行模式",
                passed: true,
                latencyMs: res.latencyMs,
                errorDescription: nil
            )
        }
        // 若是 ipAndRegion，STUN 只核对 IP 白名单，国家码由 HTTP / Target Trace 核对
        if config.admissionRuleMode == .ipAndRegion {
            if let entry = CIDRMatcher.firstMatchingEntry(for: ip, in: config.enabledAllowedIPs) {
                let tag = entry.label.isEmpty ? entry.cidrOrIP : entry.label
                return ChannelProbeSnapshot(
                    channel: "STUN",
                    ip: ip,
                    matchedEntryLabel: tag,
                    passed: true,
                    latencyMs: res.latencyMs
                )
            } else {
                return ChannelProbeSnapshot(
                    channel: "STUN",
                    ip: ip,
                    passed: false,
                    latencyMs: res.latencyMs,
                    errorDescription: "UDP STUN 出口 \(ip) 不在 IP 白名单中"
                )
            }
        }

        let check = evaluateSingleEndpoint(ip: ip, countryCode: nil, config: config)
        return ChannelProbeSnapshot(
            channel: "STUN",
            ip: ip,
            matchedEntryLabel: check.matchedEntry.map { $0.label.isEmpty ? $0.cidrOrIP : $0.label },
            passed: check.passed,
            latencyMs: res.latencyMs,
            errorDescription: check.passed ? nil : check.summary
        )
    }
}
