import Foundation
import AppKit
import Network
import SystemConfiguration
import ClaudeGuardCore

public enum SettingsTab: String, CaseIterable, Identifiable, Sendable {
    case general
    case policy
    case targets
    case logs

    public var id: String { rawValue }
}

@MainActor
@Observable
public final class GuardCoordinator {
    public static let shared = GuardCoordinator()

    public let paths: GuardPaths
    public let configStore: ConfigStore
    public let sharedStateStore: SharedStateStore
    public let admissionStore: AdmissionStateStore
    public let eventLogger: EventLogger

    public var config: GuardConfig
    public var state: SharedGuardState
    public var recentEvents: [GuardEvent] = []
    public var cliStatus: CLIHookManager.StatusReport = .init()
    public var systemIPv6Status: SystemIPv6Status = .init()
    public var isSwitchingIPv6: Bool = false
    public var isChecking: Bool = false
    public var selectedSettingsTab: SettingsTab = .general
    public var lastActionMessage: String?
    public var lastActionIsError: Bool = false
    public var showSetupWindow: Bool = false

    private var pollTimer: Timer?
    private var integrityTimer: Timer?
    private var pathMonitor: NWPathMonitor?
    private var dynamicStore: SCDynamicStore?
    private var workspaceLaunchObserver: NSObjectProtocol?
    private var workspaceTerminateObserver: NSObjectProtocol?
    private var workspaceWakeObserver: NSObjectProtocol?

    private var pendingTZRelaunchUntil: [String: Date] = [:]
    private var tzAlignedPIDs: Set<pid_t> = []

    private var checkInFlight = false
    private var checkQueued = false
    private var lastAppliedDomainsBlocked: Bool?
    private var lastAppliedUpdatesBlocked: Bool?
    private var hasAlertedCurrentBlockEpisode = false
    private var started = false

    public init(paths: GuardPaths = .live) {
        self.paths = paths
        self.configStore = ConfigStore(paths: paths)
        self.sharedStateStore = SharedStateStore(paths: paths)
        self.admissionStore = AdmissionStateStore(paths: paths)
        self.eventLogger = EventLogger(paths: paths)

        let loadedConfig = configStore.load()
        self.config = loadedConfig
        self.state = SharedGuardState(
            verdict: loadedConfig.protectionEnabled ? .offline : .paused,
            reason: loadedConfig.onboardingCompleted ? "正在检测当前网络出口…" : "请先完成初始防线与白名单配置",
            configRevision: loadedConfig.configRevision,
            exitCheckMode: loadedConfig.exitCheckMode,
            pollIntervalSeconds: loadedConfig.clampedPollInterval,
            helperInstalled: PrivilegedInstaller.isHelperInstalled(paths: paths)
        )
        self.recentEvents = eventLogger.readRecent()
        self.systemIPv6Status = IPv6GuardManager.inspectStatus()
    }

    public func startIfNeeded() {
        guard !started else { return }
        started = true

        eventLogger.append(.guardStarted, message: "ClaudeGuard 原生守护已启动（模式：\(config.exitCheckMode.shortTitle)）")
        refreshEvents()

        setupAppLaunchInterceptor()
        setupConnectivityObservers()
        reschedulePollTimer()
        scheduleIntegritySelfHeal()

        if !config.onboardingCompleted || !PrivilegedInstaller.isHelperInstalled(paths: paths) {
            showSetupWindow = true
        }

        triggerRecheck()
    }

    // MARK: - 用户操作入口

    public func updateConfig(_ mutate: (inout GuardConfig) -> Void, triggerCheck: Bool = true) {
        var draft = config
        mutate(&draft)
        do {
            config = try configStore.save(draft)
            reschedulePollTimer()
            if triggerCheck {
                triggerRecheck()
            }
        } catch {
            setBanner("保存配置失败：\(error.localizedDescription)", isError: true)
        }
    }

    public func toggleProtection(_ enabled: Bool) {
        updateConfig { cfg in
            cfg.protectionEnabled = enabled
        }
    }

    public func addAllowedIP(cidrOrIP: String, label: String) -> Bool {
        let trimmed = cidrOrIP.trimmingCharacters(in: .whitespacesAndNewlines)
        guard CIDRMatcher.isValidIPOrCIDR(trimmed) else {
            setBanner("IP 或 CIDR 网段格式无效：\(trimmed)", isError: true)
            return false
        }
        updateConfig { cfg in
            if let idx = cfg.allowedIPs.firstIndex(where: { $0.cidrOrIP.caseInsensitiveCompare(trimmed) == .orderedSame }) {
                cfg.allowedIPs[idx].isEnabled = true
                if !label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    cfg.allowedIPs[idx].label = label.trimmingCharacters(in: .whitespacesAndNewlines)
                }
            } else {
                cfg.allowedIPs.insert(
                    AllowedIPEntry(cidrOrIP: trimmed, label: label.isEmpty ? "代理节点" : label, isEnabled: true),
                    at: 0
                )
            }
        }
        setBanner("已将 \(trimmed) 加入白名单", isError: false)
        return true
    }

    public func acknowledgeCurrentExitJump() {
        Task {
            isChecking = true
            let observed = await collectFreshObservedChannels()
            AdmissionEvaluator.acknowledgeCurrentExits(observedChannels: observed, stateStore: admissionStore)
            eventLogger.append(
                .ipJumpAcknowledged,
                message: "用户确认信任新出口并更新基准：\(observed.values.sorted().joined(separator: ", "))",
                detectedIP: state.primaryIP
            )
            refreshEvents()
            setBanner("已更新出口基准并重新校验", isError: false)
            await performSingleCheckPass()
            isChecking = false
        }
    }

    public func installHelperWithPrompt() {
        do {
            try PrivilegedInstaller.installPrivilegedHelper(paths: paths)
            PrivilegedInstaller.setLaunchAtLogin(enabled: config.launchAtLogin, paths: paths)
            cliStatus = CLIHookManager.syncHooks(
                protectCLI: config.protectClaudeCLI,
                configuredRealCLI: config.realClaudeCLIPath,
                paths: paths
            )
            state.helperInstalled = PrivilegedInstaller.isHelperInstalled(paths: paths)
            lastAppliedDomainsBlocked = nil
            lastAppliedUpdatesBlocked = nil
            eventLogger.append(.helperInstalled, message: "已授权部署系统级 LaunchDaemon 网络助手")
            refreshEvents()
            setBanner("特权网络防线部署成功", isError: false)
            triggerRecheck()
        } catch {
            setBanner(error.localizedDescription, isError: true)
        }
    }

    public func completeOnboarding() {
        PrivilegedInstaller.setLaunchAtLogin(enabled: config.launchAtLogin, paths: paths)
        cliStatus = CLIHookManager.syncHooks(
            protectCLI: config.protectClaudeCLI,
            configuredRealCLI: config.realClaudeCLIPath,
            paths: paths
        )
        lastAppliedDomainsBlocked = nil
        lastAppliedUpdatesBlocked = nil
        updateConfig { cfg in
            cfg.onboardingCompleted = true
            cfg.protectionEnabled = true
        }
        showSetupWindow = false
    }

    public func runDoctorRepair() {
        cliStatus = CLIHookManager.syncHooks(
            protectCLI: config.protectClaudeCLI,
            configuredRealCLI: config.realClaudeCLIPath,
            paths: paths
        )
        lastAppliedDomainsBlocked = nil
        lastAppliedUpdatesBlocked = nil
        triggerRecheck()
        setBanner("已完成钩子与网络规则自检修复", isError: false)
    }

    public func emergencyUnblock() {
        updateConfig({ cfg in
            cfg.protectionEnabled = false
        }, triggerCheck: false)
        PrivilegedInstaller.emergencyUnblockAll(config: config, paths: paths)
        lastAppliedDomainsBlocked = false
        lastAppliedUpdatesBlocked = false
        eventLogger.append(.emergencyUnblocked, message: "用户在界面执行紧急解封，已释放所有域名与防火墙规则")
        refreshEvents()
        triggerRecheck()
        setBanner("已解除全部网络封锁并将防护设为暂停", isError: false)
    }

    public func uninstallAndQuit() {
        do {
            try PrivilegedInstaller.uninstallEverything(config: config, paths: paths)
            NSApplication.shared.terminate(nil)
        } catch {
            setBanner("卸载未完成：\(error.localizedDescription)", isError: true)
        }
    }

    public func toggleSystemPublicIPv6(disable: Bool) {
        guard !isSwitchingIPv6 else { return }
        isSwitchingIPv6 = true
        let pathsCopy = paths
        Task { @MainActor in
            defer { isSwitchingIPv6 = false }
            do {
                let updated = try await Task.detached {
                    try IPv6GuardManager.setPublicIPv6Disabled(disable, paths: pathsCopy)
                }.value
                systemIPv6Status = updated
                let actionDesc = disable
                    ? "已将物理网卡设为仅本地链接（关闭运营商公网 IPv6，保留 AirDrop）"
                    : "已恢复物理网卡自动获取公网 IPv6 (Automatic)"
                eventLogger.append(.systemIPv6Toggled, message: actionDesc)
                refreshEvents()
                setBanner(disable ? "已关闭系统公网 IPv6，正在重测出口…" : "已恢复系统公网 IPv6", isError: false)
                triggerRecheck()
            } catch {
                systemIPv6Status = IPv6GuardManager.inspectStatus()
                setBanner(error.localizedDescription, isError: true)
            }
        }
    }

    public func launchV2rayN() {
        if ProcessEnforcer.launchV2rayNIfInstalled() {
            setBanner("正在唤起 v2rayN，待连接就绪后将自动放行…", isError: false)
            for delay in [1.5, 4.0, 8.0] {
                Task {
                    try? await Task.sleep(for: .seconds(delay))
                    self.triggerRecheck()
                }
            }
        } else {
            setBanner("未在 /Applications 找到 v2rayN.app", isError: true)
        }
    }

    /// 从菜单栏悬浮卡片一键安全启动目标应用（自动携带当前对齐的进程级 `TZ` 时区）。
    public func launchGuardedAppAligned(_ target: GuardedTarget) {
        if config.protectionEnabled && state.verdict.shouldBlockFreshLaunch {
            setBanner("当前出口未通过校验，已阻止启动 \(target.name)", isError: true)
            return
        }
        let tz = state.effectiveTimeZone
        pendingTZRelaunchUntil[target.id] = Date().addingTimeInterval(8.0)
        if ProcessEnforcer.launchTargetWithEnvironment(target, timeZoneIdentifier: tz, createNewInstance: false) {
            if let tz {
                eventLogger.append(
                    .timezoneAlignedLaunch,
                    message: "启动 \(target.name) 并注入对齐时区 \(tz)",
                    detectedIP: state.primaryIP,
                    targetName: target.name
                )
                refreshEvents()
                setBanner("已按时区 \(tz) 启动 \(target.name)", isError: false)
            } else {
                setBanner("已启动 \(target.name)", isError: false)
            }
        } else {
            pendingTZRelaunchUntil.removeValue(forKey: target.id)
            setBanner("未找到已安装的 \(target.name)", isError: true)
        }
    }

    public func refreshEvents() {
        recentEvents = eventLogger.readRecent()
    }

    public func clearEvents() {
        eventLogger.clear()
        recentEvents = []
    }

    public func setBanner(_ message: String?, isError: Bool) {
        lastActionMessage = message
        lastActionIsError = isError
    }

    // MARK: - 合并式重检循环（杜绝并发探测漏事件）

    public func triggerRecheck() {
        if checkInFlight {
            checkQueued = true
            return
        }
        checkInFlight = true
        isChecking = true

        Task { @MainActor in
            while true {
                checkQueued = false
                await performSingleCheckPass()
                if !checkQueued {
                    break
                }
            }
            checkInFlight = false
            isChecking = false
        }
    }

    private func performSingleCheckPass() async {
        let currentCfg = config
        let proxyEnv = ProxyEnvironmentDetector.inspect()
        let ipv6Snap = await Task.detached { IPv6GuardManager.inspectStatus() }.value
        systemIPv6Status = ipv6Snap
        let helperReady = PrivilegedInstaller.isHelperInstalled(paths: paths)
        let customProxy = currentCfg.useCustomHTTPProxy ? currentCfg.customHTTPProxyURL : nil

        let hostsCurrentlyBlocked = (try? String(contentsOfFile: "/etc/hosts", encoding: .utf8))?
            .contains(NetworkBlockStaging.blockBeginMarker) ?? false

        // 第一阶段：并发探测不受 `/etc/hosts` 沉洞影响的通用 HTTP 出口、UDP STUN（若当前未封禁域名则一并探测各目标真实链路）
        let httpProber = HTTPExitProber()
        let stunProber = STUNProber()
        let traceProber = TargetTraceProber()
        let enabledTargets = currentCfg.enabledTargets

        async let httpTask: HTTPExitProber.Result? = currentCfg.exitCheckMode.includesHTTP
            ? await httpProber.probe(customProxyURL: customProxy, timeout: 2.5)
            : nil
        async let stunTask: STUNProber.Result? = currentCfg.exitCheckMode.includesSTUN
            ? await stunProber.probe(timeout: 1.5)
            : nil
        async let initialTraceTask: [TargetProbeSnapshot] = (!hostsCurrentlyBlocked && currentCfg.protectionEnabled)
            ? await traceProber.probeTargets(enabledTargets, customProxyURL: customProxy, timeout: 3.0)
            : []

        let (httpRes, stunRes, initialTraces) = await (httpTask, stunTask, initialTraceTask)

        var eval = AdmissionEvaluator.evaluate(
            input: .init(
                config: currentCfg,
                httpResult: httpRes,
                stunResult: stunRes,
                targetSnapshots: initialTraces,
                verifyTargetTraces: !hostsCurrentlyBlocked && !initialTraces.isEmpty
            ),
            stateStore: admissionStore
        )

        // 第二阶段：若此前处于封网状态，且通用 HTTP + STUN 现已恢复合规，先解封底层域名并立即复核目标真实链路（防分流规则写漏）
        if hostsCurrentlyBlocked && eval.verdict == .allowed && currentCfg.onboardingCompleted && helperReady {
            _ = await Task.detached {
                NetworkBlockStaging.stageAndTrigger(
                    blockTargetDomains: false,
                    blockClaudeUpdates: currentCfg.blockClaudeAutoUpdates,
                    enabledTargets: enabledTargets,
                    paths: self.paths,
                    waitForApply: true
                )
            }.value
            lastAppliedDomainsBlocked = false

            let postUnblockTraces = await traceProber.probeTargets(
                enabledTargets,
                customProxyURL: customProxy,
                timeout: 3.0
            )
            if !postUnblockTraces.isEmpty {
                eval = AdmissionEvaluator.evaluate(
                    input: .init(
                        config: currentCfg,
                        httpResult: httpRes,
                        stunResult: stunRes,
                        targetSnapshots: postUnblockTraces,
                        verifyTargetTraces: true
                    ),
                    stateStore: admissionStore
                )
            }
        }

        // 若配置在本轮探测中途已被用户修改，丢弃本轮旧判定并重跑
        guard currentCfg.configRevision == config.configRevision else {
            checkQueued = true
            return
        }

        let previousVerdict = state.verdict
        let newState = SharedGuardState(
            verdict: eval.verdict,
            reason: eval.reason,
            primaryIP: eval.primaryIP,
            primaryCountryCode: eval.primaryCountryCode,
            primaryColo: eval.primaryColo,
            effectiveTimeZone: eval.effectiveTimeZone,
            matchedWhitelistLabel: eval.matchedWhitelistLabel,
            jumpLatched: eval.jumpLatched,
            jumpBeforeIP: eval.jumpBeforeIP,
            jumpAfterIP: eval.jumpAfterIP,
            httpSnapshot: eval.httpSnapshot,
            stunSnapshot: eval.stunSnapshot,
            targetSnapshots: eval.targetSnapshots,
            proxyEnvironment: proxyEnv,
            configRevision: currentCfg.configRevision,
            exitCheckMode: currentCfg.exitCheckMode,
            pollIntervalSeconds: currentCfg.clampedPollInterval,
            helperInstalled: helperReady,
            updatedAt: Date()
        )
        state = newState
        try? sharedStateStore.write(newState)

        if previousVerdict != eval.verdict {
            if eval.jumpLatched {
                eventLogger.append(
                    .ipJumpLatched,
                    message: eval.reason,
                    detectedIP: eval.primaryIP
                )
            } else {
                eventLogger.append(
                    .verdictChanged,
                    message: "\(eval.verdict.title) — \(eval.reason)",
                    detectedIP: eval.primaryIP
                )
            }
            refreshEvents()
        }

        // 仅在已完成初始向导后执行真实的封网与强杀动作（避免首次打开应用还没配白名单就误杀正在运行的会话）
        if currentCfg.onboardingCompleted {
            await enforceSystemState(for: newState, config: currentCfg, helperReady: helperReady)
        }
    }

    private func enforceSystemState(
        for currentState: SharedGuardState,
        config: GuardConfig,
        helperReady: Bool
    ) async {
        let wantDomainsBlocked = currentState.verdict.shouldBlockDomains
        let wantUpdatesBlocked = config.protectionEnabled && config.blockClaudeAutoUpdates

        if helperReady {
            let drifted = NetworkBlockStaging.hasHostsDrifted(
                expectedDomainsBlocked: wantDomainsBlocked,
                expectedUpdatesBlocked: wantUpdatesBlocked
            )
            if drifted {
                lastAppliedDomainsBlocked = nil
                lastAppliedUpdatesBlocked = nil
            }
            if lastAppliedDomainsBlocked != wantDomainsBlocked || lastAppliedUpdatesBlocked != wantUpdatesBlocked {
                let targetsSnapshot = config.enabledTargets
                let pathsCopy = paths
                let applied = await Task.detached {
                    NetworkBlockStaging.stageAndTrigger(
                        blockTargetDomains: wantDomainsBlocked,
                        blockClaudeUpdates: wantUpdatesBlocked,
                        enabledTargets: targetsSnapshot,
                        paths: pathsCopy,
                        waitForApply: false
                    )
                }.value
                if applied {
                    lastAppliedDomainsBlocked = wantDomainsBlocked
                    lastAppliedUpdatesBlocked = wantUpdatesBlocked
                }
            }
        }

        if lastAppliedUpdatesBlocked != wantUpdatesBlocked {
            Task.detached {
                UpdateFreezeManager.apply(freeze: wantUpdatesBlocked)
            }
            lastAppliedUpdatesBlocked = wantUpdatesBlocked
        }

        if currentState.verdict.shouldTerminateRunningApps {
            let killedTargets = ProcessEnforcer.terminateRunningGuardedApps(enabledTargets: config.enabledTargets)
            if !killedTargets.isEmpty {
                let names = killedTargets.joined(separator: "、")
                eventLogger.append(
                    .runningAppTerminated,
                    message: "出口偏离白名单，已紧急关闭运行中的 \(names)：\(currentState.reason)",
                    detectedIP: currentState.primaryIP,
                    targetName: names
                )
                refreshEvents()
                if config.showInterceptAlert && !hasAlertedCurrentBlockEpisode {
                    hasAlertedCurrentBlockEpisode = true
                    InterceptAlertPresenter.present(
                        .runningAppsClosed(names: killedTargets.map(VerdictPresenter.shortName)),
                        state: currentState,
                        coordinator: self
                    )
                }
            }
        } else {
            hasAlertedCurrentBlockEpisode = false
        }
    }

    private func collectFreshObservedChannels() async -> [String: String] {
        let customProxy = config.useCustomHTTPProxy ? config.customHTTPProxyURL : nil
        async let h = HTTPExitProber().probe(customProxyURL: customProxy, timeout: 2.5)
        async let s = STUNProber().probe(timeout: 1.5)
        let (hr, sr) = await (h, s)
        var map: [String: String] = [:]
        if config.exitCheckMode.includesHTTP, let ip = hr.ip { map["http"] = ip }
        if config.exitCheckMode.includesSTUN, let ip = sr.ip { map["stun"] = ip }
        return map
    }

    // MARK: - 系统级监听（Dock 启动毫秒级拦截 + 网络切换 + 休眠唤醒）

    private func setupAppLaunchInterceptor() {
        workspaceTerminateObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didTerminateApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else {
                return
            }
            let deadPID = app.processIdentifier
            MainActor.assumeIsolated {
                _ = self?.tzAlignedPIDs.remove(deadPID)
            }
        }

        workspaceLaunchObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didLaunchApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else {
                return
            }
            MainActor.assumeIsolated {
                guard let self else { return }
                guard self.config.onboardingCompleted && self.config.protectionEnabled else { return }
                guard let matched = ProcessEnforcer.matchedTarget(for: app, in: self.config.enabledTargets) else {
                    return
                }

                // 1. 若出口未通过检查：立即强杀阻止启动
                if self.state.verdict.shouldBlockFreshLaunch {
                    ProcessEnforcer.forceTerminateApp(app, target: matched)
                    self.eventLogger.append(
                        .appLaunchIntercepted,
                        message: "拦截 Dock 启动 \(matched.name)：\(self.state.reason)",
                        detectedIP: self.state.primaryIP,
                        targetName: matched.name
                    )
                    self.refreshEvents()

                    if self.config.showInterceptAlert {
                        InterceptAlertPresenter.present(
                            .launchBlocked(appName: VerdictPresenter.shortName(matched.name)),
                            state: self.state,
                            coordinator: self
                        )
                    }
                    return
                }

                // 2. 出口已放行 (.allowed)：若开启了 Dock 自动注入时区，将未带对齐时区的顶层应用无缝重拉起
                guard self.config.relaunchDockAppsWithTimezone,
                      app.activationPolicy == .regular,
                      let bundleURL = app.bundleURL,
                      !bundleURL.path.contains("/Contents/"),
                      let targetTZ = self.state.effectiveTimeZone,
                      targetTZ != TimezoneAlignmentResolver.realMachineSystemTimeZoneIdentifier() else {
                    return
                }

                let pid = app.processIdentifier
                if self.tzAlignedPIDs.contains(pid) {
                    return
                }
                if let until = self.pendingTZRelaunchUntil[matched.id], until > Date() {
                    self.tzAlignedPIDs.insert(pid)
                    self.pendingTZRelaunchUntil.removeValue(forKey: matched.id)
                    return
                }

                // 判定为从 Dock / Finder 裸启动：先登记防重入窗口，关闭裸进程，待 SingletonLock 释放后注入 TZ 重拉起
                self.pendingTZRelaunchUntil[matched.id] = Date().addingTimeInterval(8.0)
                _ = app.forceTerminate()

                Task { @MainActor [weak self] in
                    for _ in 0..<35 {
                        if app.isTerminated { break }
                        try? await Task.sleep(for: .milliseconds(40))
                    }
                    try? await Task.sleep(for: .milliseconds(80))
                    guard let self else { return }
                    _ = ProcessEnforcer.launchTargetWithEnvironment(
                        matched,
                        bundleURL: bundleURL,
                        timeZoneIdentifier: targetTZ,
                        createNewInstance: true
                    )
                    self.eventLogger.append(
                        .timezoneAlignedLaunch,
                        message: "检测到从 Dock 启动 \(matched.name)，已自动注入对齐时区 \(targetTZ)",
                        detectedIP: self.state.primaryIP,
                        targetName: matched.name
                    )
                    self.refreshEvents()
                    self.setBanner("已自动为 \(matched.name) 注入时区 \(targetTZ)", isError: false)
                }
            }
        }
    }

    private func setupConnectivityObservers() {
        // 1. NWPathMonitor 捕获 Wi-Fi / 物理网络通断
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            let delay: Double = (path.status == .satisfied) ? 0.35 : 0.05
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: .seconds(delay))
                self?.triggerRecheck()
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.claudeguard.nwpath"))
        self.pathMonitor = monitor

        // 2. SCDynamicStore 实时捕获 V2rayN 系统代理开关与 utun 路由表变更（~0.3s 响应）
        var ctx = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info else { return }
            let coord = Unmanaged<GuardCoordinator>.fromOpaque(info).takeUnretainedValue()
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(300))
                coord.triggerRecheck()
            }
        }
        if let store = SCDynamicStoreCreate(kCFAllocatorDefault, "com.claudeguard.netstore" as CFString, callback, &ctx) {
            let patterns = [
                "State:/Network/Global/IPv4",
                "State:/Network/Global/IPv6",
                "State:/Network/Global/Proxies",
                "State:/Network/Interface/.*",
                "State:/Network/Service/.*"
            ] as CFArray
            SCDynamicStoreSetNotificationKeys(store, nil, patterns)
            if let rlSrc = SCDynamicStoreCreateRunLoopSource(kCFAllocatorDefault, store, 0) {
                CFRunLoopAddSource(CFRunLoopGetMain(), rlSrc, .commonModes)
            }
            self.dynamicStore = store
        }

        // 3. 合盖休眠唤醒后阶梯重检（防止隔夜休眠唤醒停留在旧状态）
        workspaceWakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            for delay in [0.5, 3.0, 7.0] {
                Task { @MainActor [weak self] in
                    try? await Task.sleep(for: .seconds(delay))
                    self?.triggerRecheck()
                }
            }
        }
    }

    private func reschedulePollTimer() {
        pollTimer?.invalidate()
        let interval = config.clampedPollInterval
        pollTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, !self.checkInFlight else { return }
                self.triggerRecheck()
            }
        }
    }

    private func scheduleIntegritySelfHeal() {
        cliStatus = CLIHookManager.syncHooks(
            protectCLI: config.protectClaudeCLI,
            configuredRealCLI: config.realClaudeCLIPath,
            paths: paths
        )
        integrityTimer?.invalidate()
        integrityTimer = Timer.scheduledTimer(withTimeInterval: 60.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.cliStatus = CLIHookManager.syncHooks(
                    protectCLI: self.config.protectClaudeCLI,
                    configuredRealCLI: self.config.realClaudeCLIPath,
                    paths: self.paths
                )
            }
        }
    }
}
