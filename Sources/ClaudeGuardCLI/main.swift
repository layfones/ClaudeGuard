import Foundation
import Darwin
import ClaudeGuardCore

private final class AtomicBlockBox: @unchecked Sendable {
    private let lock = NSLock()
    private var reason: String?

    func set(_ text: String) {
        lock.lock()
        if reason == nil { reason = text }
        lock.unlock()
    }

    func get() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return reason
    }
}

private enum TerminalGuardHelper {
    static func restoreTUIState() {
        let resetSeq = "\u{001B}[?1049l\u{001B}[?1000l\u{001B}[?1002l\u{001B}[?1003l\u{001B}[?1006l\u{001B}[?2004l\u{001B}[?25h\u{001B}[0m"
        FileHandle.standardError.write(Data(resetSeq.utf8))
        let stty = Process()
        stty.executableURL = URL(fileURLWithPath: "/bin/stty")
        stty.arguments = ["sane"]
        stty.standardInput = FileHandle.standardInput
        stty.standardOutput = FileHandle.nullDevice
        stty.standardError = FileHandle.nullDevice
        try? stty.run()
        stty.waitUntilExit()
    }

    static func printBlockBanner(title: String, reason: String, ip: String?) {
        let red = "\u{001B}[31;1m"
        let yellow = "\u{001B}[33m"
        let reset = "\u{001B}[0m"
        let ipLine = ip.map { "  当前出口：\($0)\n" } ?? ""
        let text = """
        \n\(red)🛡️ \(title)\(reset)
        \(yellow)  原因：\(reason)\(reset)
        \(ipLine)  请在菜单栏打开 ClaudeGuard 检查代理连接或白名单设置。\n
        """
        FileHandle.standardError.write(Data(text.utf8))
    }
}

/// 在守护进程未运行或状态过期时，由 CLI 独立执行一次快速只读探测与策略判定（不写系统防火墙）。
private func evaluateLiveReadOnly(config: GuardConfig, paths: GuardPaths) async -> AdmissionEvaluator.EvaluationOutput {
    let customProxy = config.useCustomHTTPProxy ? config.customHTTPProxyURL : nil
    let httpProber = HTTPExitProber()
    let stunProber = STUNProber()
    let traceProber = TargetTraceProber()

    let hostsBlocked = (try? String(contentsOfFile: "/etc/hosts", encoding: .utf8))?
        .contains(NetworkBlockStaging.blockBeginMarker) ?? false

    async let httpTask: HTTPExitProber.Result? = config.exitCheckMode.includesHTTP
        ? await httpProber.probe(customProxyURL: customProxy, timeout: 2.2)
        : nil
    async let stunTask: STUNProber.Result? = config.exitCheckMode.includesSTUN
        ? await stunProber.probe(timeout: 1.5)
        : nil
    async let tracesTask: [TargetProbeSnapshot] = (!hostsBlocked)
        ? await traceProber.probeTargets(config.enabledTargets, customProxyURL: customProxy, timeout: 2.5)
        : []

    let (httpRes, stunRes, traces) = await (httpTask, stunTask, tracesTask)
    let admissionStore = AdmissionStateStore(paths: paths)
    return AdmissionEvaluator.evaluate(
        input: .init(
            config: config,
            httpResult: httpRes,
            stunResult: stunRes,
            targetSnapshots: traces,
            verifyTargetTraces: !hostsBlocked && !traces.isEmpty
        ),
        stateStore: admissionStore
    )
}

private func currentVerdictForCLI(config: GuardConfig, paths: GuardPaths) async -> (verdict: GuardVerdict, reason: String, ip: String?, timeZone: String?) {
    if !config.protectionEnabled {
        let manualOrDisabled = TimezoneAlignmentResolver.resolve(
            mode: config.effectiveTimezoneAlignmentMode,
            manualTimeZone: config.manualTimeZoneIdentifier,
            countryCode: nil,
            colo: nil
        )
        return (.paused, "防护已暂停", nil, manualOrDisabled)
    }
    if let shared = SharedStateStore(paths: paths).read(), shared.isFresh(for: config) {
        return (shared.verdict, shared.reason, shared.primaryIP, shared.effectiveTimeZone)
    }
    let live = await evaluateLiveReadOnly(config: config, paths: paths)
    return (live.verdict, live.reason, live.primaryIP, live.effectiveTimeZone)
}

private func runClaudeCLIWrapper(arguments: [String]) async -> Int32 {
    let paths = GuardPaths.live
    let config = ConfigStore(paths: paths).load()
    let logger = EventLogger(paths: paths)

    guard let realCLI = CLIHookManager.discoverRealCLI(configuredPath: config.realClaudeCLIPath) else {
        TerminalGuardHelper.printBlockBanner(
            title: "ClaudeGuard 未找到真实的 claude 命令行",
            reason: "请在 ClaudeGuard 设置窗口检查或重新安装 Claude Code CLI。",
            ip: nil
        )
        return 1
    }

    var resolvedTimeZoneForSession: String?
    if config.protectionEnabled && config.protectClaudeCLI {
        let preflight = await currentVerdictForCLI(config: config, paths: paths)
        resolvedTimeZoneForSession = preflight.timeZone
        if preflight.verdict.shouldBlockFreshLaunch {
            logger.append(
                .cliSessionBlocked,
                message: "已阻止启动 claude CLI：\(preflight.reason)",
                detectedIP: preflight.ip,
                targetName: "claude CLI"
            )
            TerminalGuardHelper.printBlockBanner(
                title: "ClaudeGuard 已阻止启动 Claude Code",
                reason: preflight.reason,
                ip: preflight.ip
            )
            return 1
        }
    } else if config.effectiveTimezoneAlignmentMode != .disabled {
        let check = await currentVerdictForCLI(config: config, paths: paths)
        resolvedTimeZoneForSession = check.timeZone
    }

    let child = Process()
    child.executableURL = URL(fileURLWithPath: realCLI)
    child.arguments = arguments

    var env = ProcessInfo.processInfo.environment
    if let tz = resolvedTimeZoneForSession, !tz.isEmpty {
        env["TZ"] = tz
    }
    if config.blockClaudeAutoUpdates {
        env["DISABLE_AUTO_UPDATE"] = "1"
        env["CLAUDE_DISABLE_AUTO_UPDATE"] = "1"
    }
    if config.useCustomHTTPProxy && !config.customHTTPProxyURL.isEmpty {
        let p = config.customHTTPProxyURL
        env["HTTP_PROXY"] = p
        env["HTTPS_PROXY"] = p
        env["ALL_PROXY"] = p
        env["http_proxy"] = p
        env["https_proxy"] = p
        env["all_proxy"] = p
        env["NO_PROXY"] = ""
        env["no_proxy"] = ""
    }
    child.environment = env
    child.standardInput = FileHandle.standardInput
    child.standardOutput = FileHandle.standardOutput
    child.standardError = FileHandle.standardError

    do {
        try child.run()
    } catch {
        FileHandle.standardError.write(Data("ClaudeGuard: 启动 \(realCLI) 失败：\(error.localizedDescription)\n".utf8))
        return 1
    }

    let blockBox = AtomicBlockBox()
    let monitorQueue = DispatchQueue(label: "com.claudeguard.cli.monitor")
    let timer = DispatchSource.makeTimerSource(queue: monitorQueue)
    let interval = config.clampedPollInterval
    timer.schedule(deadline: .now() + interval, repeating: interval)
    timer.setEventHandler {
        Task {
            let latestCfg = ConfigStore(paths: paths).load()
            guard latestCfg.protectionEnabled && latestCfg.protectClaudeCLI else { return }
            let check = await currentVerdictForCLI(config: latestCfg, paths: paths)
            // 仅在明确违例 (.blocked) 时强杀正在运行的 CLI 会话；瞬时断网 (.offline) 不误杀
            if check.verdict == .blocked && child.isRunning {
                blockBox.set(check.reason)
                logger.append(
                    .cliSessionBlocked,
                    message: "运行中出口异常，已终止 claude CLI 会话：\(check.reason)",
                    detectedIP: check.ip,
                    targetName: "claude CLI"
                )
                let pid = child.processIdentifier
                _ = kill(pid, SIGTERM)
                for _ in 0..<10 {
                    if !child.isRunning { break }
                    usleep(100_000)
                }
                if child.isRunning {
                    _ = kill(pid, SIGKILL)
                }
            }
        }
    }
    timer.resume()

    child.waitUntilExit()
    timer.cancel()

    if let reason = blockBox.get() {
        TerminalGuardHelper.restoreTUIState()
        TerminalGuardHelper.printBlockBanner(
            title: "出口偏离白名单，ClaudeGuard 已紧急切断会话",
            reason: reason,
            ip: nil
        )
        return 130
    }

    return child.terminationStatus
}

private func runManagementCommand(arguments: [String]) async -> Int32 {
    let sub = arguments.first ?? "status"
    let paths = GuardPaths.live
    let configStore = ConfigStore(paths: paths)
    let config = configStore.load()

    switch sub {
    case "status":
        let forceDryRun = arguments.contains("--dry-run")
        let asJSON = arguments.contains("--json")
        let proxyEnv = ProxyEnvironmentDetector.inspect()

        if !forceDryRun, let shared = SharedStateStore(paths: paths).read(), shared.isFresh(for: config) {
            if asJSON, let data = try? JSONEncoder().encode(shared), let txt = String(data: data, encoding: .utf8) {
                print(txt)
                return shared.verdict == .allowed ? 0 : 2
            }
            print("状态：\(shared.verdict.title)（来自守护进程实时缓存）")
            print("说明：\(shared.reason)")
            print("主出口 IP：\(shared.primaryIP ?? "未获取")  地区：\(shared.primaryCountryCode ?? "-")")
            print("代理环境：\(shared.proxyEnvironment.summaryBadge)")
            return shared.verdict == .allowed ? 0 : 2
        }

        // 只读实时探测（含目标真实链路，不修改任何系统网络设置）
        let customProxy = config.useCustomHTTPProxy ? config.customHTTPProxyURL : nil
        async let httpRes = HTTPExitProber().probe(customProxyURL: customProxy, timeout: 2.5)
        async let stunRes = STUNProber().probe(timeout: 1.8)
        async let targetSnaps = TargetTraceProber().probeTargets(
            GuardedTarget.defaultTargets.map { var t = $0; t.isEnabled = ($0.id == "claude" || $0.id == "chatgpt"); return t },
            customProxyURL: customProxy,
            timeout: 3.0
        )
        let (h, s, traces) = await (httpRes, stunRes, targetSnaps)
        let eval = AdmissionEvaluator.evaluate(
            input: .init(
                config: config,
                httpResult: h,
                stunResult: s,
                targetSnapshots: traces,
                verifyTargetTraces: !traces.isEmpty
            ),
            stateStore: AdmissionStateStore(paths: paths)
        )

        if asJSON {
            let payload: [String: Any] = [
                "verdict": eval.verdict.rawValue,
                "reason": eval.reason,
                "http_ip": h.ip as Any,
                "http_country": h.countryCode as Any,
                "http_colo": h.colo as Any,
                "http_latency_ms": h.latencyMs as Any,
                "stun_ip": s.ip as Any,
                "stun_latency_ms": s.latencyMs as Any,
                "system_timezone": TimezoneAlignmentResolver.realMachineSystemTimeZoneIdentifier(),
                "effective_timezone": eval.effectiveTimeZone as Any,
                "proxy_env": proxyEnv.summaryBadge,
                "v2rayn_installed": proxyEnv.isV2rayNInstalled,
                "v2rayn_running": proxyEnv.isV2rayNRunning,
                "targets": traces.map { [
                    "id": $0.id,
                    "name": $0.targetName,
                    "ip": $0.ip as Any,
                    "country": $0.countryCode as Any,
                    "colo": $0.colo as Any,
                    "latency_ms": $0.latencyMs as Any,
                    "error": $0.errorDescription as Any
                ] }
            ]
            if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]),
               let txt = String(data: data, encoding: .utf8) {
                print(txt)
            }
            return eval.verdict == .allowed ? 0 : 2
        }

        print("🛡️ ClaudeGuard 状态检查（只读探测）")
        print("────────────────────────────────────────")
        print("当前判定：\(eval.verdict.title)")
        print("判定原因：\(eval.reason)")
        print("代理环境：\(proxyEnv.summaryBadge)")
        let tzDesc = eval.effectiveTimeZone.map { TimezoneAlignmentResolver.formatDisplaySummary(for: $0) } ?? "未开启（保持系统时区）"
        print("时区对齐：\(tzDesc) [本机系统：\(TimezoneAlignmentResolver.realMachineSystemTimeZoneIdentifier())]")
        print("HTTP 出口：\(h.ip ?? "未获取") \(h.countryCode.map { "(\($0))" } ?? "") \(h.latencyMs.map { "[\($0)ms]" } ?? "")")
        print("STUN 出口：\(s.ip ?? "未获取") \(s.latencyMs.map { "[\($0)ms]" } ?? "")")
        for t in traces {
            print("目标链路 [\(t.targetName)]：\(t.ip ?? "未获取") \(t.countryCode.map { "(\($0))" } ?? "") \(t.latencyMs.map { "[\($0)ms]" } ?? "") \(t.errorDescription ?? "")")
        }
        return eval.verdict == .allowed ? 0 : 2

    case "doctor":
        let helperOK = PrivilegedInstaller.isHelperInstalled(paths: paths)
        let cliReport = CLIHookManager.syncHooks(
            protectCLI: config.protectClaudeCLI,
            configuredRealCLI: config.realClaudeCLIPath,
            paths: paths
        )
        print("🩺 ClaudeGuard 自检报告")
        print("  • 特权网络助手 LaunchDaemon：\(helperOK ? "✅ 已就绪" : "⚠️ 未安装（请在图形界面一键授权安装）")")
        print("  • 独立 claude CLI 真实路径：\(cliReport.realCLIPath ?? "未安装独立 CLI")")
        print("  • 已挂载软链入口：\(cliReport.hookedLocations.isEmpty ? "无" : cliReport.hookedLocations.joined(separator: ", "))")
        for note in cliReport.notes {
            print("  • 提示：\(note)")
        }
        return 0

    case "unblock-emergency":
        PrivilegedInstaller.emergencyUnblockAll(config: config, paths: paths)
        EventLogger(paths: paths).append(.emergencyUnblocked, message: "通过命令行执行紧急网络解封")
        print("✓ 已提交紧急解封请求（/etc/hosts、pf 子锚点与自动更新目录锁均已释放）。")
        return 0

    default:
        print("""
        ClaudeGuard for macOS — 原生多 AI 客户端网络出口门禁
        日常配置与白名单管理请直接点击屏幕右上角菜单栏盾牌图标打开图形界面。

        辅助命令：
          claudeguard status [--dry-run] [--json]   查看当前出口状态或执行只读实时探测
          claudeguard doctor                        检查并修复特权助手与 CLI 软链状态
          claudeguard unblock-emergency             紧急解除所有底层域名与防火墙封锁
        """)
        return 0
    }
}

let invokedName = (CommandLine.arguments[0] as NSString).lastPathComponent
let userArgs = Array(CommandLine.arguments.dropFirst())

Task.detached {
    let code: Int32
    if invokedName == "claude" {
        code = await runClaudeCLIWrapper(arguments: userArgs)
    } else {
        code = await runManagementCommand(arguments: userArgs)
    }
    exit(code)
}

dispatchMain()
