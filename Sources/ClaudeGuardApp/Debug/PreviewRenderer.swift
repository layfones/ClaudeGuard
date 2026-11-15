#if DEBUG
import AppKit
import SwiftUI
import ClaudeGuardCore

/// 开发用：把真实的 SwiftUI 视图渲染成 PNG，便于在不启动守护的情况下检查设计。
/// 用法：`swift run ClaudeGuard --render-previews <输出目录>`
/// 使用临时数据目录，不读写真实配置，不调用 startIfNeeded()，不改动任何网络设置。
@MainActor
enum PreviewRenderer {
    static func runIfRequested() -> Bool {
        let args = ProcessInfo.processInfo.arguments
        guard let flag = args.firstIndex(of: "--render-previews") else { return false }
        let outDir = args.indices.contains(flag + 1)
            ? URL(fileURLWithPath: args[flag + 1])
            : FileManager.default.temporaryDirectory.appendingPathComponent("claudeguard-previews")
        try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

        for scenario in Scenario.allCases {
            let coordinator = makeCoordinator(for: scenario)
            let panel = StatusPopoverView(coordinator: coordinator, openSetupAction: {}, openSettingsAction: { _ in })
                .background(.regularMaterial)
            render(panel, appearance: scenario.dark ? .darkAqua : .aqua, backdrop: true,
                   to: outDir.appendingPathComponent("panel-\(scenario.rawValue).png"))
        }

        let onboarding = makeCoordinator(for: .onboarding)
        render(SetupGuideView(coordinator: onboarding).background(Color(nsColor: .windowBackgroundColor)),
               appearance: .aqua, backdrop: false, to: outDir.appendingPathComponent("onboarding.png"))

        let settings = makeCoordinator(for: .allowed)
        for tab in SettingsTab.allCases {
            let pane: AnyView
            switch tab {
            case .general: pane = AnyView(GeneralSettingsPane(coordinator: settings, openSetupAction: {}))
            case .policy: pane = AnyView(PolicySettingsPane(coordinator: settings))
            case .targets: pane = AnyView(TargetsSettingsPane(coordinator: settings))
            case .logs: pane = AnyView(LogsAndResetPane(coordinator: settings))
            }
            render(pane.frame(width: tab.paneSize.width, height: tab.paneSize.height).background(Color(nsColor: .windowBackgroundColor)),
                   appearance: .aqua, backdrop: false, to: outDir.appendingPathComponent("settings-\(tab.rawValue).png"))
        }

        print("Previews written to \(outDir.path)")
        return true
    }

    enum Scenario: String, CaseIterable {
        case allowed, v2rayNStopped = "v2rayn-stopped", udpLeakDark = "udp-leak-dark", onboarding

        var dark: Bool { self == .udpLeakDark }
    }

    private static func makeCoordinator(for scenario: Scenario) -> GuardCoordinator {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("claudeguard-preview-\(UUID().uuidString)")
        let coordinator = GuardCoordinator(paths: GuardPaths(appSupportDir: tmp, homeDirectory: tmp))
        var cfg = GuardConfig()
        cfg.onboardingCompleted = scenario != .onboarding
        cfg.protectionEnabled = true
        cfg.allowedIPs = scenario == .onboarding ? [] : [
            AllowedIPEntry(cidrOrIP: "203.0.113.0/24", label: "洛杉矶主力", isEnabled: true),
            AllowedIPEntry(cidrOrIP: "198.51.100.7", label: "东京备用", isEnabled: true),
            AllowedIPEntry(cidrOrIP: "192.0.2.44", label: "旧节点", isEnabled: false)
        ]
        coordinator.config = cfg

        let proxyIP = "203.0.113.42", realIP = "58.33.12.7"
        var s = SharedGuardState(
            verdict: .allowed,
            reason: "",
            primaryIP: proxyIP,
            primaryCountryCode: "US",
            primaryColo: "LAX",
            effectiveTimeZone: "America/Los_Angeles",
            matchedWhitelistLabel: "洛杉矶主力",
            httpSnapshot: ChannelProbeSnapshot(channel: "HTTP", ip: proxyIP, passed: true, latencyMs: 86),
            stunSnapshot: ChannelProbeSnapshot(channel: "STUN", ip: proxyIP, passed: true, latencyMs: 41),
            targetSnapshots: [TargetProbeSnapshot(id: "claude", targetName: "Claude", ip: proxyIP, countryCode: "US", colo: "LAX", passed: true, latencyMs: 112)],
            proxyEnvironment: ProxyEnvironmentSnapshot(isV2rayNInstalled: true, isV2rayNRunning: true, activeTUNInterfaces: ["utun5"]),
            helperInstalled: true
        )
        switch scenario {
        case .allowed:
            break
        case .v2rayNStopped:
            s.verdict = .blocked
            s.primaryIP = realIP
            s.primaryCountryCode = "CN"
            s.primaryColo = nil
            s.effectiveTimeZone = nil
            s.matchedWhitelistLabel = nil
            s.httpSnapshot = ChannelProbeSnapshot(channel: "HTTP", ip: realIP, passed: false, latencyMs: 58)
            s.stunSnapshot = ChannelProbeSnapshot(channel: "STUN", ip: realIP, passed: false, latencyMs: 23)
            s.targetSnapshots = []
            s.proxyEnvironment = ProxyEnvironmentSnapshot(isV2rayNInstalled: true, isV2rayNRunning: false)
        case .udpLeakDark:
            s.verdict = .blocked
            s.stunSnapshot = ChannelProbeSnapshot(channel: "STUN", ip: realIP, passed: false, latencyMs: 30)
            s.proxyEnvironment = ProxyEnvironmentSnapshot(isV2rayNInstalled: true, isV2rayNRunning: true, systemHTTPProxy: "127.0.0.1:10808")
        case .onboarding:
            s.verdict = .blocked
            s.helperInstalled = true
            s.matchedWhitelistLabel = nil
        }
        coordinator.state = s
        coordinator.recentEvents = [
            GuardEvent(kind: .appLaunchIntercepted, message: "拦截 Dock 启动 Claude：出口是本机真实 IP", detectedIP: realIP, targetName: "Claude"),
            GuardEvent(kind: .verdictChanged, message: "已放行 — 出口校验通过 · 当前节点「洛杉矶主力」", detectedIP: proxyIP)
        ]
        return coordinator
    }

    private static func render<V: View>(_ view: V, appearance: NSAppearance.Name, backdrop: Bool, to url: URL) {
        let content = view.fixedSize()
        let root = ZStack {
            if backdrop {
                LinearGradient(colors: appearance == .darkAqua
                               ? [Color(red: 0.05, green: 0.08, blue: 0.19), Color(red: 0.24, green: 0.12, blue: 0.40)]
                               : [Color(red: 0.31, green: 0.49, blue: 1.0), Color(red: 0.96, green: 0.70, blue: 0.62)],
                               startPoint: .topLeading, endPoint: .bottomTrailing)
            }
            content
                .clipShape(RoundedRectangle(cornerRadius: backdrop ? 18 : 0, style: .continuous))
                .padding(backdrop ? 24 : 0)
        }
        let host = NSHostingView(rootView: root)
        host.appearance = NSAppearance(named: appearance)
        let size = host.fittingSize
        host.frame = CGRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: CGRect(x: -20000, y: -20000, width: size.width, height: size.height),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: appearance)
        window.contentView = host
        window.orderFrontRegardless()
        host.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.4))

        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
        host.cacheDisplay(in: host.bounds, to: rep)
        if let data = rep.representation(using: .png, properties: [:]) {
            try? data.write(to: url)
        }
        window.orderOut(nil)
    }
}
#endif
