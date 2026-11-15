import XCTest
@testable import ClaudeGuardCore

final class StatusPresentationTests: XCTestCase {
    private let proxyIP = "203.0.113.42"
    private let realIP = "58.33.12.7"

    private func config(onboarded: Bool = true) -> GuardConfig {
        var c = GuardConfig()
        c.onboardingCompleted = onboarded
        c.protectionEnabled = true
        c.exitCheckMode = .all
        c.allowedIPs = [AllowedIPEntry(cidrOrIP: "203.0.113.0/24", label: "洛杉矶主力", isEnabled: true)]
        return c
    }

    private func context(installed: Set<String> = ["claude"], ipv6Disabled: Bool = false) -> VerdictPresenter.Context {
        .init(helperInstalled: true, publicIPv6Disabled: ipv6Disabled, installedTargetIDs: installed)
    }

    private func allowedState() -> SharedGuardState {
        SharedGuardState(
            verdict: .allowed,
            reason: "ok",
            primaryIP: proxyIP,
            primaryCountryCode: "US",
            primaryColo: "LAX",
            matchedWhitelistLabel: "洛杉矶主力",
            httpSnapshot: ChannelProbeSnapshot(channel: "HTTP", ip: proxyIP, passed: true, latencyMs: 86),
            stunSnapshot: ChannelProbeSnapshot(channel: "STUN", ip: proxyIP, passed: true, latencyMs: 41),
            targetSnapshots: [TargetProbeSnapshot(id: "claude", targetName: "Claude", ip: proxyIP, countryCode: "US", colo: "LAX", passed: true, latencyMs: 112)],
            proxyEnvironment: ProxyEnvironmentSnapshot(isV2rayNInstalled: true, isV2rayNRunning: true, activeTUNInterfaces: ["utun5"]),
            helperInstalled: true
        )
    }

    // MARK: - 放行

    func testAllowedConvergesOnWhitelistedExit() {
        let route = RoutePresenter.make(state: allowedState(), config: config())
        XCTAssertEqual(route.lanes.map(\.label), ["HTTP", "claude.ai", "UDP"])
        XCTAssertTrue(route.lanes.allSatisfy { $0.state == .pass && !$0.diverges })
        XCTAssertEqual(route.exit.ip, proxyIP)
        XCTAssertEqual(route.exit.state, .pass)
        XCTAssertEqual(route.exit.metaText, "美国 · LAX")

        let verdict = VerdictPresenter.make(state: allowedState(), config: config(), context: context())
        XCTAssertEqual(verdict.tone, .pass)
        XCTAssertEqual(verdict.title, "可以放心使用")
        XCTAssertEqual(verdict.action, .launchTarget(id: "claude"))
        XCTAssertEqual(verdict.actionTitle, "打开 Claude")
        XCTAssertTrue(verdict.message.contains("洛杉矶主力"))

        let notInstalled = VerdictPresenter.make(state: allowedState(), config: config(), context: context(installed: []))
        XCTAssertNil(notInstalled.action, "未安装任何受保护应用时不显示打开按钮")
    }

    // MARK: - 忘记开 v2rayN（用户的核心场景）

    func testV2rayNStoppedShowsSealedLaneAndLaunchAction() {
        var s = allowedState()
        s.verdict = .blocked
        s.primaryIP = realIP
        s.primaryCountryCode = "CN"
        s.httpSnapshot = ChannelProbeSnapshot(channel: "HTTP", ip: realIP, passed: false, latencyMs: 58)
        s.stunSnapshot = ChannelProbeSnapshot(channel: "STUN", ip: realIP, passed: false, latencyMs: 23)
        s.targetSnapshots = []
        s.proxyEnvironment = ProxyEnvironmentSnapshot(isV2rayNInstalled: true, isV2rayNRunning: false)

        let route = RoutePresenter.make(state: s, config: config())
        XCTAssertEqual(route.lanes.map(\.state), [.fail, .sealed, .fail])
        XCTAssertEqual(route.exit.ip, realIP)
        XCTAssertEqual(route.exit.state, .fail)

        let verdict = VerdictPresenter.make(state: s, config: config(), context: context())
        XCTAssertEqual(verdict.tone, .block)
        XCTAssertEqual(verdict.title, "已拦截 Claude")
        XCTAssertEqual(verdict.action, .launchV2rayN)
        XCTAssertNotNil(verdict.hint)

        let rows = StatusDetailPresenter.make(state: s, config: config(), helperInstalled: true)
        XCTAssertEqual(rows.map(\.value), ["v2rayN 未运行", "已封锁 Claude 相关域名"])

        let beforeSetup = StatusDetailPresenter.make(state: s, config: config(onboarded: false), helperInstalled: true)
        XCTAssertFalse(beforeSetup.contains { $0.label == "网络" }, "初始设置完成前不会真正封锁，不能显示已封锁")
    }

    // MARK: - UDP 绕开代理

    func testUDPLeakDivergesToBottomLane() {
        var s = allowedState()
        s.verdict = .blocked
        s.stunSnapshot = ChannelProbeSnapshot(channel: "STUN", ip: realIP, passed: false, latencyMs: 30)

        let route = RoutePresenter.make(state: s, config: config())
        XCTAssertEqual(route.lanes.last?.label, "UDP")
        XCTAssertEqual(route.lanes.last?.diverges, true)
        XCTAssertEqual(route.lanes.last?.state, .fail)
        XCTAssertEqual(route.exit.ip, proxyIP)
        XCTAssertEqual(route.exit.state, .pass)
        XCTAssertTrue(route.accessibilitySummary.contains("UDP 直连 \(realIP)"))

        let verdict = VerdictPresenter.make(state: s, config: config(), context: context())
        XCTAssertEqual(verdict.title, "已拦截：UDP 直连")
        XCTAssertEqual(verdict.action, .openV2rayN)

        s.stunSnapshot = ChannelProbeSnapshot(channel: "STUN", ip: "2408:8207:1::1f3", passed: false)
        let v6 = VerdictPresenter.make(state: s, config: config(), context: context(ipv6Disabled: false))
        XCTAssertEqual(v6.action, .disablePublicIPv6)
    }

    func testDivergingLaneIsMovedBelowConvergingLanes() {
        var s = allowedState()
        s.verdict = .blocked
        s.httpSnapshot = ChannelProbeSnapshot(channel: "HTTP", ip: realIP, passed: false)

        let route = RoutePresenter.make(state: s, config: config())
        XCTAssertEqual(route.lanes.map(\.label), ["claude.ai", "UDP", "HTTP"])
        XCTAssertEqual(route.lanes.map(\.diverges), [false, false, true])
    }

    // MARK: - 其他状态

    func testJumpLatchedOffersTrustAction() {
        var s = allowedState()
        s.verdict = .blocked
        s.jumpLatched = true
        s.jumpBeforeIP = "203.0.113.42"
        s.jumpAfterIP = "203.0.113.77"
        let verdict = VerdictPresenter.make(state: s, config: config(), context: context())
        XCTAssertEqual(verdict.title, "出口变了")
        XCTAssertEqual(verdict.action, .trustNewExit)
        XCTAssertTrue(verdict.message.contains("203.0.113.42 → 203.0.113.77"))
    }

    func testPausedShowsIdleRouteAndResumeAction() {
        var cfg = config()
        cfg.protectionEnabled = false
        var s = allowedState()
        s.verdict = .paused
        let route = RoutePresenter.make(state: s, config: cfg)
        XCTAssertTrue(route.lanes.allSatisfy { $0.state == .idle })
        XCTAssertEqual(route.exit.state, .idle)
        XCTAssertEqual(VerdictPresenter.make(state: s, config: cfg, context: context()).action, .resumeProtection)
    }

    func testSetupIncompleteAlwaysPointsToOnboarding() {
        let verdict = VerdictPresenter.make(state: allowedState(), config: config(onboarded: false), context: context())
        XCTAssertEqual(verdict.action, .openSetup)
        let noHelper = VerdictPresenter.make(
            state: allowedState(),
            config: config(),
            context: .init(helperInstalled: false, publicIPv6Disabled: false, installedTargetIDs: [])
        )
        XCTAssertEqual(noHelper.action, .openSetup)
    }

    func testEmptyWhitelistAsksToAddExit() {
        var cfg = config()
        cfg.allowedIPs = []
        var s = allowedState()
        s.verdict = .blocked
        let verdict = VerdictPresenter.make(state: s, config: cfg, context: context())
        XCTAssertEqual(verdict.title, "还没有白名单")
        XCTAssertNil(verdict.action, "v2rayN 已运行时不再提供启动按钮，改由面板里的「加入白名单」完成")
    }

    func testTimeZoneSummaryUsesLocalizedNameAndOffset() {
        var comps = DateComponents()
        comps.year = 2026; comps.month = 1; comps.day = 15
        let winter = Calendar(identifier: .gregorian).date(from: comps)!
        let summary = StatusDetailPresenter.timeZoneSummary("America/Los_Angeles", now: winter)
        XCTAssertTrue(summary.hasSuffix("UTC−8"), summary)
        XCTAssertTrue(StatusDetailPresenter.timeZoneSummary("Asia/Kolkata", now: winter).hasSuffix("UTC+5:30"))
    }

    func testShortNameDropsParenthetical() {
        XCTAssertEqual(VerdictPresenter.shortName("Claude (Desktop + Claude Code)"), "Claude")
        XCTAssertEqual(VerdictPresenter.shortName("ChatGPT / Codex"), "ChatGPT / Codex")
    }
}
