import XCTest
@testable import ClaudeGuardCore

final class ClaudeGuardCoreTests: XCTestCase {
    // MARK: - 1. CIDRMatcher 测试（IPv4 / IPv6 / CIDR / 备注命中）

    func testIPv4AndIPv6CIDRMatching() {
        XCTAssertTrue(CIDRMatcher.isValidLiteralIP("203.0.113.42"))
        XCTAssertTrue(CIDRMatcher.isValidLiteralIP("2607:6bc0::10"))
        XCTAssertFalse(CIDRMatcher.isValidLiteralIP("203.0.113.0/24"))
        XCTAssertFalse(CIDRMatcher.isValidLiteralIP("999.1.1.1"))
        XCTAssertFalse(CIDRMatcher.isValidIPOrCIDR("203.0.113.0/33"))
        XCTAssertFalse(CIDRMatcher.isValidIPOrCIDR("2607:6bc0::/129"))

        XCTAssertTrue(CIDRMatcher.matches(ip: "160.79.104.10", rule: "160.79.104.0/24"))
        XCTAssertTrue(CIDRMatcher.matches(ip: "160.79.104.255", rule: "160.79.104.0/24"))
        XCTAssertFalse(CIDRMatcher.matches(ip: "160.79.105.1", rule: "160.79.104.0/24"))

        XCTAssertTrue(CIDRMatcher.matches(ip: "2607:6bc0:abcd::1", rule: "2607:6bc0::/32"))
        XCTAssertFalse(CIDRMatcher.matches(ip: "2607:6bc1::1", rule: "2607:6bc0::/32"))

        let entries = [
            AllowedIPEntry(cidrOrIP: "198.51.100.10", label: "停用节点", isEnabled: false),
            AllowedIPEntry(cidrOrIP: "203.0.113.0/24", label: "洛杉矶主力", isEnabled: true)
        ]
        XCTAssertNil(CIDRMatcher.firstMatchingEntry(for: "198.51.100.10", in: entries))
        XCTAssertEqual(CIDRMatcher.firstMatchingEntry(for: "203.0.113.88", in: entries)?.label, "洛杉矶主力")
    }

    // MARK: - 2. Trace 与 STUN 报文编解码测试

    func testCloudflareTraceAndHTTPParsing() {
        let sampleTrace = """
        fl=29f12
        h=claude.ai
        ip=203.0.113.77
        ts=1730000000.123
        visit_scheme=https
        loc=US
        colo=LAX
        """
        let parsed = TargetTraceProber.parseTraceBody(sampleTrace)
        XCTAssertEqual(parsed.ip, "203.0.113.77")
        XCTAssertEqual(parsed.countryCode, "US")
        XCTAssertEqual(parsed.colo, "LAX")

        let jsonPayload = Data("{\"ip\":\"198.51.100.9\",\"country\":\"JP\"}".utf8)
        let httpParsed = HTTPExitProber.parseResponse(jsonPayload)
        XCTAssertEqual(httpParsed?.ip, "198.51.100.9")
        XCTAssertEqual(httpParsed?.countryCode, "JP")
    }

    func testSTUNXORMappedIPv4AndIPv6Decoding() {
        let txID: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        // 构造模拟 203.0.113.5 的 XOR-MAPPED-ADDRESS (0x0020)
        let targetIP: [UInt8] = [203, 0, 113, 5]
        let xoredIP = zip(targetIP, STUNProber.magicCookie).map { $0 ^ $1 }

        var packet: [UInt8] = [
            0x01, 0x01,             // Binding Success Response
            0x00, 0x0C              // Message Length = 12 bytes
        ]
        packet.append(contentsOf: STUNProber.magicCookie)
        packet.append(contentsOf: txID)
        packet.append(contentsOf: [
            0x00, 0x20,             // XOR-MAPPED-ADDRESS
            0x00, 0x08,             // Attr Length = 8
            0x00, 0x01,             // Reserved + Family IPv4 (0x01)
            0x12, 0x34              // X-Port
        ])
        packet.append(contentsOf: xoredIP)

        XCTAssertEqual(STUNProber.parseBindingResponse(packet, expectedTransactionID: txID), "203.0.113.5")
        // Transaction ID 不匹配时必须拒绝
        var wrongTx = txID
        wrongTx[0] = 99
        XCTAssertNil(STUNProber.parseBindingResponse(packet, expectedTransactionID: wrongTx))
    }

    // MARK: - 3. 准入策略状态机：空规则拒止、跳变锁持久化、分流泄漏锁

    func testAdmissionEvaluatorEmptyWhitelistFailsClosed() throws {
        let sandbox = FileManager.default.temporaryDirectory.appendingPathComponent("cg-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: sandbox) }
        let paths = GuardPaths(appSupportDir: sandbox)
        let store = AdmissionStateStore(paths: paths)

        let emptyConfig = GuardConfig(protectionEnabled: true, allowedIPs: [], allowedRegions: [])
        let out = AdmissionEvaluator.evaluate(
            input: .init(
                config: emptyConfig,
                httpResult: .init(ip: "203.0.113.10", countryCode: "US", latencyMs: 100),
                stunResult: .init(ip: "203.0.113.10", latencyMs: 50),
                targetSnapshots: [],
                verifyTargetTraces: false
            ),
            stateStore: store
        )
        XCTAssertEqual(out.verdict, .blocked)
    }

    func testStickyIPJumpLatchAndAcknowledge() throws {
        let sandbox = FileManager.default.temporaryDirectory.appendingPathComponent("cg-jump-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: sandbox) }
        let paths = GuardPaths(appSupportDir: sandbox)
        let store = AdmissionStateStore(paths: paths)

        let cfg = GuardConfig(
            protectionEnabled: true,
            exitCheckMode: .all,
            admissionRuleMode: .ipOnly,
            allowedIPs: [
                AllowedIPEntry(cidrOrIP: "203.0.113.10", label: "节点 A"),
                AllowedIPEntry(cidrOrIP: "203.0.113.20", label: "节点 B")
            ],
            detectIPChange: true
        )

        // 第一次：建立基准 203.0.113.10 -> allowed
        let first = AdmissionEvaluator.evaluate(
            input: .init(
                config: cfg,
                httpResult: .init(ip: "203.0.113.10", countryCode: "US", latencyMs: 80),
                stunResult: .init(ip: "203.0.113.10", latencyMs: 40),
                targetSnapshots: [],
                verifyTargetTraces: false
            ),
            stateStore: store
        )
        XCTAssertEqual(first.verdict, .allowed)
        XCTAssertEqual(first.matchedWhitelistLabel, "节点 A")

        // 第二次：即使切到同样在白名单里的 203.0.113.20，开启跳变锁后也必须持久化拦截！
        let jumped = AdmissionEvaluator.evaluate(
            input: .init(
                config: cfg,
                httpResult: .init(ip: "203.0.113.20", countryCode: "US", latencyMs: 90),
                stunResult: .init(ip: "203.0.113.20", latencyMs: 45),
                targetSnapshots: [],
                verifyTargetTraces: false
            ),
            stateStore: store
        )
        XCTAssertEqual(jumped.verdict, .blocked)
        XCTAssertTrue(jumped.jumpLatched)
        XCTAssertEqual(jumped.jumpBeforeIP, "203.0.113.10")
        XCTAssertEqual(jumped.jumpAfterIP, "203.0.113.20")

        // 第三次：哪怕切回原 IP 203.0.113.10，未人工确认前依然保持锁死
        let switchedBack = AdmissionEvaluator.evaluate(
            input: .init(
                config: cfg,
                httpResult: .init(ip: "203.0.113.10", countryCode: "US", latencyMs: 85),
                stunResult: .init(ip: "203.0.113.10", latencyMs: 40),
                targetSnapshots: [],
                verifyTargetTraces: false
            ),
            stateStore: store
        )
        XCTAssertEqual(switchedBack.verdict, .blocked)
        XCTAssertTrue(switchedBack.jumpLatched)

        // 第四次：用户点击「信任当前新出口」确认 203.0.113.20 -> 立即恢复 allowed
        AdmissionEvaluator.acknowledgeCurrentExits(
            observedChannels: ["http": "203.0.113.20", "stun": "203.0.113.20"],
            stateStore: store
        )
        let afterAck = AdmissionEvaluator.evaluate(
            input: .init(
                config: cfg,
                httpResult: .init(ip: "203.0.113.20", countryCode: "US", latencyMs: 88),
                stunResult: .init(ip: "203.0.113.20", latencyMs: 42),
                targetSnapshots: [],
                verifyTargetTraces: false
            ),
            stateStore: store
        )
        XCTAssertEqual(afterAck.verdict, .allowed)
        XCTAssertFalse(afterAck.jumpLatched)
    }

    func testSplitTunnelTargetLeakLatchesImmediately() throws {
        let sandbox = FileManager.default.temporaryDirectory.appendingPathComponent("cg-leak-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: sandbox) }
        let store = AdmissionStateStore(paths: GuardPaths(appSupportDir: sandbox))

        let cfg = GuardConfig(
            protectionEnabled: true,
            exitCheckMode: .all,
            admissionRuleMode: .ipOnly,
            allowedIPs: [AllowedIPEntry(cidrOrIP: "203.0.113.10", label: "美西节点")]
        )

        // 通用 HTTP/STUN 走了代理 203.0.113.10，但 claude.ai/cdn-cgi/trace 漏了直连 114.114.114.114
        let leakEval = AdmissionEvaluator.evaluate(
            input: .init(
                config: cfg,
                httpResult: .init(ip: "203.0.113.10", countryCode: "US", latencyMs: 110),
                stunResult: .init(ip: "203.0.113.10", latencyMs: 60),
                targetSnapshots: [
                    TargetProbeSnapshot(
                        id: "claude",
                        targetName: "Claude",
                        ip: "114.114.114.114",
                        countryCode: "CN",
                        latencyMs: 35
                    )
                ],
                verifyTargetTraces: true
            ),
            stateStore: store
        )
        XCTAssertEqual(leakEval.verdict, .blocked)
        XCTAssertTrue(leakEval.routeLeakDetectedNow)
    }

    // MARK: - 4. Hosts 与 PF 暂存规则生成测试

    func testStagedHostsAndPFGeneration() {
        let targets = [GuardedTarget.claudePreset, GuardedTarget.chatgptPreset]
        let hosts = NetworkBlockStaging.buildStagedHostsBlock(
            blockTargetDomains: true,
            blockClaudeUpdates: true,
            enabledTargets: targets
        )
        XCTAssertTrue(hosts.contains(NetworkBlockStaging.blockBeginMarker))
        XCTAssertTrue(hosts.contains("0.0.0.0\tclaude.ai"))
        XCTAssertTrue(hosts.contains("0.0.0.0\tchatgpt.com"))
        XCTAssertTrue(hosts.contains(NetworkBlockStaging.updateBeginMarker))
        XCTAssertFalse(hosts.contains("localhost"))

        let pf = NetworkBlockStaging.buildStagedPFEntries(
            blockTargetDomains: true,
            enabledTargets: targets
        )
        // PF 表只包含 Anthropic 专属 CIDR，绝不误纳入 ChatGPT 的共享 Cloudflare CDN IP
        XCTAssertTrue(pf.contains("160.79.104.0/23"))
        XCTAssertTrue(pf.contains("2607:6bc0::/48"))

        let emptyPF = NetworkBlockStaging.buildStagedPFEntries(
            blockTargetDomains: false,
            enabledTargets: targets
        )
        XCTAssertEqual(emptyPF, "")
    }

    // MARK: - 5. 进程级智能时区推导测试

    func testTimezoneAlignmentResolver() {
        // 单时区国家严格以 loc 国家码为准（哪怕邻近 CDN 落到东京 NRT，KR 仍应返回 Asia/Seoul）
        XCTAssertEqual(
            TimezoneAlignmentResolver.resolve(mode: .autoFromExit, manualTimeZone: "", countryCode: "KR", colo: "NRT"),
            "Asia/Seoul"
        )
        // 多时区大国按 Cloudflare 边缘机房精确区分东西海岸与中部
        XCTAssertEqual(
            TimezoneAlignmentResolver.resolve(mode: .autoFromExit, manualTimeZone: "", countryCode: "US", colo: "LAX"),
            "America/Los_Angeles"
        )
        XCTAssertEqual(
            TimezoneAlignmentResolver.resolve(mode: .autoFromExit, manualTimeZone: "", countryCode: "US", colo: "EWR"),
            "America/New_York"
        )
        XCTAssertEqual(
            TimezoneAlignmentResolver.resolve(mode: .autoFromExit, manualTimeZone: "", countryCode: "US", colo: "ORD"),
            "America/Chicago"
        )
        // 手动模式校验合法与非法 IANA 时区
        XCTAssertEqual(
            TimezoneAlignmentResolver.resolve(mode: .manual, manualTimeZone: "Asia/Tokyo", countryCode: "US", colo: "LAX"),
            "Asia/Tokyo"
        )
        XCTAssertNil(
            TimezoneAlignmentResolver.resolve(mode: .manual, manualTimeZone: "Invalid/Zone_123", countryCode: "US", colo: "LAX")
        )
        // 关闭模式返回 nil
        XCTAssertNil(
            TimezoneAlignmentResolver.resolve(mode: .disabled, manualTimeZone: "Asia/Seoul", countryCode: "KR", colo: "ICN")
        )
        XCTAssertFalse(TimezoneAlignmentResolver.realMachineSystemTimeZoneIdentifier().isEmpty)
    }
    // MARK: - 6. 进程匹配边界与内置预设刷新

    func testClaudePresetKeywordsDoNotMatchUnrelatedPaths() {
        let kws = GuardedTarget.claudePreset.processPathKeywords
        let unrelated = "/Users/dev/projects/claude-code/build/tool"
        XCTAssertFalse(kws.contains { unrelated.contains($0) })
        let embedded = "/Users/dev/Library/Application Support/Claude/claude-code/2.1.0/claude.app/Contents/MacOS/claude"
        XCTAssertTrue(kws.contains { embedded.contains($0) })
    }

    func testPFEntriesUseOfficialInboundRanges() {
        let entries = NetworkBlockStaging.buildStagedPFEntries(
            blockTargetDomains: true,
            enabledTargets: [GuardedTarget.claudePreset]
        )
        XCTAssertTrue(entries.contains("160.79.104.0/23"))
        XCTAssertTrue(entries.contains("153.61.224.0/22"))
        XCTAssertTrue(entries.contains("2607:6bc0::/48"))
        XCTAssertFalse(entries.contains("160.79.104.0/24"))
    }

    func testLoadRefreshesBuiltInPresetsButKeepsEnabledFlag() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("cg-test-\(UUID().uuidString)")
        let paths = GuardPaths(appSupportDir: tmp)
        let store = ConfigStore(paths: paths)
        var cfg = GuardConfig()
        if let i = cfg.targets.firstIndex(where: { $0.id == "chatgpt" }) { cfg.targets[i].isEnabled = true }
        if let i = cfg.targets.firstIndex(where: { $0.id == "claude" }) {
            cfg.targets[i].processPathKeywords = ["/claude-code/"]
            cfg.targets[i].dedicatedPFCIDRs = ["160.79.104.0/24"]
        }
        try store.save(cfg)
        let loaded = store.load()
        let claude = try XCTUnwrap(loaded.targets.first { $0.id == "claude" })
        XCTAssertFalse(claude.processPathKeywords.contains("/claude-code/"))
        XCTAssertTrue(claude.dedicatedPFCIDRs.contains("160.79.104.0/23"))
        XCTAssertTrue(try XCTUnwrap(loaded.targets.first { $0.id == "chatgpt" }).isEnabled)
    }

    // MARK: - 7. 时区对齐总开关

    func testTimezoneAlignmentToggleDefaultsOnAndMigratesLegacyDisabled() throws {
        XCTAssertTrue(GuardConfig().timezoneAlignmentEnabled)
        XCTAssertEqual(GuardConfig().effectiveTimezoneAlignmentMode, .autoFromExit)

        var off = GuardConfig()
        off.timezoneAlignmentEnabled = false
        XCTAssertEqual(off.effectiveTimezoneAlignmentMode, .disabled)

        let decoder = JSONDecoder()
        let legacyOff = try decoder.decode(GuardConfig.self, from: Data(#"{"timezoneAlignmentMode":"disabled"}"#.utf8))
        XCTAssertFalse(legacyOff.timezoneAlignmentEnabled)
        let legacyManual = try decoder.decode(GuardConfig.self, from: Data(#"{"timezoneAlignmentMode":"manual"}"#.utf8))
        XCTAssertTrue(legacyManual.timezoneAlignmentEnabled)
        XCTAssertEqual(legacyManual.effectiveTimezoneAlignmentMode, .manual)
        let fresh = try decoder.decode(GuardConfig.self, from: Data("{}".utf8))
        XCTAssertTrue(fresh.timezoneAlignmentEnabled)
    }

    // MARK: - 8. 系统公网 IPv6 防泄漏策略生成测试

    func testIPv6GuardManagerPolicyAndStatus() {
        let payload = IPv6GuardManager.buildPolicyPayload(
            disablePublicIPv6: true,
            services: ["Wi-Fi", "Thunderbolt Bridge", "-evil-flag", "*Disabled"]
        )
        XCTAssertEqual(payload, "linklocal\nWi-Fi\nThunderbolt Bridge\n")

        let statusOpen = SystemIPv6Status(services: [
            NetworkServiceIPv6Item(serviceName: "Wi-Fi", mode: "Automatic"),
            NetworkServiceIPv6Item(serviceName: "Thunderbolt Bridge", mode: "Link-local")
        ])
        XCTAssertFalse(statusOpen.isPublicIPv6DisabledOnAll)

        let statusLocked = SystemIPv6Status(services: [
            NetworkServiceIPv6Item(serviceName: "Wi-Fi", mode: "Link-local"),
            NetworkServiceIPv6Item(serviceName: "Thunderbolt Bridge", mode: "Link-local")
        ])
        XCTAssertTrue(statusLocked.isPublicIPv6DisabledOnAll)

        // 实机回归用例：macOS networksetup -getinfo 在 LinkLocal 模式下省略 IPv6: 行
        let macOSLinkLocalOutput = """
        DHCP Configuration
        IP address: 192.168.0.186
        Subnet mask: 255.255.255.0
        Router: 192.168.0.1
        Client ID:
        IPv6 IP address: none
        IPv6 Router: none
        Wi-Fi ID: 80:47:15:9d:04:66
        """
        XCTAssertEqual(IPv6GuardManager.parseNetworkSetupInfo(macOSLinkLocalOutput).mode, "Link-local")

        let macOSAutoOutput = """
        DHCP Configuration
        IP address: 192.168.0.186
        IPv6: Automatic
        IPv6 IP address: none
        IPv6 Router: none
        """
        XCTAssertEqual(IPv6GuardManager.parseNetworkSetupInfo(macOSAutoOutput).mode, "Automatic")
    }
}
