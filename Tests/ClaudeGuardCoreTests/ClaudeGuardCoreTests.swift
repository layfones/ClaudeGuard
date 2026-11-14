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
        XCTAssertTrue(pf.contains("160.79.104.0/24"))
        XCTAssertTrue(pf.contains("2607:6bc0::/32"))

        let emptyPF = NetworkBlockStaging.buildStagedPFEntries(
            blockTargetDomains: false,
            enabledTargets: targets
        )
        XCTAssertEqual(emptyPF, "")
    }
}
