import Foundation

/// 针对各 AI 客户端自身域名（如 `https://claude.ai/cdn-cgi/trace`、`https://chatgpt.com/cdn-cgi/trace`）
/// 发起真实链路出口校验，识别“通用流量走了代理、但目标域名被分流直连”的盲区。
public struct TargetTraceProber: Sendable {
    public struct TraceFields: Sendable, Equatable {
        public var ip: String?
        public var countryCode: String?
        public var colo: String?

        public init(ip: String? = nil, countryCode: String? = nil, colo: String? = nil) {
            self.ip = ip
            self.countryCode = countryCode
            self.colo = colo
        }
    }

    public init() {}

    /// 解析 Cloudflare `/cdn-cgi/trace` 文本（形如 `ip=1.2.3.4\nloc=US\ncolo=LAX`）。
    public static func parseTraceBody(_ body: String) -> TraceFields {
        var ip: String?
        var loc: String?
        var colo: String?

        for line in body.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            let val = parts[1].trimmingCharacters(in: .whitespaces)
            guard !val.isEmpty else { continue }

            switch key {
            case "ip":
                if CIDRMatcher.isValidLiteralIP(val) {
                    ip = val
                }
            case "loc":
                let upper = val.uppercased()
                if upper.count == 2 && upper != "XX" && upper != "T1" {
                    loc = upper
                }
            case "colo":
                colo = val.uppercased()
            default:
                break
            }
        }
        return TraceFields(ip: ip, countryCode: loc, colo: colo)
    }

    /// 并行探测所有已启用且配有 `traceURL` 的守护目标。
    public func probeTargets(
        _ targets: [GuardedTarget],
        customProxyURL: String? = nil,
        timeout: TimeInterval = 3.0
    ) async -> [TargetProbeSnapshot] {
        let targetsWithTrace = targets.filter { $0.isEnabled && ($0.traceURL?.isEmpty == false) }
        guard !targetsWithTrace.isEmpty else { return [] }

        let cfg = HTTPExitProber.makeSessionConfiguration(customProxyURL: customProxyURL, timeout: timeout)
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }

        return await withTaskGroup(of: (Int, TargetProbeSnapshot).self) { group in
            for (index, target) in targetsWithTrace.enumerated() {
                group.addTask {
                    let snap = await Self.probeSingle(target, session: session, timeout: timeout)
                    return (index, snap)
                }
            }

            var collected: [(Int, TargetProbeSnapshot)] = []
            for await pair in group {
                collected.append(pair)
            }
            return collected.sorted { $0.0 < $1.0 }.map(\.1)
        }
    }

    private static func probeSingle(
        _ target: GuardedTarget,
        session: URLSession,
        timeout: TimeInterval
    ) async -> TargetProbeSnapshot {
        guard let urlStr = target.traceURL, let url = URL(string: urlStr) else {
            return TargetProbeSnapshot(
                id: target.id,
                targetName: target.name,
                passed: false,
                errorDescription: "未配置探测 URL"
            )
        }

        let started = Date()
        var req = URLRequest(
            url: url,
            cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
            timeoutInterval: timeout
        )
        req.setValue("ClaudeGuard-macOS/1.0", forHTTPHeaderField: "User-Agent")

        do {
            let (data, resp) = try await session.data(for: req)
            let ms = Int(Date().timeIntervalSince(started) * 1000)
            guard let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
                return TargetProbeSnapshot(
                    id: target.id,
                    targetName: target.name,
                    passed: false,
                    latencyMs: ms,
                    errorDescription: "HTTP 状态码异常 (\(code))"
                )
            }

            if let body = String(data: data, encoding: .utf8) {
                let trace = parseTraceBody(body)
                if let ip = trace.ip {
                    return TargetProbeSnapshot(
                        id: target.id,
                        targetName: target.name,
                        ip: ip,
                        countryCode: trace.countryCode,
                        passed: false, // 由 AdmissionEvaluator 填充最终匹配结论
                        latencyMs: ms
                    )
                }
            }

            // 兼容 JSON IP 接口作为自定义目标的 traceURL
            if let parsed = HTTPExitProber.parseResponse(data) {
                return TargetProbeSnapshot(
                    id: target.id,
                    targetName: target.name,
                    ip: parsed.ip,
                    countryCode: parsed.countryCode,
                    passed: false,
                    latencyMs: ms
                )
            }

            return TargetProbeSnapshot(
                id: target.id,
                targetName: target.name,
                passed: false,
                latencyMs: ms,
                errorDescription: "响应未包含有效出口 IP"
            )
        } catch {
            let ms = Int(Date().timeIntervalSince(started) * 1000)
            return TargetProbeSnapshot(
                id: target.id,
                targetName: target.name,
                passed: false,
                latencyMs: ms,
                errorDescription: "连接目标探测接口失败"
            )
        }
    }
}
