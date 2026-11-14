import Foundation
import SystemConfiguration

/// 线程安全的单次 Continuation 包装器，确保并发竞速时绝不重复 resume。
final class OnceContinuationBox<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Never>?

    init(_ continuation: CheckedContinuation<T, Never>) {
        self.continuation = continuation
    }

    func resume(returning value: T) {
        lock.lock()
        let cont = continuation
        continuation = nil
        lock.unlock()
        cont?.resume(returning: value)
    }
}

/// 并发竞速探测通用 HTTP 出口 IP（以及 `cloudflare.com/cdn-cgi/trace` 国家码）。
public struct HTTPExitProber: Sendable {
    public struct Result: Sendable, Equatable {
        public var ip: String?
        public var countryCode: String?
        public var latencyMs: Int?
        public var errorDescription: String?

        public init(
            ip: String? = nil,
            countryCode: String? = nil,
            latencyMs: Int? = nil,
            errorDescription: String? = nil
        ) {
            self.ip = ip
            self.countryCode = countryCode
            self.latencyMs = latencyMs
            self.errorDescription = errorDescription
        }
    }

    public static let defaultEndpoints: [String] = [
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://api.ipify.org?format=json",
        "https://icanhazip.com",
        "https://ifconfig.me/ip"
    ]

    public init() {}

    /// 解析任意 HTTP IP 接口响应（支持 `cdn-cgi/trace` 键值对、JSON `{"ip": "..."}` 或纯文本 IP）。
    public static func parseResponse(_ data: Data) -> (ip: String, countryCode: String?)? {
        guard let text = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              !text.isEmpty else {
            return nil
        }

        // 1. Cloudflare trace 格式：ip=x.x.x.x \n loc=US
        if text.contains("ip=") && text.contains("\n") {
            let trace = TargetTraceProber.parseTraceBody(text)
            if let ip = trace.ip, CIDRMatcher.isValidLiteralIP(ip) {
                return (ip, trace.countryCode)
            }
        }

        // 2. JSON 格式：{"ip": "x.x.x.x"}
        if text.hasPrefix("{"),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let rawIP = (json["ip"] as? String) ?? (json["ip_addr"] as? String)
            let rawCountry = (json["country"] as? String) ?? (json["country_code"] as? String)
            if let ip = rawIP?.trimmingCharacters(in: .whitespacesAndNewlines),
               CIDRMatcher.isValidLiteralIP(ip) {
                let cc = rawCountry?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
                return (ip, cc?.count == 2 ? cc : nil)
            }
        }

        // 3. 纯文本单行 IP
        let firstLine = String(text.split(whereSeparator: \.isNewline).first ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if CIDRMatcher.isValidLiteralIP(firstLine) {
            return (firstLine, nil)
        }

        return nil
    }

    /// 构建无缓存 `URLSessionConfiguration`，可选注入用户显式指定的本地 HTTP 代理。
    public static func makeSessionConfiguration(
        customProxyURL: String?,
        timeout: TimeInterval
    ) -> URLSessionConfiguration {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        cfg.urlCache = nil
        cfg.httpCookieStorage = nil
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout

        if let proxyRaw = customProxyURL?.trimmingCharacters(in: .whitespacesAndNewlines),
           !proxyRaw.isEmpty,
           let comps = URLComponents(string: proxyRaw),
           let scheme = comps.scheme?.lowercased(),
           (scheme == "http" || scheme == "https"),
           let host = comps.host, !host.isEmpty,
           let port = comps.port, (1...65535).contains(port) {
            cfg.connectionProxyDictionary = [
                kCFNetworkProxiesHTTPEnable as String: 1,
                kCFNetworkProxiesHTTPProxy as String: host,
                kCFNetworkProxiesHTTPPort as String: port,
                kCFNetworkProxiesHTTPSEnable as String: 1,
                kCFNetworkProxiesHTTPSProxy as String: host,
                kCFNetworkProxiesHTTPSPort as String: port
            ]
        }
        return cfg
    }

    public func probe(
        customProxyURL: String? = nil,
        timeout: TimeInterval = 2.5,
        endpoints: [String] = HTTPExitProber.defaultEndpoints
    ) async -> Result {
        let started = Date()
        let cfg = Self.makeSessionConfiguration(customProxyURL: customProxyURL, timeout: timeout)
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }

        return await withTaskGroup(of: (String, String?, Int)?.self) { group in
            for endpoint in endpoints {
                guard let url = URL(string: endpoint) else { continue }
                group.addTask {
                    var req = URLRequest(
                        url: url,
                        cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                        timeoutInterval: timeout
                    )
                    req.setValue("ClaudeGuard-macOS/1.0", forHTTPHeaderField: "User-Agent")
                    do {
                        let reqStart = Date()
                        let (data, resp) = try await session.data(for: req)
                        guard let http = resp as? HTTPURLResponse,
                              (200...299).contains(http.statusCode),
                              let parsed = Self.parseResponse(data) else {
                            return nil
                        }
                        let ms = Int(Date().timeIntervalSince(reqStart) * 1000)
                        return (parsed.ip, parsed.countryCode, ms)
                    } catch {
                        return nil
                    }
                }
            }

            var bestFallback: (String, String?, Int)?
            while let next = await group.next() {
                if let hit = next {
                    // 若拿到带国家码的结果直接返回，否则先暂存首个 IP，若已有结果也可立即胜出
                    if hit.1 != nil {
                        group.cancelAll()
                        return Result(ip: hit.0, countryCode: hit.1, latencyMs: hit.2)
                    }
                    if bestFallback == nil {
                        bestFallback = hit
                    }
                }
            }

            if let hit = bestFallback {
                return Result(ip: hit.0, countryCode: hit.1, latencyMs: hit.2)
            }

            let elapsed = Int(Date().timeIntervalSince(started) * 1000)
            return Result(
                ip: nil,
                countryCode: nil,
                latencyMs: elapsed,
                errorDescription: "HTTP 出口探测超时或网络不可达"
            )
        }
    }
}
