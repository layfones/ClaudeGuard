import Foundation
import Darwin

/// 原生基于 POSIX `inet_pton` 的 IPv4 / IPv6 单地址与 CIDR 网段匹配器。
public enum CIDRMatcher {
    public enum ParsedNetwork: Sendable, Equatable {
        case ipv4(address: [UInt8], prefixLength: Int)
        case ipv6(address: [UInt8], prefixLength: Int)
    }

    /// 解析单个 IP（如 `203.0.113.10`、`2607:6bc0::10`）或 CIDR（如 `160.79.104.0/24`、`2607:6bc0::/32`）。
    public static func parse(_ text: String) -> ParsedNetwork? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return nil }

        let ipPart = String(parts[0])
        let explicitPrefix: Int?
        if parts.count == 2 {
            guard let bits = Int(parts[1]) else { return nil }
            explicitPrefix = bits
        } else {
            explicitPrefix = nil
        }

        if let v4 = parseIPv4Bytes(ipPart) {
            let prefix = explicitPrefix ?? 32
            guard (0...32).contains(prefix) else { return nil }
            return .ipv4(address: v4, prefixLength: prefix)
        }

        if let v6 = parseIPv6Bytes(ipPart) {
            let prefix = explicitPrefix ?? 128
            guard (0...128).contains(prefix) else { return nil }
            return .ipv6(address: v6, prefixLength: prefix)
        }

        return nil
    }

    /// 判断输入字符串是否是合法的 IPv4 / IPv6 地址（不含 `/` 掩码）。
    public static func isValidLiteralIP(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("/") else { return false }
        return parseIPv4Bytes(trimmed) != nil || parseIPv6Bytes(trimmed) != nil
    }

    /// 判断输入字符串是否是合法的 IP 或 CIDR 网段（供表单实时校验）。
    public static func isValidIPOrCIDR(_ text: String) -> Bool {
        parse(text) != nil
    }

    /// 检查 `candidateIP` 是否落在指定 IP 或 CIDR `rule` 中。
    public static func matches(ip candidateIP: String, rule: String) -> Bool {
        let cleanIP = candidateIP.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let targetNet = parse(rule) else { return false }

        switch targetNet {
        case let .ipv4(netBytes, prefix):
            guard let ipBytes = parseIPv4Bytes(cleanIP) else { return false }
            return bytesMatch(ipBytes, netBytes, prefixBits: prefix)
        case let .ipv6(netBytes, prefix):
            guard let ipBytes = parseIPv6Bytes(cleanIP) else { return false }
            return bytesMatch(ipBytes, netBytes, prefixBits: prefix)
        }
    }

    /// 在一组 `AllowedIPEntry` 中查找第一个命中的已启用规则（返回该条目以便显示节点备注名）。
    public static func firstMatchingEntry(
        for candidateIP: String,
        in entries: [AllowedIPEntry]
    ) -> AllowedIPEntry? {
        for entry in entries where entry.isEnabled {
            if matches(ip: candidateIP, rule: entry.cidrOrIP) {
                return entry
            }
        }
        return nil
    }

    /// 判断给定 IP 是否属于任意一组 CIDR 字符串。
    public static func isIP(_ candidateIP: String, inAnyCIDR cidrs: [String]) -> Bool {
        cidrs.contains { matches(ip: candidateIP, rule: $0) }
    }

    private static func parseIPv4Bytes(_ text: String) -> [UInt8]? {
        var addr = in_addr()
        let rc = text.withCString { cstr in
            inet_pton(AF_INET, cstr, &addr)
        }
        guard rc == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }

    private static func parseIPv6Bytes(_ text: String) -> [UInt8]? {
        var addr = in6_addr()
        let rc = text.withCString { cstr in
            inet_pton(AF_INET6, cstr, &addr)
        }
        guard rc == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }

    private static func bytesMatch(_ lhs: [UInt8], _ rhs: [UInt8], prefixBits: Int) -> Bool {
        guard lhs.count == rhs.count else { return false }
        if prefixBits == 0 { return true }
        let fullBytes = prefixBits / 8
        let remBits = prefixBits % 8

        for idx in 0..<fullBytes {
            if lhs[idx] != rhs[idx] {
                return false
            }
        }
        if remBits > 0 {
            let mask: UInt8 = UInt8(0xFF) << (8 - remBits)
            if (lhs[fullBytes] & mask) != (rhs[fullBytes] & mask) {
                return false
            }
        }
        return true
    }
}
