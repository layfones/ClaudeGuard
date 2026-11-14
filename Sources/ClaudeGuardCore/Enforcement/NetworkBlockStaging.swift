import Foundation
import Darwin

/// 生成待特权助手消费的 `/etc/hosts` 沉洞段落与 `com.apple/claudeguard` PF 阻断地址列表，
/// 并通过写 `pending/request` 触发 LaunchDaemon（无 sudo 弹窗、无 setuid）。
public enum NetworkBlockStaging {
    public static let blockBeginMarker = "# BEGIN CLAUDEGUARD BLOCKS"
    public static let blockEndMarker = "# END CLAUDEGUARD BLOCKS"
    public static let updateBeginMarker = "# BEGIN CLAUDEGUARD UPDATE BLOCKS"
    public static let updateEndMarker = "# END CLAUDEGUARD UPDATE BLOCKS"

    public static let claudeUpdateDomains: [String] = [
        "desktop-app-updates.anthropic.com"
    ]

    /// 生成完整的受管 `/etc/hosts` 注入块（若无任何需封禁项则返回空字符串）。
    public static func buildStagedHostsBlock(
        blockTargetDomains: Bool,
        blockClaudeUpdates: Bool,
        enabledTargets: [GuardedTarget]
    ) -> String {
        var lines: [String] = []

        if blockTargetDomains {
            var allDomains = Set<String>()
            for target in enabledTargets {
                allDomains.formUnion(target.expandedBlockedDomains)
            }
            let sorted = allDomains
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                .filter { isValidStagedDomain($0) }
                .sorted()

            if !sorted.isEmpty {
                lines.append(blockBeginMarker)
                for domain in sorted {
                    lines.append("0.0.0.0\t\(domain)")
                    lines.append("127.0.0.1\t\(domain)")
                    lines.append("::1\t\(domain)")
                }
                lines.append(blockEndMarker)
            }
        }

        if blockClaudeUpdates {
            lines.append(updateBeginMarker)
            for domain in claudeUpdateDomains {
                lines.append("0.0.0.0\t\(domain)")
                lines.append("127.0.0.1\t\(domain)")
                lines.append("::1\t\(domain)")
            }
            lines.append(updateEndMarker)
        }

        guard !lines.isEmpty else { return "" }
        return lines.joined(separator: "\n") + "\n"
    }

    /// 生成待写入 `pf` `<claude_guard>` 表的专属 IP / CIDR 行列表（空字符串代表解除 PF 阻断）。
    /// 注意：仅纳入各启用目标声明的 `dedicatedPFCIDRs` 与 `pfFallbackIPs`，绝不把共享 Cloudflare CDN IP 塞入 PF。
    public static func buildStagedPFEntries(
        blockTargetDomains: Bool,
        enabledTargets: [GuardedTarget]
    ) -> String {
        guard blockTargetDomains else { return "" }
        var entries = Set<String>()
        for target in enabledTargets {
            for cidr in target.dedicatedPFCIDRs where CIDRMatcher.isValidIPOrCIDR(cidr) {
                entries.insert(cidr)
            }
            for ip in target.pfFallbackIPs where CIDRMatcher.isValidIPOrCIDR(ip) {
                entries.insert(ip)
            }
        }
        guard !entries.isEmpty else { return "" }
        return entries.sorted().joined(separator: "\n") + "\n"
    }

    /// 检查当前系统 `/etc/hosts` 状态是否偏离了我们期望的封禁状态（用于防止系统更新或外部工具改写后失效）。
    public static func hasHostsDrifted(
        expectedDomainsBlocked: Bool,
        expectedUpdatesBlocked: Bool,
        hostsPath: String = "/etc/hosts"
    ) -> Bool {
        guard let content = try? String(contentsOfFile: hostsPath, encoding: .utf8) else {
            return false
        }
        let hasDomainSection = content.contains(blockBeginMarker)
        let hasUpdateSection = content.contains(updateBeginMarker)
        let expectedHasDomain = expectedDomainsBlocked
        let expectedHasUpdate = expectedUpdatesBlocked
        return hasDomainSection != expectedHasDomain || hasUpdateSection != expectedHasUpdate
    }

    /// 将期望的规则暂存到 `pending/` 并原地刷新 `pending/request` 唤醒 LaunchDaemon。
    @discardableResult
    public static func stageAndTrigger(
        blockTargetDomains: Bool,
        blockClaudeUpdates: Bool,
        enabledTargets: [GuardedTarget],
        paths: GuardPaths = .live,
        waitForApply: Bool = true
    ) -> Bool {
        do {
            try paths.ensureDirectoriesExist()
            let hostsBlock = buildStagedHostsBlock(
                blockTargetDomains: blockTargetDomains,
                blockClaudeUpdates: blockClaudeUpdates,
                enabledTargets: enabledTargets
            )
            let pfEntries = buildStagedPFEntries(
                blockTargetDomains: blockTargetDomains,
                enabledTargets: enabledTargets
            )

            try atomicWrite(hostsBlock, to: paths.pendingHostsBlockFile)
            if pfEntries.isEmpty {
                try? FileManager.default.removeItem(at: paths.pendingPFAnchorFile)
            } else {
                try atomicWrite(pfEntries, to: paths.pendingPFAnchorFile)
            }

            // 原地覆写 pending/request（不能 rename，否则 launchd 的 kqueue vnode 监听会脱落！）
            try touchTriggerInPlace(paths.pendingRequestFile)

            guard waitForApply, FileManager.default.fileExists(atPath: paths.systemHelperBinary.path) else {
                return true
            }

            let wantDomainMarker = hostsBlock.contains(blockBeginMarker)
            for _ in 0..<25 {
                if let currentHosts = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8),
                   currentHosts.contains(blockBeginMarker) == wantDomainMarker {
                    return true
                }
                usleep(80_000) // 80ms * 25 = 最长等待 2s
            }
            return false
        } catch {
            return false
        }
    }

    public static func isValidStagedDomain(_ domain: String) -> Bool {
        guard domain.count >= 3, domain.count <= 253 else { return false }
        let forbidden: Set<String> = ["localhost", "localhost.localdomain", "broadcasthost"]
        if forbidden.contains(domain) { return false }
        guard domain.contains("."),
              !domain.hasPrefix("."),
              !domain.hasPrefix("-"),
              !domain.hasSuffix("."),
              !domain.hasSuffix("-"),
              !domain.contains("..") else {
            return false
        }
        return domain.unicodeScalars.allSatisfy { scalar in
            CharacterSet.alphanumerics.contains(scalar) || scalar == "." || scalar == "-"
        }
    }

    private static func atomicWrite(_ text: String, to destination: URL) throws {
        let tmp = destination.appendingPathExtension("tmp")
        guard let data = text.data(using: .utf8) else { return }
        try data.write(to: tmp)
        _ = try FileManager.default.replaceItemAt(destination, withItemAt: tmp)
    }

    private static func touchTriggerInPlace(_ fileURL: URL) throws {
        let stamp = "\(Date().timeIntervalSince1970)\n"
        let fd = open(fileURL.path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { close(fd) }
        stamp.withCString { ptr in
            _ = write(fd, ptr, strlen(ptr))
        }
        fsync(fd)
    }
}
